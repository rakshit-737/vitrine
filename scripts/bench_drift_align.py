#!/usr/bin/env python
"""Intervention test for the drift ranking: align 2024 feature marginals to 2018 and re-score.

The PSI x mean|SHAP| ranking in ``ember2024_drift.json`` is correlational. This script asks a
counterfactual question of the *frozen* 2018 models (the three 275,732-row seeds saved by
``bench_drift.py``): if a group of features had its 2018 distribution on the 2024 test set, how much
of the 2018 -> 2024 AUC loss would come back?

For every feature in a group and each class separately, 2024 test values are mapped through their
within-class empirical CDF (ties broken at random) onto the 2018 test quantiles of the same class
(``inverted_cdf``, so mapped values stay on the 2018 support). Within-class ranks, and so the joint
dependence between features, are kept; only the marginals move. Because the mapping uses the labels,
it is an oracle intervention for analysis, not a deployable correction.

Reported per group: 2024 test metrics after alignment minus before, paired stratified bootstrap
pooled over the 3 seeds, and the share of the 2018-test-minus-2024-test AUC drop recovered. Groups:
all 91 features; faithful vs non-faithful (definition-changed) features; the faithful top-10 of the
ranking; feature groups; single features; and group-matched random draws of 10 faithful features.

    python scripts/bench_drift_align.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import json
import time

import numpy as np
from _common import RESULTS, data_dir, dump
from _drift_defs import FAITHFUL, feature_class, feature_group
from _stats import paired_bootstrap_diff, roc_metrics
from bench_drift import load18, load24, score

from vitrine.features import FEATURE_NAMES


def align(T24: np.ndarray, y24: np.ndarray, T18: np.ndarray, y18: np.ndarray, cols: list[int],
          rng: np.random.Generator) -> np.ndarray:
    """Copy of T24 whose ``cols`` have, per class, the 2018 test marginal (within-class ranks kept)."""
    out = T24.copy()
    for c in (0, 1):
        r24, r18 = np.flatnonzero(y24 == c), np.flatnonzero(y18 == c)
        for j in cols:
            x = T24[r24, j]
            order = np.lexsort((rng.random(x.size), x))  # sort by value, ties in random order
            u = np.empty(x.size)
            u[order] = (np.arange(x.size) + 0.5) / x.size
            out[r24, j] = np.quantile(T18[r18, j], u, method="inverted_cdf")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--draws", type=int, default=20, help="group-matched random draws of k faithful features")
    ap.add_argument("--k", type=int, default=10)
    a = ap.parse_args()
    import xgboost as xgb

    t0 = time.time()
    data = data_dir(a.data)
    store = data / "models" / "drift"
    T18, y18, _, _ = load18(data)["test"]
    T24, y24, _, _ = load24(data)["test"]
    models = []
    for s in range(3):
        b = xgb.Booster()
        b.load_model(str(store / f"ember2018_seed{s}.ubj"))
        models.append(b)
    base24 = [score(b, T24) for b in models]
    base18 = [score(b, T18) for b in models]
    m18 = np.mean([roc_metrics(y18, s) for s in base18], axis=0)
    m24 = np.mean([roc_metrics(y24, s) for s in base24], axis=0)
    drop = m18 - m24
    names = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
    print(f"2018 test {m18}, 2024 test {m24} ({time.time() - t0:.0f}s)", flush=True)

    rank = json.loads((RESULTS / "ember2024_drift.json").read_text())["drift_ranking"]
    faithful = [f["feature"] for f in rank["features"] if f["faithful"]]
    idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
    is_f = [feature_class(n) in FAITHFUL for n in FEATURE_NAMES]
    top = faithful[: a.k]
    groups = {"all_91": list(range(len(FEATURE_NAMES))),
              "faithful_all": [i for i, f in enumerate(is_f) if f],
              "non_faithful_redefined_or_proxy": [i for i, f in enumerate(is_f) if not f],
              f"faithful_top{a.k}": [idx[n] for n in top]}
    for g in sorted({feature_group(n) for n in FEATURE_NAMES}):
        groups[f"group:{g}"] = [i for i, n in enumerate(FEATURE_NAMES) if feature_group(n) == g]
    for n in [*top, "n_embedded_mz"]:
        groups[f"feature:{n}"] = [idx[n]]
    rr = np.random.default_rng(13)
    pool = {}
    for n in faithful[a.k:]:
        pool.setdefault(feature_group(n), []).append(idx[n])
    need = {}
    for n in top:
        need[feature_group(n)] = need.get(feature_group(n), 0) + 1
    for d in range(a.draws):
        pick = []
        for g, c in need.items():
            pick += rr.choice(pool[g], min(c, len(pool[g])), replace=False).tolist()
        groups[f"random{a.k}:{d}"] = sorted(pick)

    rng = np.random.default_rng(17)
    res = {"description": __doc__.split("\n\n")[0],
           "method": ("per-class quantile mapping of 2024 test values onto 2018 test quantiles (oracle: uses labels); "
                      "frozen 2018 models (275,732 rows, 3 seeds); paired bootstrap pooled over seeds"),
           "bootstrap_resamples": a.boot,
           "baseline": {"ember2018_test": dict(zip(names, map(float, m18))),
                        "ember2024_test": dict(zip(names, map(float, m24))),
                        "drop_2018_minus_2024": dict(zip(names, map(float, drop)))},
           "faithful_top_k": top, "groups": {}}
    for gname, cols in groups.items():
        X = align(T24, y24, T18, y18, cols, rng)
        s = [score(b, X) for b in models]
        boot = a.boot if not gname.startswith("random") else 0
        pt = np.mean([np.subtract(roc_metrics(y24, si), roc_metrics(y24, bi)) for si, bi in zip(s, base24)], axis=0)
        e = {"n_features": len(cols), "features": [FEATURE_NAMES[j] for j in cols] if len(cols) <= 12 else None,
             "aligned_minus_original": dict(zip(names, map(float, pt))),
             "share_of_auc_drop_recovered": float(pt[0] / drop[0])}
        if boot:
            e["aligned_minus_original_ci"] = paired_bootstrap_diff(y24, s, base24, boot)
        res["groups"][gname] = e
        print(f"{gname:40s} dAUC {pt[0]:+.4f} ({pt[0] / drop[0]:+.0%} of drop) ({time.time() - t0:.0f}s)", flush=True)
    rnd = np.array([v["aligned_minus_original"]["roc_auc"] for k, v in res["groups"].items() if k.startswith("random")])
    tk = res["groups"][f"faithful_top{a.k}"]["aligned_minus_original"]["roc_auc"]
    res["random_draws_summary"] = {
        "n_draws": int(rnd.size), "mean_dauc": float(rnd.mean()),
        "p2.5": float(np.percentile(rnd, 2.5)), "p97.5": float(np.percentile(rnd, 97.5)),
        "n_draws_recovering_at_least_topk": int((rnd >= tk).sum()),
        "mc_p_topk_recovers_more": (1 + int((rnd >= tk).sum())) / (1 + rnd.size)}
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_drift_align.json", res)


if __name__ == "__main__":
    main()
