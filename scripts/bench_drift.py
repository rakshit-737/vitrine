#!/usr/bin/env python
"""Cross-time evaluation EMBER 2018 <-> EMBER2024 on VITRINE's 91 named features, with a drift ranking.

Data (features only, no binaries):
  * EMBER 2018: ``<data>/processed`` from ``prepare_ember.py --train-frac 0.5`` (sha256-prefix half of
    the labelled training rows). Fit = all rows except 2018-10; calibration = 2018-10; test = Nov-Dec 2018.
  * EMBER2024 Win32: ``<data>/ember2024/processed`` from ``prepare_ember2024.py`` -- a sha256-range
    subsample (first 8 MiB of each weekly file, ~2k of ~30k files per week). Fit = train weeks 0-47,
    calibration = weeks 48-51 (2024-08-25 .. 2024-09-21), test = the 12 test weeks (2024-09-22 .. 2024-12-14).
    v3 records are translated to the v2 schema by :mod:`vitrine.ember3` before feature extraction.

Experiments
  1. Cross-time matrix: models trained on each dataset (3 seeds) scored on both test sets. A 2018 model
     subsampled to the 2024 training size separates "less data" from "older data".
     Metrics: ROC AUC, TPR at 1 % / 0.1 % FPR (test-ROC reading), and test FPR / recall at the
     *source*-calibrated 1 % threshold (what a deployed model would actually do).
     95 % CIs: stratified bootstrap pooled over the 3 training seeds, for every metric (threshold
     metrics included). The 2018 -> 2024 drop of the same models is bootstrapped by resampling the two
     test sets independently.
  2. Per-week AUC of the 2018 model over the 64 EMBER2024 weeks (drift curve, per-week bootstrap band)
     and AUT (TESSERACT).
  3. Drift ranking (correlational): per named feature and class, PSI between the 2018 and 2024 test sets
     on point-mass-aware bins (``_stats.psi``), weight = max(PSI_benign, PSI_malicious) x the 2018
     model's mean |SHAP|. Reported with the v1.1.0 decile PSI, pooled-quantile bins and a
     family-composition control (top 2018 malware family removed) for comparison, per-class zero shares,
     and a bootstrap of PSI, weights and ranks. The removal ablation and definition audit are in
     ``bench_drift_parity.py``; the marginal-alignment intervention in ``bench_drift_align.py``.

Models and per-seed scores are saved under ``<data>/models/drift/`` (``--reuse`` reloads them instead of
retraining). Peak RSS is about 1.5 GB (91-feature matrices only), so it runs locally.

    python scripts/bench_drift.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path

import numpy as np
from _common import binary_metrics, data_dir, dump, threshold_for_fpr
from _drift_defs import EXTRACTOR_SENSITIVE, FAITHFUL, feature_class, feature_group, shift_pattern
from _stats import (
    bootstrap_roc,
    bootstrap_threshold,
    independent_bootstrap_diff,
    paired_bootstrap_diff,
    psi,
    psi_legacy,
    roc_metrics,
    stratified_indices,
)

from vitrine.ember3 import APPROXIMATIONS
from vitrine.features import FEATURE_NAMES

XGB = {"objective": "binary:logistic", "tree_method": "hist", "max_depth": 10, "eta": 0.08,
       "subsample": 0.8, "colsample_bytree": 0.8, "nthread": 8}
ROUNDS = 600


def load18(data: Path):
    p = data / "processed"
    out = {}
    for split in ("train", "test"):
        F = np.load(p / f"{split}_F.npy")
        with open(p / f"{split}_meta.csv", newline="") as f:
            rows = list(csv.DictReader(f))
        out[split] = (F, np.array([int(r["label"]) for r in rows], np.int8), np.array([r["appeared"] for r in rows]),
                      np.array([r["avclass"] for r in rows]))
    return out


def load24(data: Path):
    p = data / "ember2024" / "processed"
    out = {}
    for split in ("train", "test"):
        F = np.load(p / f"{split}_F.npy")
        with open(p / f"{split}_meta.csv", newline="") as f:
            rows = list(csv.DictReader(f))
        out[split] = (F, np.array([int(r["label"]) for r in rows], np.int8),
                      np.array([int(r["week_id"]) for r in rows]), np.array([r["family"] for r in rows]))
    return out


def train(X, y, seed, cols=None):
    import xgboost as xgb

    X = X if cols is None else X[:, cols]
    return xgb.train({**XGB, "seed": seed}, xgb.DMatrix(X, label=y), ROUNDS)


def score(b, X, cols=None):
    import xgboost as xgb

    return b.predict(xgb.DMatrix(X if cols is None else X[:, cols]))


def cell(y, scores, thr_list, B):
    r = bootstrap_roc(y, scores, b=B)
    at = [binary_metrics(y, s, t) for s, t in zip(scores, thr_list)]
    r["at_source_1pct_threshold"] = {"fpr_mean": float(np.mean([m["fpr"] for m in at])),
                                     "recall_mean": float(np.mean([m["recall"] for m in at])),
                                     "per_seed": [{"fpr": m["fpr"], "recall": m["recall"]} for m in at],
                                     "bootstrap_seed_pooled": bootstrap_threshold(y, scores, thr_list, b=B)}
    r["n"] = int(y.size)
    r["n_malicious"] = int(y.sum())
    return r


def models_for(name, X, y, seeds, store: Path, reuse: bool):
    import xgboost as xgb

    out = []
    for s in seeds:
        f = store / f"{name}_seed{s}.ubj"
        if reuse and f.exists():
            b = xgb.Booster()
            b.load_model(str(f))
        else:
            b = train(X, y, s)
            b.save_model(str(f))
        out.append(b)
    return out


def _ranks(w: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """1-based rank of each masked feature by descending weight (unmasked -> 0)."""
    r = np.zeros(w.size, int)
    idx = np.flatnonzero(mask)
    order = idx[np.argsort(-w[idx], kind="stable")]
    r[order] = np.arange(1, order.size + 1)
    return r


def drift_ranking(T18, yT18, fam18, T24, yT24, fam24, shap_rows, B: int, k: int) -> dict:
    """PSI x mean|SHAP| ranking with binning/family controls and a bootstrap of PSI, weights and ranks."""
    n_f = len(FEATURE_NAMES)
    faithful = np.array([feature_class(n) in FAITHFUL for n in FEATURE_NAMES])
    top_fam = max(set(fam18[(yT18 == 1) & (fam18 != "")]), key=lambda f: int(((fam18 == f) & (yT18 == 1)).sum()))
    sets = {"b18": T18[yT18 == 0], "m18": T18[yT18 == 1], "b24": T24[yT24 == 0], "m24": T24[yT24 == 1],
            "m18x": T18[(yT18 == 1) & (fam18 != top_fam)], "m24x": T24[(yT24 == 1) & (fam24 != top_fam)]}
    shap = shap_rows.mean(axis=0)

    def weights(S, sh, how="primary"):
        f = {"primary": psi, "legacy": psi_legacy, "pooled": lambda a, b: psi(a, b, pooled=True)}[how]
        pb = np.array([f(S["b18"][:, j], S["b24"][:, j]) for j in range(n_f)])
        pm = np.array([f(S["m18"][:, j], S["m24"][:, j]) for j in range(n_f)])
        return pb, pm, np.maximum(pb, pm) * sh

    pb, pm, w = weights(sets, shap)
    pbl, pml, wl = weights(sets, shap, "legacy")
    pbp, pmp, wp = weights(sets, shap, "pooled")
    pmx = np.array([psi(sets["m18x"][:, j], sets["m24x"][:, j]) for j in range(n_f)])
    wx = np.maximum(pb, pmx) * shap
    rank_all, rank_f = _ranks(w, np.ones(n_f, bool)), _ranks(w, faithful)

    # bootstrap: resample rows within each class x period (joint across features) and the SHAP rows
    rng = np.random.default_rng(5)
    bw = np.empty((B, n_f))
    bpb, bpm = np.empty((B, n_f)), np.empty((B, n_f))
    bra, brf = np.empty((B, n_f), int), np.empty((B, n_f), int)
    for i in range(B):
        S = {key: sets[key][rng.integers(0, len(sets[key]), len(sets[key]))] for key in ("b18", "m18", "b24", "m24")}
        sh = shap_rows[rng.integers(0, len(shap_rows), len(shap_rows))].mean(axis=0)
        bpb[i], bpm[i], bw[i] = weights(S, sh)
        bra[i], brf[i] = _ranks(bw[i], np.ones(n_f, bool)), _ranks(bw[i], faithful)
        if (i + 1) % 25 == 0:
            print(f"  rank bootstrap {i + 1}/{B}", flush=True)

    def pct(a, j):
        lo, hi = np.percentile(a[:, j], [2.5, 97.5])
        return [float(lo), float(hi)]

    feats = []
    for j, n in enumerate(FEATURE_NAMES):
        feats.append({
            "feature": n, "class": feature_class(n), "group": feature_group(n), "faithful": bool(faithful[j]),
            "psi_benign": float(pb[j]), "psi_benign_ci95": pct(bpb, j),
            "psi_malicious": float(pm[j]), "psi_malicious_ci95": pct(bpm, j),
            "psi": float(max(pb[j], pm[j])), "shift_pattern": shift_pattern(pb[j], pm[j]),
            "mean_abs_shap_2018": float(shap[j]),
            "drift_weight": float(w[j]), "drift_weight_ci95": pct(bw, j),
            "rank_all": int(rank_all[j]), "rank_all_ci95": [int(v) for v in pct(bra, j)],
            "rank_faithful": int(rank_f[j]) or None,
            "rank_faithful_ci95": [int(v) for v in pct(brf, j)] if faithful[j] else None,
            "p_in_faithful_top_k": float(((brf[:, j] >= 1) & (brf[:, j] <= k)).mean()) if faithful[j] else None,
            "zero_share": {key: float((sets[key][:, j] == 0).mean()) for key in ("b18", "b24", "m18", "m24")},
            "psi_legacy_benign": float(pbl[j]), "psi_legacy_malicious": float(pml[j]),
            "drift_weight_legacy": float(wl[j]),
            "psi_pooled_benign": float(pbp[j]), "psi_pooled_malicious": float(pmp[j]),
            "drift_weight_pooled": float(wp[j]),
            "psi_malicious_excl_top_family": float(pmx[j]), "drift_weight_excl_top_family": float(wx[j]),
        })
    feats.sort(key=lambda f: -f["drift_weight"])

    def topk(weight, only_faithful=True):
        idx = [j for j in np.argsort(-weight, kind="stable") if faithful[j] or not only_faithful]
        return [FEATURE_NAMES[j] for j in idx[:k]]

    tops = {"primary": topk(w), "legacy_deciles": topk(wl), "pooled_quantiles": topk(wp),
            f"excl_{top_fam}": topk(wx)}
    stab = {name: {"top_k": t, "overlap_with_primary": len(set(t) & set(tops["primary"]))}
            for name, t in tops.items()}
    return {
        "definition": ("weight = max(PSI_benign, PSI_malicious) x mean |SHAP| of the 2018 model (20k 2018 test "
                       "rows); PSI on point-mass-aware bins (every value with >= 10 % of the reference gets its own "
                       "bin, the rest reference deciles; shares floored at 1e-4). Correlational ranking, not a "
                       "causal attribution; parser features differ in extractor (LIEF 0.9 vs pefile)."),
        "zero_share_keys": "b18/b24 = benign 2018/2024 test, m18/m24 = malicious 2018/2024 test",
        "top_family_control": {"family": top_fam,
                                "share_of_2018_test_malware": float(((fam18 == top_fam) & (yT18 == 1)).sum()
                                                                    / max(int(yT18.sum()), 1)),
                                "share_of_2024_test_malware": float(((fam24 == top_fam) & (yT24 == 1)).sum()
                                                                    / max(int(yT24.sum()), 1))},
        "bootstrap_resamples": B, "k": k,
        "faithful_top_k_by_binning": stab,
        "features": feats,
    }


def _shap_rows(b0, T18, n18: int):
    import xgboost as xgb

    rs = np.random.default_rng(1)
    i18 = rs.choice(n18, 20000, replace=False)
    return np.abs(b0.predict(xgb.DMatrix(T18[i18]), pred_contribs=True)[:, :-1])


def _rank_only(a, store: Path, d18, d24, t0: float) -> None:
    import json

    import xgboost as xgb
    from _common import RESULTS
    from _drift_defs import EXTRACTOR_SENSITIVE

    res = json.loads((RESULTS / "ember2024_drift.json").read_text(encoding="utf-8"))
    T18, yT18, _, fam18 = d18["test"]
    T24, yT24, _, fam24 = d24["test"]
    b0 = xgb.Booster()
    b0.load_model(str(store / "ember2018_seed0.ubj"))
    res["drift_ranking"] = drift_ranking(T18, yT18, fam18, T24, yT24, fam24, _shap_rows(b0, T18, yT18.size),
                                         a.rank_boot, a.k)
    res["drift_ranking"]["extractor_sensitive_excluded"] = EXTRACTOR_SENSITIVE
    prev = res.pop("provenance", None)
    res["provenance_of_other_sections"] = res.pop("provenance_of_other_sections", prev)
    res["runtime_seconds_rank_only"] = round(time.time() - t0)
    dump("ember2024_drift.json", res)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--week-boot", type=int, default=200, help="bootstrap resamples per EMBER2024 week")
    ap.add_argument("--rank-boot", type=int, default=200, help="bootstrap resamples for PSI / rank intervals")
    ap.add_argument("--k", type=int, default=10, help="size of the top-k sets compared across binnings")
    ap.add_argument("--reuse", action="store_true", help="load saved models from <data>/models/drift if present")
    ap.add_argument("--rank-only", action="store_true",
                    help="recompute only the drift ranking (seed-0 2018 model from <data>/models/drift) and keep "
                         "the other sections of results/ember2024_drift.json")
    a = ap.parse_args()
    data = data_dir(a.data)
    store = data / "models" / "drift"
    store.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    d18, d24 = load18(data), load24(data)
    if a.rank_only:
        _rank_only(a, store, d18, d24, t0)
        return
    F18, y18, m18, _ = d18["train"]
    fit18, val18 = m18 != "2018-10", m18 == "2018-10"
    T18, yT18, _, fam18 = d18["test"]
    F24, y24, w24, _ = d24["train"]
    fit24, val24 = w24 <= 47, w24 >= 48
    T24, yT24, wT24, fam24 = d24["test"]
    seeds = list(range(a.seeds))
    rng = np.random.default_rng(0)
    sub18 = np.sort(rng.choice(np.flatnonzero(fit18), int(fit24.sum()), replace=False))

    sources = {
        "ember2018": (F18[fit18], y18[fit18], F18[val18], y18[val18]),
        "ember2018_sub": (F18[sub18], y18[sub18], F18[val18], y18[val18]),
        "ember2024": (F24[fit24], y24[fit24], F24[val24], y24[val24]),
    }
    targets = {"ember2018_test": (T18, yT18), "ember2024_test": (T24, yT24)}
    res = {"description": __doc__.split("\n\n")[0], "feature_set": "VITRINE 91 named features",
           "translation_approximations": APPROXIMATIONS,
           "rows": {"ember2018_fit": int(fit18.sum()), "ember2018_fit_sub": int(sub18.size),
                    "ember2018_val": int(val18.sum()), "ember2018_test": int(yT18.size),
                    "ember2024_fit": int(fit24.sum()), "ember2024_val": int(val24.sum()),
                    "ember2024_test": int(yT24.size)},
           "test_class_counts": {"ember2018_test": {"benign": int((yT18 == 0).sum()), "malicious": int(yT18.sum())},
                                 "ember2024_test": {"benign": int((yT24 == 0).sum()), "malicious": int(yT24.sum())}},
           "subsample_note": ("EMBER 2018: deterministic sha256-prefix half (--train-frac 0.5) of the 600k labelled "
                              "training rows. EMBER2024: first 8 MiB of each weekly Win32 member (sha256-sorted, "
                              "so a sha256-range sample of about 7 % of each week), 135,423 labelled rows of ~2.0M; "
                              "chosen to fit download bandwidth and 16 GB RAM."),
           "xgb_params": {**XGB, "rounds": ROUNDS}, "seeds": seeds, "bootstrap": a.boot, "matrix": {}}
    models, thr = {}, {}
    for name, (X, y, Xv, yv) in sources.items():
        models[name] = models_for(name, X, y, seeds, store, a.reuse)
        thr[name] = [threshold_for_fpr(yv, score(b, Xv), 0.01) for b in models[name]]
        print(f"models {name} x{len(seeds)} ({time.time() - t0:.0f}s)", flush=True)
    res["source_thresholds_1pct"] = thr
    scores = {}
    for src in sources:
        for tgt, (X, y) in targets.items():
            s = [score(b, X) for b in models[src]]
            for sd, arr in zip(seeds, s):
                np.save(store / f"scores_{src}__{tgt}__seed{sd}.npy", arr)
            scores[(src, tgt)] = s
            res["matrix"][f"{src}->{tgt}"] = cell(y, s, thr[src], a.boot)
            r = res["matrix"][f"{src}->{tgt}"]
            bt = r["at_source_1pct_threshold"]["bootstrap_seed_pooled"]
            print(f"{src:14s} -> {tgt:15s} AUC {r['roc_auc']['point']:.4f} [{r['roc_auc']['lo']:.4f},"
                  f"{r['roc_auc']['hi']:.4f}] TPR@1% {r['tpr_at_fpr_1pct']['point']:.3f} "
                  f"src-thr FPR {bt['fpr']['point']:.4f} [{bt['fpr']['lo']:.4f},{bt['fpr']['hi']:.4f}] "
                  f"recall {bt['recall']['point']:.3f} [{bt['recall']['lo']:.3f},{bt['recall']['hi']:.3f}]",
                  flush=True)
    # paired: does the 2018 model lose on 2024 relative to an in-period 2024 model of the same size?
    res["paired"] = {
        "2024test: ember2024 - ember2018_sub": paired_bootstrap_diff(
            yT24, scores[("ember2024", "ember2024_test")], scores[("ember2018_sub", "ember2024_test")], a.boot),
        "2018test: ember2018_sub - ember2024": paired_bootstrap_diff(
            yT18, scores[("ember2018_sub", "ember2018_test")], scores[("ember2024", "ember2018_test")], a.boot),
    }
    # the drop itself: same models, 2018 test minus 2024 test (independent resamples of the two test sets)
    res["drop_2018test_minus_2024test"] = {
        src: independent_bootstrap_diff(yT18, scores[(src, "ember2018_test")], yT24, scores[(src, "ember2024_test")],
                                        a.boot, ta=thr[src], tb=thr[src])
        for src in ("ember2018", "ember2018_sub")}
    print("drop", res["drop_2018test_minus_2024test"]["ember2018"], flush=True)

    # ---- per-week drift curve of the 2018 model (all 64 EMBER2024 weeks), seed-pooled bootstrap band
    allF = np.vstack([F24, T24])
    ally = np.concatenate([y24, yT24])
    allw = np.concatenate([w24, wT24])
    s_seeds = [score(b, allF) for b in models["ember2018"]]
    s_all = np.mean(s_seeds, axis=0)
    rb = np.random.default_rng(4)
    curve = []
    for w in np.unique(allw):
        m = np.flatnonzero(allw == w)
        yw = ally[m]
        if 0 < yw.sum() < m.size:
            auc, t1, _ = roc_metrics(yw, s_all[m])
            sw = s_all[m]
            bs = [roc_metrics(yw[ix], sw[ix])[0] for ix in (stratified_indices(yw, rb) for _ in range(a.week_boot))]
            lo, hi = np.percentile(bs, [2.5, 97.5])
            curve.append({"week": int(w), "n": int(m.size), "n_malicious": int(yw.sum()), "roc_auc": auc,
                          "roc_auc_ci95": [float(lo), float(hi)], "tpr_at_fpr_1pct": t1})
    res["weekly_2018_model_on_2024"] = curve
    res["weekly_note"] = (f"AUC of the mean score of the 3 seeds (a fixed ensemble); band = 2.5-97.5 % of "
                          f"{a.week_boot} stratified resamples of the week's rows")
    aucs = np.array([c["roc_auc"] for c in curve])
    res["aut_auc_2018_model_over_2024_weeks"] = float(np.trapezoid(aucs) / (len(aucs) - 1)) if len(aucs) > 1 else None
    print(f"weekly curve ({time.time() - t0:.0f}s)", flush=True)

    # ---- drift ranking: PSI per class x mean |SHAP| of the 2018 model (seed 0), with bootstrap and controls

    res["drift_ranking"] = drift_ranking(T18, yT18, fam18, T24, yT24, fam24,
                                         _shap_rows(models["ember2018"][0], T18, yT18.size), a.rank_boot, a.k)
    res["drift_ranking"]["extractor_sensitive_excluded"] = EXTRACTOR_SENSITIVE
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_drift.json", res)


if __name__ == "__main__":
    main()
