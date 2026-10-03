#!/usr/bin/env python
"""Is the EMBER 2018 -> EMBER2024 drift ranking confounded by the v2 <-> v3 schema translation?

The cross-dataset PSI in ``ember2024_drift.json`` compares a 2018 value computed by EMBER v2 with a
2024 value computed by EMBER v3 (thrember) and translated by :mod:`vitrine.ember3`. Where the two
extractors define a feature differently, PSI measures the definition change, not the files.

1. Definition audit: every one of the 91 named features is put in one class (``_drift_defs.py``):
   ``redefined``, ``proxy``, ``parser`` (same definition, LIEF 0.9 vs pefile) or ``byte_level``.
2. Parity on overlap data: both definitions of each ``redefined`` counter are computed on the same
   benign files (a deterministic sample of local ``C:/Windows/System32`` PEs; regexes copied from
   elastic/ember v2 and thrember v3). Reported with 95 % intervals (Wilson; bootstrap over files):
   exact agreement, total-variation distance, Spearman rho, and the PSI between the two definitions
   on identical files (with its sensitivity to the share floor). Parser-based features are NOT
   checked: that needs LIEF 0.9 and pefile on the same files.
3. Ranking restricted to faithful features (``parser`` + ``byte_level``), copied from
   ``ember2024_drift.json`` with its bootstrap rank intervals and binning / family controls.
4. Ablation of the top-10 faithful drift features on the 2018 model (3 seeds, paired bootstrap)
   versus ``--draws`` random draws of 10 faithful features matched by feature group. Draw ``i`` is
   trained with seed ``i % 3`` and compared with the full and top-10 models of the same seed
   (plug-in differences), and Monte Carlo p-values (1 + #as-extreme) / (1 + #draws) are reported.
   To fit the shared laptop, all models are trained on the 99,144-row 2018 subsample used for
   ``ember2018_sub`` in ``bench_drift.py``.

    python scripts/bench_drift_parity.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np
from _common import RESULTS, _clean, data_dir, dump, provenance
from _drift_defs import PROXY, REDEFINED, feature_class, feature_group
from _stats import paired_bootstrap_diff, psi, psi_legacy, roc_metrics, total_variation, wilson
from bench_drift import load18, load24, score, train

from vitrine.features import FEATURE_NAMES

# v2 (elastic/ember features.py, as in vitrine/ember.py) and v3 (thrember features.py) definitions
_ALL = re.compile(rb"[\x20-\x7f]{5,}")
V2 = {"n_embedded_mz": re.compile(rb"MZ"), "n_paths": re.compile(rb"c:\\", re.I),
      "n_registry": re.compile(rb"HKEY_"), "n_urls": re.compile(rb"https?://", re.I)}
V3 = {"n_embedded_mz": re.compile("!This program "), "n_paths": re.compile("\\bC:/"),
      "n_registry": re.compile("\\b(?:KHEY_|KHLM|HKCU)"),
      "n_urls": re.compile("\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+")}


def parity(root: Path, n: int, boot: int = 1000) -> dict:
    from scipy.stats import spearmanr

    files = sorted(p for p in root.glob("*") if p.suffix.lower() in (".dll", ".exe", ".sys") and p.is_file())
    files = [p for p in files if 0 < p.stat().st_size <= 8 << 20][:: max(1, len(files) // n)][:n]
    v2 = {k: [] for k in V2}
    v3 = {k: [] for k in V3}
    used = 0
    for p in files:
        try:
            b = p.read_bytes()
        except OSError:
            continue
        if b[:2] != b"MZ":
            continue
        used += 1
        strs = [s.decode() for s in _ALL.findall(b)]
        for k in V2:
            v2[k].append(len(V2[k].findall(b)))
            v3[k].append(sum(1 for s in strs if V3[k].search(s)))
    out = {"corpus": f"{root} (benign; deterministic every-k-th sample of PE files <= 8 MiB)", "n_files": used,
           "bootstrap_resamples_over_files": boot,
           "note": ("PSI between two definitions on the same files depends on the share floor when one "
                    "definition puts every file in one bin; exact agreement and total variation do not.")}
    rng = np.random.default_rng(9)
    for k in V2:
        a, c = np.array(v2[k], float), np.array(v3[k], float)
        rho = spearmanr(a, c).statistic if a.std() and c.std() else None
        agree = int((a == c).sum())
        bt = {"tv": [], "psi": []}
        for _ in range(boot):
            ix = rng.integers(0, a.size, a.size)  # resample files (pairs kept together)
            bt["tv"].append(total_variation(a[ix], c[ix]))
            bt["psi"].append(psi(a[ix], c[ix]))
        ci = {m: [float(v) for v in np.percentile(bt[m], [2.5, 97.5])] for m in bt}
        out[k] = {"definition": REDEFINED[k], "v2_mean": float(a.mean()), "v3_mean": float(c.mean()),
                  "v2_median": float(np.median(a)), "v3_median": float(np.median(c)),
                  "v3_distinct_values": int(np.unique(c).size),
                  "exact_agreement": agree / a.size, "exact_agreement_wilson95": wilson(agree, a.size),
                  "total_variation": total_variation(a, c), "total_variation_ci95": ci["tv"],
                  "spearman_rho": None if rho is None else float(rho),
                  "psi_v2_vs_v3_same_files": psi(a, c), "psi_ci95": ci["psi"],
                  "psi_legacy_deciles": psi_legacy(a, c),
                  "psi_by_floor": {f"{e:g}": psi(a, c, floor=e) for e in (1e-3, 1e-4, 1e-5, 1e-6)}}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--system32", default="C:/Windows/System32")
    ap.add_argument("--parity-files", type=int, default=600)
    ap.add_argument("--draws", type=int, default=100)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--parity-out", help="compute only the System32 definition parity, write it here and exit")
    ap.add_argument("--parity-json", help="reuse a definition parity written by --parity-out (e.g. a Windows job)")
    a = ap.parse_args()
    t0 = time.time()
    res = {"description": __doc__.split("\n\n")[0],
           "feature_classes": {n: feature_class(n) for n in FEATURE_NAMES},
           "definitions": {**REDEFINED, **PROXY}}
    s32 = Path(a.system32)
    if a.parity_json:
        res["parity_system32"] = json.loads(Path(a.parity_json).read_text(encoding="utf-8"))
    else:
        res["parity_system32"] = parity(s32, a.parity_files, a.boot) if s32.exists() else {"skipped": "no System32"}
    if a.parity_out:
        res["parity_system32"]["provenance"] = provenance()
        text = json.dumps(_clean(res["parity_system32"]), indent=1, allow_nan=False)
        Path(a.parity_out).write_text(text, encoding="utf-8")
        return
    print(json.dumps(res["parity_system32"], indent=1), flush=True)
    res["parser_parity"] = ("LIEF 0.9 vs pefile on the same benign files: see extractor_parity_join "
                            "(results/extractor_parity.json)")

    # ---- ranking restricted to faithful features (from bench_drift.py, with its bootstrap and controls)
    rank = json.loads((RESULTS / "ember2024_drift.json").read_text())["drift_ranking"]
    feats = rank["features"]
    keys = ("feature", "class", "group", "shift_pattern", "psi_benign", "psi_benign_ci95", "psi_malicious",
            "psi_malicious_ci95", "mean_abs_shap_2018", "drift_weight", "drift_weight_ci95")
    res["all_features_top15"] = [{k: f[k] for k in (*keys, "rank_all_ci95")} for f in feats[:15]]
    faithful = [f for f in feats if f["faithful"]]
    res["faithful_attribution"] = [{k: f[k] for k in (*keys, "rank_faithful_ci95", "p_in_faithful_top_k",
                                                      "zero_share", "psi_malicious_excl_top_family")}
                                   for f in faithful[:15]]
    tops = rank["faithful_top_k_by_binning"]
    res["faithful_top_k_robust_core"] = sorted(set.intersection(*(set(v["top_k"]) for v in tops.values())))
    res["faithful_top_k_by_binning"] = tops
    res["faithful_both_class_top"] = [f["feature"] for f in faithful if f["shift_pattern"] == "both_classes"][:a.k]
    xp = RESULTS / "extractor_parity.json"
    if xp.exists():
        xd = json.loads(xp.read_text(encoding="utf-8"))
        byf = {f["feature"]: f for f in xd["features"]}
        res["extractor_parity_join"] = {
            "source": "results/extractor_parity.json", "github_run_url": xd["provenance"].get("github_run_url"),
            "n_files": xd["n_files_both_parsed"], "close_agreement_threshold": 0.99,
            "extractor_sensitive_parser_features": rank.get("extractor_sensitive_excluded", {}),
            "all_features_top15": [
                {"feature": f["feature"], "class": f["class"], "drift_weight": f["drift_weight"],
                 "psi_benign_2018_vs_2024": f["psi_benign"],
                 "extractor_close_agreement": byf[f["feature"]]["close_agreement_1pct"],
                 "extractor_psi_same_files": byf[f["feature"]]["psi_extractor_same_files"],
                 "extractor_psi_ci95": byf[f["feature"]]["psi_extractor_ci95"]} for f in feats[:15]],
            "faithful_top_k": [
                {"feature": f["feature"], "psi_benign_2018_vs_2024": f["psi_benign"],
                 "extractor_close_agreement": byf[f["feature"]]["close_agreement_1pct"],
                 "extractor_psi_same_files": byf[f["feature"]]["psi_extractor_same_files"]} for f in faithful[: a.k]]}

    # ---- ablation on faithful features vs group-matched random draws
    data = data_dir(a.data)
    d18, d24 = load18(data), load24(data)
    F18, y18, m18, _ = d18["train"]
    fit18 = m18 != "2018-10"
    rng = np.random.default_rng(0)  # identical subsample to bench_drift.py's ember2018_sub
    fit24n = int((d24["train"][2] <= 47).sum())
    sub = np.sort(rng.choice(np.flatnonzero(fit18), fit24n, replace=False))
    X, y = F18[sub], y18[sub]
    targets = {"ember2018_test": d18["test"][:2], "ember2024_test": d24["test"][:2]}
    seeds = [0, 1, 2]
    allc = list(range(len(FEATURE_NAMES)))
    full = [train(X, y, s) for s in seeds]
    full_s = {t: [score(b, Xt) for b in full] for t, (Xt, _) in targets.items()}
    full_m = {t: [roc_metrics(targets[t][1], s) for s in full_s[t]] for t in targets}
    print(f"full models ({time.time() - t0:.0f}s)", flush=True)
    names = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")

    top = [FEATURE_NAMES.index(f["feature"]) for f in faithful[: a.k]]
    keep = [j for j in allc if j not in top]
    top_models = [train(X, y, s, keep) for s in seeds]
    top_s = {t: [score(b, Xt, keep) for b in top_models] for t, (Xt, _) in targets.items()}
    top_d = {t: [np.subtract(roc_metrics(targets[t][1], s), full_m[t][i]) for i, s in enumerate(top_s[t])]
             for t in targets}
    ab = {"dropped": [FEATURE_NAMES[j] for j in top], "seeds": seeds, "bootstrap_resamples": a.boot,
          "ablated_minus_full": {t: paired_bootstrap_diff(yt, top_s[t], full_s[t], a.boot)
                                 for t, (_, yt) in targets.items()},
          "ablated_minus_full_per_seed": {t: [dict(zip(names, map(float, d))) for d in top_d[t]] for t in targets}}
    print(f"faithful ablation {ab['ablated_minus_full']} ({time.time() - t0:.0f}s)", flush=True)
    # group-matched random draws from the faithful pool (excluding the top-k themselves), seed-matched
    pool = {}
    for f in faithful[a.k:]:
        pool.setdefault(f["group"], []).append(FEATURE_NAMES.index(f["feature"]))
    need = {}
    for j in top:
        g = feature_group(FEATURE_NAMES[j])
        need[g] = need.get(g, 0) + 1
    rr = np.random.default_rng(11)
    draws = []
    for i in range(a.draws):
        sd = seeds[i % len(seeds)]
        pick = []
        for g, c in need.items():
            pick += rr.choice(pool[g], min(c, len(pool[g])), replace=False).tolist()
        kp = [j for j in allc if j not in pick]
        b = train(X, y, sd, kp)
        e = {"dropped": [FEATURE_NAMES[j] for j in sorted(pick)], "seed": sd}
        for t, (Xt, yt) in targets.items():
            d = np.subtract(roc_metrics(yt, score(b, Xt, kp)), full_m[t][sd])
            e[t] = dict(zip(names, map(float, d)))
            e[t + ":minus_topk_same_seed"] = dict(zip(names, map(float, d - top_d[t][sd])))
        draws.append(e)
        print(f"draw {len(draws)} ({time.time() - t0:.0f}s)", flush=True)
    summ = {}
    n = len(draws)
    for t in targets:
        for j, m in enumerate(names):
            v = np.array([d[t][m] for d in draws])
            rel = np.array([d[t + ":minus_topk_same_seed"][m] for d in draws])
            worse = int((rel < 0).sum())
            summ[f"{t}:{m}"] = {
                "mean": float(v.mean()), "p2.5": float(np.percentile(v, 2.5)), "p97.5": float(np.percentile(v, 97.5)),
                "topk_mean_over_seeds": float(np.mean([d[j] for d in top_d[t]])),
                "n_draws_worse_than_topk": worse, "frac_draws_worse_than_topk": worse / n,
                "mc_p_topk_more_damaging": (1 + int((rel >= 0).sum())) / (1 + n),
                "mc_p_topk_less_damaging": (1 + int((rel <= 0).sum())) / (1 + n)}
    ab["group_matched_random"] = {
        "n_draws": n, "group_counts": need,
        "design": ("draw i trained with seed i % 3, compared with the full and top-k models of the same seed; "
                   "plug-in metric differences on the full test sets"),
        "p_value_note": ("one-sided Monte Carlo p = (1 + #draws at least as extreme) / (1 + #draws); "
                         "mc_p_topk_more_damaging tests whether removing the top-k hurts more than a random draw"),
        "summary": summ, "draws": draws}
    res["faithful_ablation"] = ab
    res["training_rows"] = int(sub.size)
    res["threshold_note"] = "ROC-read metrics; no thresholds are calibrated in this script"
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_drift_parity.json", res)


if __name__ == "__main__":
    main()
