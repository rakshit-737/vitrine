#!/usr/bin/env python
"""Intervals for the secondary EMBER 2018 statistics quoted in README, docs and paper.

1. SHAP faithfulness: the deletion test of ``train_ember.py`` re-run on the saved triage model
   (same RNG sequence, so the point values reproduce ``ember_benchmark.json``) with a bootstrap over
   the 2,000 test malware for the mean score drops and the top-k / random-k ratio.
2. Packed vs unpacked test files: ROC AUC per subset with bootstrap CIs and the packed-minus-unpacked
   difference (independent subsets), plus the benign false-positive rate of each subset at each
   model's validation-calibrated 1 % FPR threshold (Wilson CIs, Fisher exact test).
3. VITRINE vs the EMBER authors' published 2018 model on the same 200k test rows: plug-in paired
   differences for seed 0 (the saved triage model) and seed-pooled over the three 275,732-row seeds
   saved by ``bench_drift.py``, with paired bootstrap CIs.
4. The published model on the EMBER2024 test subsample: drop from its 2018 test AUC (independent
   bootstrap of the two test sets) and Wilson intervals at its 2018-test 1 % FPR threshold.
5. Training-data composition counts quoted in the docs.

    python scripts/bench_secondary.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import csv
import time

import numpy as np
from _common import data_dir, dump, load_split, threshold_for_fpr
from _stats import bootstrap_roc, independent_bootstrap_diff, paired_bootstrap_diff, wilson

from vitrine.features import FEATURE_NAMES
from vitrine.gbdt import GBDTVerdictModel


def ci(v: np.ndarray) -> list[float]:
    return [float(x) for x in np.percentile(v, [2.5, 97.5])]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    t0 = time.time()
    data = data_dir(a.data)
    md = data / "models"
    _, Ftr, ytr, mtr = load_split(data, "train", vectors=False)
    _, Fte, yte, _ = load_split(data, "test", vectors=False)
    yte = yte.astype(int)
    app = np.asarray(mtr["appeared"])
    fit_idx, val_idx = np.flatnonzero(app != "2018-10"), np.flatnonzero(app == "2018-10")
    m = GBDTVerdictModel.load(md / "vitrine_xgb.json")
    res = {"description": __doc__.split("\n\n")[0], "bootstrap_resamples": a.boot}

    # ---- 1. SHAP deletion test (same RNG sequence as train_ember.py)
    rng = np.random.default_rng(0)
    mal = rng.choice(np.flatnonzero(yte == 1), 2000, replace=False)
    C = m.contributions(Fte[mal])
    ben_median = np.median(Ftr[fit_idx][ytr[fit_idx] == 0], axis=0)
    base = m.score_many(Fte[mal])
    rb = np.random.default_rng(1)
    bidx = rb.integers(0, mal.size, (a.boot, mal.size))
    dele = {}
    for k in (1, 3, 5, 10):
        Xs, Xr = Fte[mal].copy(), Fte[mal].copy()
        top = np.argsort(-C[:, :-1], axis=1)[:, :k]
        for i in range(len(mal)):
            Xs[i, top[i]] = ben_median[top[i]]
            rnd = rng.choice(len(FEATURE_NAMES), k, replace=False)
            Xr[i, rnd] = ben_median[rnd]
        ds, dr = base - m.score_many(Xs), base - m.score_many(Xr)
        bs, br = ds[bidx].mean(axis=1), dr[bidx].mean(axis=1)
        dele[str(k)] = {"mean_score_drop_shap_topk": float(ds.mean()), "shap_topk_ci95": ci(bs),
                        "mean_score_drop_random_k": float(dr.mean()), "random_k_ci95": ci(br),
                        "ratio_topk_over_random": float(ds.mean() / dr.mean()), "ratio_ci95": ci(bs / br)}
    res["shap_deletion_test"] = {"n_malware": int(mal.size), "replacement": "benign training median",
                                 "interval": "bootstrap over the 2,000 test malware", "k": dele}
    print("deletion", {k: (round(v["ratio_topk_over_random"], 1), v["ratio_ci95"]) for k, v in dele.items()},
          flush=True)

    # ---- 2. packed vs unpacked
    col = {n: Fte[:, FEATURE_NAMES.index(n)] for n in ("packer_section_name", "n_high_entropy_sections",
                                                          "imports_tiny")}
    pk = (col["packer_section_name"] > 0) | ((col["n_high_entropy_sections"] > 0) & (col["imports_tiny"] > 0))
    models = {"vitrine_xgb": (np.load(md / "vitrine_xgb_test_scores.npy"), m.thresholds["fpr_1pct"])}
    for name in ("lgbm_ember_2018", "lgbm_ember_paper"):
        s_val = np.load(md / f"{name}_val_scores.npy")
        models[name] = (np.load(md / f"{name}_test_scores.npy"), threshold_for_fpr(ytr[val_idx], s_val, 0.01))
    from scipy.stats import fisher_exact

    packing = {"packed_fraction_test": float(pk.mean()), "packed_malicious_fraction": float(yte[pk].mean()),
               "n_packed": int(pk.sum()), "n_packed_benign": int((pk & (yte == 0)).sum()),
               "n_unpacked_benign": int((~pk & (yte == 0)).sum())}
    for name, (s, thr) in models.items():
        e = {"packed": bootstrap_roc(yte[pk], [s[pk]], b=a.boot)["roc_auc"],
             "unpacked": bootstrap_roc(yte[~pk], [s[~pk]], b=a.boot)["roc_auc"],
             "packed_minus_unpacked": independent_bootstrap_diff(yte[pk], [s[pk]], yte[~pk], [s[~pk]],
                                                                 b=a.boot)["roc_auc"]}
        fp_p = int(((s >= thr) & pk & (yte == 0)).sum())
        fp_u = int(((s >= thr) & ~pk & (yte == 0)).sum())
        n_p, n_u = packing["n_packed_benign"], packing["n_unpacked_benign"]
        e["benign_fpr_at_val_1pct_threshold"] = {
            "threshold": float(thr), "packed": fp_p / n_p, "packed_wilson95": wilson(fp_p, n_p),
            "unpacked": fp_u / n_u, "unpacked_wilson95": wilson(fp_u, n_u),
            "fisher_p_two_sided": float(fisher_exact([[fp_p, n_p - fp_p], [fp_u, n_u - fp_u]]).pvalue)}
        packing[name] = e
    res["packing_subsets"] = packing
    print("packing", {k: v["benign_fpr_at_val_1pct_threshold"] for k, v in packing.items() if isinstance(v, dict)},
          flush=True)

    # ---- 3. VITRINE vs the published model, seed 0 and seed-pooled
    pub = np.load(md / "ember_published_2018_test_scores.npy")
    res["vitrine_minus_published"] = {
        "seed0_saved_triage_model": paired_bootstrap_diff(yte, [models["vitrine_xgb"][0]], [pub], a.boot)}
    drift = md / "drift"
    seeds = [drift / f"scores_ember2018__ember2018_test__seed{s}.npy" for s in range(3)]
    if all(p.exists() for p in seeds):
        sx = [np.load(p) for p in seeds]
        res["vitrine_minus_published"]["seed_pooled_3_seeds"] = paired_bootstrap_diff(yte, sx, [pub], a.boot)
        res["vitrine_3_seeds_ember2018_test"] = bootstrap_roc(yte, sx, b=a.boot)
    res["vitrine_minus_published"]["note"] = (
        "point = plug-in difference (mean over seeds); lo/hi = paired stratified bootstrap percentiles. "
        "The 3 seeds are bench_drift.py's 275,732-row models (same rows and hyperparameters as the triage model)")

    # ---- 4. published model 2018 -> 2024
    p24 = md / "ember_published_2018_on_2024test_scores.npy"
    if p24.exists():
        with open(data / "ember2024" / "processed" / "test_meta.csv", newline="") as f:
            y24 = np.array([int(r["label"]) for r in csv.DictReader(f)])
        s24 = np.load(p24)
        thr18 = threshold_for_fpr(yte, pub, 0.01)
        tp, fp = int(((s24 >= thr18) & (y24 == 1)).sum()), int(((s24 >= thr18) & (y24 == 0)).sum())
        res["published_2018_model_on_2024"] = {
            "drop_2018test_minus_2024test": independent_bootstrap_diff(yte, [pub], y24, [s24], b=a.boot,
                                                                      ta=[thr18], tb=[thr18]),
            "at_2018_test_1pct_threshold": {"threshold": thr18, "recall": tp / int(y24.sum()),
                                            "recall_wilson95": wilson(tp, int(y24.sum())),
                                            "fpr": fp / int((y24 == 0).sum()),
                                            "fpr_wilson95": wilson(fp, int((y24 == 0).sum())), "tp": tp, "fp": fp}}

    # ---- 5. composition
    lab = ytr[fit_idx]
    old = (app[fit_idx] < "2018-01") & (lab == 0)
    res["training_composition"] = {
        "fit_rows": int(fit_idx.size), "fit_benign": int((lab == 0).sum()), "fit_malicious": int((lab == 1).sum()),
        "fit_benign_first_seen_before_2018": int(old.sum()),
        "first_seen_range_of_those": [str(app[fit_idx][old].min()), str(app[fit_idx][old].max())]}
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember_secondary.json", res)


if __name__ == "__main__":
    main()
