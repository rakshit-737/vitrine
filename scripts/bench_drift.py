#!/usr/bin/env python
"""Cross-time evaluation EMBER 2018 <-> EMBER2024 on VITRINE's 91 named features, with explainable drift.

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
     95 % CIs: stratified bootstrap pooled over the 3 training seeds.
  2. Per-week AUC of the 2018 model over the 64 EMBER2024 weeks (drift curve) and AUT (TESSERACT).
  3. Explainable drift: per named feature, PSI between the 2018 and 2024 test sets and the change in
     mean |SHAP| of the 2018 model; then an ablation retraining the 2018 model without the top-k
     drifting features (in-period cost vs cross-time gain, paired CIs).

Peak RSS is about 1.5 GB (91-feature matrices only), so it runs locally.

    python scripts/bench_drift.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path

import numpy as np
from _common import FIGURES, binary_metrics, data_dir, dump, threshold_for_fpr
from _stats import bootstrap_roc, paired_bootstrap_diff, psi, roc_metrics

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
        out[split] = (F, np.array([int(r["label"]) for r in rows], np.int8), np.array([r["appeared"] for r in rows]))
    return out


def load24(data: Path):
    p = data / "ember2024" / "processed"
    out = {}
    for split in ("train", "test"):
        F = np.load(p / f"{split}_F.npy")
        with open(p / f"{split}_meta.csv", newline="") as f:
            rows = list(csv.DictReader(f))
        out[split] = (F, np.array([int(r["label"]) for r in rows], np.int8),
                      np.array([int(r["week_id"]) for r in rows]))
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
                                     "per_seed": [{"fpr": m["fpr"], "recall": m["recall"]} for m in at]}
    r["n"] = int(y.size)
    r["n_malicious"] = int(y.sum())
    return r


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--ablate-k", type=int, default=10)
    a = ap.parse_args()
    data = data_dir(a.data)
    t0 = time.time()
    d18, d24 = load18(data), load24(data)
    F18, y18, m18 = d18["train"]
    fit18, val18 = m18 != "2018-10", m18 == "2018-10"
    T18, yT18, _ = d18["test"]
    F24, y24, w24 = d24["train"]
    fit24, val24 = w24 <= 47, w24 >= 48
    T24, yT24, wT24 = d24["test"]
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
           "subsample_note": ("EMBER 2018: deterministic sha256-prefix half (--train-frac 0.5) of the 600k labelled "
                              "training rows. EMBER2024: first 8 MiB of each weekly Win32 member (sha256-sorted, "
                              "so a sha256-range sample of about 7 % of each week), 135,423 labelled rows of ~2.0M; "
                              "chosen to fit download bandwidth and 16 GB RAM."),
           "xgb_params": {**XGB, "rounds": ROUNDS}, "seeds": seeds, "bootstrap": a.boot, "matrix": {}}
    models, thr = {}, {}
    for name, (X, y, Xv, yv) in sources.items():
        models[name] = [train(X, y, s) for s in seeds]
        thr[name] = [threshold_for_fpr(yv, score(b, Xv), 0.01) for b in models[name]]
        print(f"trained {name} x{len(seeds)} ({time.time() - t0:.0f}s)", flush=True)
    scores = {}
    for src in sources:
        for tgt, (X, y) in targets.items():
            s = [score(b, X) for b in models[src]]
            scores[(src, tgt)] = s
            res["matrix"][f"{src}->{tgt}"] = cell(y, s, thr[src], a.boot)
            r = res["matrix"][f"{src}->{tgt}"]
            print(f"{src:14s} -> {tgt:15s} AUC {r['roc_auc']['point']:.4f} [{r['roc_auc']['lo']:.4f},"
                  f"{r['roc_auc']['hi']:.4f}] TPR@1% {r['tpr_at_fpr_1pct']['point']:.3f} "
                  f"src-thr FPR {r['at_source_1pct_threshold']['fpr_mean']:.4f} "
                  f"recall {r['at_source_1pct_threshold']['recall_mean']:.3f}", flush=True)
    # paired: does the 2018 model lose on 2024 relative to an in-period 2024 model of the same size?
    res["paired"] = {
        "2024test: ember2024 - ember2018_sub": paired_bootstrap_diff(
            yT24, scores[("ember2024", "ember2024_test")], scores[("ember2018_sub", "ember2024_test")], a.boot),
        "2018test: ember2018_sub - ember2024": paired_bootstrap_diff(
            yT18, scores[("ember2018_sub", "ember2018_test")], scores[("ember2024", "ember2018_test")], a.boot),
    }

    # ---- per-week drift curve of the 2018 model (all 64 EMBER2024 weeks)
    allF = np.vstack([F24, T24])
    ally = np.concatenate([y24, yT24])
    allw = np.concatenate([w24, wT24])
    s_all = np.mean([score(b, allF) for b in models["ember2018"]], axis=0)
    curve = []
    for w in np.unique(allw):
        m = allw == w
        if 0 < ally[m].sum() < m.sum():
            auc, t1, _ = roc_metrics(ally[m], s_all[m])
            curve.append({"week": int(w), "n": int(m.sum()), "roc_auc": auc, "tpr_at_fpr_1pct": t1})
    res["weekly_2018_model_on_2024"] = curve
    aucs = np.array([c["roc_auc"] for c in curve])
    res["aut_auc_2018_model_over_2024_weeks"] = float(np.trapezoid(aucs) / (len(aucs) - 1)) if len(aucs) > 1 else None

    # ---- explainable drift: PSI and SHAP-mass change per named feature
    import xgboost as xgb

    b0 = models["ember2018"][0]
    rs = np.random.default_rng(1)
    i18 = rs.choice(yT18.size, 20000, replace=False)
    i24 = rs.choice(yT24.size, min(20000, yT24.size), replace=False)
    sh18 = np.abs(b0.predict(xgb.DMatrix(T18[i18]), pred_contribs=True)[:, :-1]).mean(axis=0)
    sh24 = np.abs(b0.predict(xgb.DMatrix(T24[i24]), pred_contribs=True)[:, :-1]).mean(axis=0)
    feats = []
    for j, n in enumerate(FEATURE_NAMES):
        feats.append({"feature": n, "psi_benign": psi(T18[yT18 == 0, j], T24[yT24 == 0, j]),
                      "psi_malicious": psi(T18[yT18 == 1, j], T24[yT24 == 1, j]),
                      "mean_abs_shap_2018": float(sh18[j]), "mean_abs_shap_2024": float(sh24[j])})
    for f in feats:
        f["psi"] = max(f["psi_benign"], f["psi_malicious"])
        f["drift_weight"] = f["psi"] * f["mean_abs_shap_2018"]  # shifted AND relied upon
    feats.sort(key=lambda f: -f["drift_weight"])
    res["feature_drift"] = feats

    # ---- ablation: drop the top-k drift-weighted features, retrain the 2018 model
    drop = [FEATURE_NAMES.index(f["feature"]) for f in feats[: a.ablate_k]]
    keep = [j for j in range(len(FEATURE_NAMES)) if j not in drop]
    Xa, ya = F18[fit18], y18[fit18]
    abl = [train(Xa, ya, s, keep) for s in seeds]
    athr = [threshold_for_fpr(y18[val18], score(b, F18[val18], keep), 0.01) for b in abl]
    ab = {"dropped": [FEATURE_NAMES[j] for j in drop]}
    for tgt, (X, y) in targets.items():
        s = [score(b, X, keep) for b in abl]
        ab[tgt] = cell(y, s, athr, a.boot)
        ab[f"{tgt}: ablated - full"] = paired_bootstrap_diff(y, s, scores[("ember2018", tgt)], a.boot)
    # control: drop k random features (same k) to show the gain is specific to the drifting ones
    rr = np.random.default_rng(7)
    rnd = sorted(rr.choice(len(FEATURE_NAMES), a.ablate_k, replace=False).tolist())
    keep_r = [j for j in range(len(FEATURE_NAMES)) if j not in rnd]
    abr = [train(Xa, ya, s, keep_r) for s in seeds]
    ab["random_control"] = {"dropped": [FEATURE_NAMES[j] for j in rnd]}
    for tgt, (X, y) in targets.items():
        s = [score(b, X, keep_r) for b in abr]
        ab["random_control"][f"{tgt}: random-ablated - full"] = paired_bootstrap_diff(
            y, s, scores[("ember2018", tgt)], a.boot)
    res["drift_ablation"] = ab
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_drift.json", res)
    _figure(curve, feats)


def _figure(curve, feats):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(10, 3.8), dpi=110)
    w = [c["week"] for c in curve]
    ax.plot(w, [c["roc_auc"] for c in curve], marker=".", lw=1.2, color="#4c72b0")
    ax.axvline(51.5, ls=":", c="grey")
    ax.set_xlabel("EMBER2024 week (0 = 2023-09-24; test from 52)")
    ax.set_ylabel("ROC AUC")
    ax.set_title("2018-trained VITRINE XGB on EMBER2024 weeks")
    ax.grid(alpha=0.3)
    top = feats[:12][::-1]
    bx.barh([f["feature"] for f in top], [f["drift_weight"] for f in top], color="#dd8452")
    bx.set_xlabel("PSI x mean |SHAP| (2018 model)")
    bx.set_title("Named features that drifted and mattered")
    fig.tight_layout()
    fig.savefig(FIGURES / "drift_ember2024.png")


if __name__ == "__main__":
    main()
