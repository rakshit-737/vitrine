#!/usr/bin/env python
"""Confidence intervals, seed variance and a like-for-like comparison for the EMBER 2018 benchmark.

1. Stratified bootstrap (B resamples of the 200k test set) of ROC AUC, TPR @ 1 % FPR and
   TPR @ 0.1 % FPR for every saved ``*_test_scores.npy``, plus *paired* bootstrap differences
   (VITRINE XGBoost minus each LightGBM baseline) -- the same resample indices for both models.
2. Seed variance: VITRINE XGBoost retrained with several seeds on (a) all 275,732 training rows
   and (b) the exact seeded 150k-row subsample the LightGBM baselines used (like-for-like rows).

Writes ``results/ember_ci.json``. Needs the prepared EMBER data (``--data``).

    python scripts/bench_ci.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import json
import time

import numpy as np
from _common import data_dir, dump, load_split
from sklearn.metrics import roc_auc_score, roc_curve

from vitrine.gbdt import GBDTVerdictModel


def _metrics(y, s) -> dict:
    fpr, tpr, _ = roc_curve(y, s)
    out = {"roc_auc": float(roc_auc_score(y, s))}
    for name, t in (("tpr_at_fpr_1pct", 0.01), ("tpr_at_fpr_0.1pct", 0.001)):
        out[name] = float(tpr[np.where(fpr <= t)[0][-1]])
    return out


def _ci(vals) -> dict:
    v = np.asarray(vals)
    return {"mean": float(v.mean()), "lo": float(np.percentile(v, 2.5)), "hi": float(np.percentile(v, 97.5))}


def bootstrap(y, scores: dict, B: int, seed: int = 0) -> dict:
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    draws = {n: [] for n in scores}
    for _ in range(B):
        idx = np.concatenate([rng.choice(pos, pos.size), rng.choice(neg, neg.size)])
        for n, s in scores.items():
            draws[n].append(_metrics(y[idx], s[idx]))
    keys = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
    out = {"per_model": {n: {"point": _metrics(y, scores[n]), **{k: _ci([d[k] for d in draws[n]]) for k in keys}}
                         for n in scores}, "paired_diff_vitrine_xgb_minus": {}}
    if "vitrine_xgb" in draws:
        for n in scores:
            if n == "vitrine_xgb":
                continue
            out["paired_diff_vitrine_xgb_minus"][n] = {
                k: _ci([a[k] - b[k] for a, b in zip(draws["vitrine_xgb"], draws[n])]) for k in keys}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--boot", type=int, default=300)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--xgb-rounds", type=int, default=600)
    ap.add_argument("--lgbm-limit", type=int, default=150000)
    a = ap.parse_args()
    data = data_dir(a.data)
    md = data / "models"

    _, Ftr, ytr, mtr = load_split(data, "train", vectors=False)
    _, Fte, yte, _ = load_split(data, "test", vectors=False)
    yte = yte.astype(int)
    val = np.asarray([m == "2018-10" for m in mtr["appeared"]])
    fit_idx = np.flatnonzero(~val)
    sub_idx = np.sort(np.random.default_rng(0).choice(fit_idx, size=a.lgbm_limit, replace=False))

    scores = {p.name.removesuffix("_test_scores.npy"): np.load(p) for p in sorted(md.glob("*_test_scores.npy"))}
    t = time.time()
    res = {"n_test": int(yte.size), "bootstrap_resamples": a.boot, "stratified": True,
           "bootstrap": bootstrap(yte, scores, a.boot)}
    print(f"bootstrap done in {time.time() - t:.0f}s", flush=True)

    seeds = {}
    for label, idx in (("full_275k", fit_idx), (f"subsample_{a.lgbm_limit // 1000}k_same_as_lgbm", sub_idx)):
        runs = []
        for s in a.seeds:
            t = time.time()
            m = GBDTVerdictModel.fit(Ftr[idx], ytr[idx], num_rounds=a.xgb_rounds,
                                     params={"max_depth": 10, "eta": 0.08, "seed": s})
            r = _metrics(yte, m.score_many(Fte))
            r.update(seed=s, train_seconds=round(time.time() - t, 1))
            runs.append(r)
            print(label, r, flush=True)
        keys = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
        seeds[label] = {"n_train": int(idx.size), "runs": runs,
                        **{k: {"mean": float(np.mean([r[k] for r in runs])),
                               "std": float(np.std([r[k] for r in runs], ddof=1))} for k in keys}}
    res["vitrine_xgb_seed_variance"] = seeds
    dump("ember_ci.json", res)
    print(json.dumps(res["bootstrap"]["paired_diff_vitrine_xgb_minus"], indent=1))


if __name__ == "__main__":
    main()
