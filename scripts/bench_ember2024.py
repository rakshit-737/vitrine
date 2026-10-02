#!/usr/bin/env python
"""EMBER2024 Win32 baselines on the VITRINE subsample: released model, paper-config retrain, and the
translation-loss control.

* ``released``: the EMBER2024 authors' ``EMBER2024_Win32.model`` (LightGBM, trained on the full
  2.4M-file Win32 training split) scored on our test-week subsample with native v3 vectors (thrember).
  Paper (Joyce et al., KDD 2025, Table 5): Win32 -> Win32 ROC AUC 0.9984, PR AUC 0.9986, on the
  full test split.
* ``retrain_v3``: the paper's ``examples/lgbm_config.json`` (500 rounds, 64 leaves, lr 0.1) retrained
  on our *subsample* of training weeks (stated N) with native v3 vectors; 3 seeds.
* ``retrain_v2_translated``: identical config and rows on the v3->v2 translated 2,381-dim vectors.
  The v3 vs v2 gap on identical rows bounds the representation loss of the translation that the
  2018<->2024 cross-time numbers (``bench_drift.py``) rely on.

Uses about 2.5 GB RAM at peak (one 107k x 2,568 float32 matrix at a time).

    python scripts/bench_ember2024.py --data D:/cyber-portfolio/datasets/vitrine \\
        --released D:/cyber-portfolio/datasets/vitrine/ref/models2024/EMBER2024_Win32.model \\
        --config D:/cyber-portfolio/datasets/vitrine/ref/EMBER2024/examples/lgbm_config.json
"""
from __future__ import annotations

import argparse
import csv
import json
import time

import numpy as np
from _common import data_dir, dump
from _stats import bootstrap_roc, paired_bootstrap_diff

DIMS = {"X2": 2381, "X3": 2568}


def meta(p):
    with open(p, newline="") as f:
        return np.array([int(r["label"]) for r in csv.DictReader(f)], np.int8)


def load(proc, split, kind, n):
    return np.fromfile(proc / f"{split}_{kind}.f32", dtype=np.float32).reshape(n, DIMS[kind])


def pr_auc(y, s):
    from sklearn.metrics import average_precision_score

    return float(average_precision_score(y, s))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--released", required=True, help="EMBER2024_Win32.model")
    ap.add_argument("--config", required=True, help="EMBER2024 examples/lgbm_config.json")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    import lightgbm as lgb

    t0 = time.time()
    proc = data_dir(a.data) / "ember2024" / "processed"
    ytr, yte = meta(proc / "train_meta.csv"), meta(proc / "test_meta.csv")
    cfg = json.loads(open(a.config).read())
    rounds = cfg.pop("num_iterations", 500)
    for k in ("task", "metric", "first_metric_only", "device_type", "tree_learner"):
        cfg.pop(k, None)
    cfg.update({"verbosity": -1, "num_threads": 8})
    res = {"subsample": {"train_rows": int(ytr.size), "train_malicious": int(ytr.sum()),
                         "test_rows": int(yte.size), "test_malicious": int(yte.sum()),
                         "note": "first 8 MiB of each weekly Win32 member (sha256-range sample, ~7 % of files); "
                                 "see results/ember2024_manifest.json"},
           "paper_win32": {"roc_auc": 0.9984, "pr_auc": 0.9986,
                           "source": "Joyce et al., KDD 2025 (arXiv:2506.05074), Table 5, full Win32 test split"},
           "lgbm_config": {**cfg, "num_iterations": rounds}, "seeds": list(range(a.seeds))}

    Xte3 = load(proc, "test", "X3", yte.size)
    rel = lgb.Booster(model_file=a.released)
    s_rel = rel.predict(Xte3)
    res["released"] = {**bootstrap_roc(yte, [s_rel], b=a.boot), "pr_auc": pr_auc(yte, s_rel),
                       "trees": int(rel.num_trees())}
    print("released", {k: v for k, v in res["released"].items()}, f"({time.time() - t0:.0f}s)", flush=True)

    scores = {}
    for kind in ("X3", "X2"):
        Xtr = load(proc, "train", kind, ytr.size)
        Xte = Xte3 if kind == "X3" else load(proc, "test", "X2", yte.size)
        ss = []
        for seed in range(a.seeds):
            p = {**cfg, "seed": seed, "bagging_seed": seed, "feature_fraction_seed": seed}
            b = lgb.train(p, lgb.Dataset(Xtr, ytr, free_raw_data=True), rounds)
            ss.append(b.predict(Xte))
            print(f"{kind} seed {seed} done ({time.time() - t0:.0f}s)", flush=True)
        name = "retrain_v3" if kind == "X3" else "retrain_v2_translated"
        res[name] = {**bootstrap_roc(yte, ss, b=a.boot), "pr_auc_mean": float(np.mean([pr_auc(yte, s) for s in ss]))}
        scores[kind] = ss
        print(name, res[name], flush=True)
        del Xtr
    res["paired_v3_minus_v2_translated"] = paired_bootstrap_diff(yte, scores["X3"], scores["X2"], b=a.boot)
    res["paired_released_minus_retrain_v3"] = paired_bootstrap_diff(yte, [s_rel], scores["X3"], b=a.boot)
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_baselines.json", res)


if __name__ == "__main__":
    main()
