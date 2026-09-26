#!/usr/bin/env python
"""Fold previously trained LightGBM baselines into ``results/ember_benchmark.json``.

``train_ember.py`` trains the 2381-dim LightGBM baselines and VITRINE's XGBoost in one process,
which on a 16 GB laptop can be memory-starved. It saves every model's test (and validation)
scores under ``<data>/models``; this script re-evaluates any saved ``*_test_scores.npy`` that is
missing from the benchmark JSON (same metrics, same validation-calibrated thresholds), adds its
packed/unpacked AUCs and redraws the ROC figure -- without retraining anything.

    python scripts/merge_baselines.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import json

import numpy as np
from _common import RESULTS, data_dir, dump, load_split
from train_ember import _figures, evaluate

from vitrine.features import FEATURE_NAMES

# what each saved baseline was trained with (recorded by train_ember.py; memory-limited run)
KNOWN = {"lgbm_ember_paper": {"params": {"objective": "binary", "num_boost_round": 100},
                              "n_train": 150000, "train_seconds": None}}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    a = ap.parse_args()
    data = data_dir(a.data)
    md = data / "models"
    res = json.loads((RESULTS / "ember_benchmark.json").read_text())
    have = {m["model"] for m in res["models"]}

    _, _, ytr, mtr = load_split(data, "train", vectors=False)
    _, Fte, yte, _ = load_split(data, "test", vectors=False)
    yv = ytr[np.asarray([m == "2018-10" for m in mtr["appeared"]])]

    scores = {}
    for p in sorted(md.glob("*_test_scores.npy")):
        name = p.name.removesuffix("_test_scores.npy")
        scores[name] = np.load(p)
        vp = md / f"{name}_val_scores.npy"
        if name in have or not vp.exists():
            continue
        r = evaluate(name, yv, np.load(vp), yte, scores[name], 0.0)
        r.update({k: v for k, v in KNOWN.get(name, {}).items() if v is not None})
        r["train_seconds"] = KNOWN.get(name, {}).get("train_seconds")
        r["n_features"] = 2381
        res["models"].insert(0, r)

    col = {n: Fte[:, FEATURE_NAMES.index(n)] for n in ("packer_section_name", "n_high_entropy_sections",
                                                          "imports_tiny")}
    pk = (col["packer_section_name"] > 0) | ((col["n_high_entropy_sections"] > 0) & (col["imports_tiny"] > 0))
    from sklearn.metrics import roc_auc_score

    sub = res.setdefault("packing_subsets", {})
    for name, s in scores.items():
        sub[name] = {"auc_packed": float(roc_auc_score(yte[pk], s[pk])),
                     "auc_unpacked": float(roc_auc_score(yte[~pk], s[~pk]))}
    dump("ember_benchmark.json", res)
    _figures(yte, scores, res)


if __name__ == "__main__":
    main()
