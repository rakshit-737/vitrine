#!/usr/bin/env python
"""Reproduce the EMBER paper's LightGBM baseline under its published setup (runs in GitHub Actions).

Setup (Anderson & Roth 2018, elastic/ember README):
  * data: ``ember_dataset.tar.bz2`` (EMBER 2017, feature version 1), sha256 checked by the workflow;
  * vectorizer: elastic/ember pinned at commit ``d97a0b5``, ``PEFeatureExtractor(feature_version=1)``
    -> 2,351 dims, run under scikit-learn 0.24 (the per-character entry-name hashing of the original);
  * model: ``lgb.train({"application": "binary"}, ...)`` -- LightGBM defaults (100 trees, 31 leaves,
    learning rate 0.1) on the 600k labelled training rows (unlabelled rows dropped, as in
    ``ember.train_model``);
  * test: the 200k labelled test rows. Metrics read off the test ROC, as in the paper, with 95 %
    stratified-bootstrap CIs.

Only raw-feature JSON is processed. No PE file is parsed, so LIEF is never called; the workflow
installs a stub ``lief`` module (``__version__``) because elastic/ember imports it at module load.
Needs about 10 GB RAM and 20 GB disk: run it in Actions (``.github/workflows/ember2017.yml``), not
on the shared laptop.

    python scripts/repro_ember2017.py --data ember2017_data --ember-src ember_src --out ember2017_repro.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import provenance  # noqa: E402
from _stats import bootstrap_roc  # noqa: E402

PAPER = {"source": "Anderson & Roth 2018, EMBER (arXiv:1804.04637), LightGBM baseline on EMBER 2017 v1",
         "roc_auc": 0.99911, "tpr_at_fpr_1pct": 0.982, "tpr_at_fpr_0.1pct": 0.9299}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--ember-src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--sha256", default="")
    ap.add_argument("--skip-vectorize", action="store_true")
    a = ap.parse_args()
    sys.path.insert(0, a.ember_src)
    import ember
    import lightgbm as lgb
    import sklearn

    t0 = time.time()
    data = str(Path(a.data))
    if not a.skip_vectorize:
        ember.create_vectorized_features(data, feature_version=1)
    t_vec = time.time() - t0
    X, y, Xt, yt = ember.read_vectorized_features(data, feature_version=1)
    lab = y != -1
    model = lgb.train({"application": "binary"}, lgb.Dataset(np.asarray(X[lab]), np.asarray(y[lab])))
    t_fit = time.time() - t0 - t_vec
    st = model.predict(np.asarray(Xt))
    ytl = np.asarray(yt).astype(np.int8)
    m = ytl != -1
    rep = bootstrap_roc(ytl[m], [st[m]], b=a.boot)
    res = {
        "description": __doc__.split("\n\n")[0],
        "dataset": "EMBER 2017 feature version 1 (ember_dataset.tar.bz2)",
        "archive_sha256": a.sha256,
        "vectorizer": "elastic/ember@d97a0b5 PEFeatureExtractor(feature_version=1)",
        "n_features": int(X.shape[1]),
        "rows": {"train_total": int(y.shape[0]), "train_labelled": int(lab.sum()),
                 "test_labelled": int(m.sum()), "test_malicious": int(ytl[m].sum())},
        "model": "LightGBM defaults, params={'application': 'binary'} (100 trees, 31 leaves, lr 0.1)",
        "versions": {"python": sys.version.split()[0], "lightgbm": lgb.__version__,
                     "scikit_learn": sklearn.__version__, "numpy": np.__version__},
        "paper": PAPER,
        "reproduction": rep,
        "reproduction_minus_paper": {k: rep[k]["point"] - PAPER[k]
                                     for k in ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")},
        "paper_value_inside_ci": {k: rep[k]["lo"] <= PAPER[k] <= rep[k]["hi"]
                                  for k in ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")},
        "bootstrap": a.boot,
        "runtime_seconds": {"vectorize": round(t_vec), "train": round(t_fit), "total": round(time.time() - t0)},
        "provenance": provenance(),  # Actions run id/URL, commit, command, versions
    }
    Path(a.out).write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
