"""Gradient-boosted verdict model (XGBoost) with exact TreeSHAP attribution.

Trained on VITRINE's interpretable features (see :mod:`vitrine.features`). Attributions come
from XGBoost's built-in TreeSHAP (``pred_contribs=True``): per-feature contributions in log-odds
space that sum *exactly* to the model margin, so "the 5 features that drove the score" is a
faithful statement, not a post-hoc story.

Family assignment is nearest-centroid over standardized features of the training malware,
restricted to the most frequent AVClass families (EMBER 2018 metadata).

Model file: one JSON document holding the booster (XGBoost JSON format), the feature schema,
the calibrated operating thresholds and the family centroids. Requires ``xgboost`` + ``numpy``.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .features import FEATURE_NAMES, describe
from .models import Attribution


@dataclass
class GBDTVerdictModel:
    booster: object = None
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    thresholds: dict[str, float] = field(default_factory=dict)  # e.g. {"fpr_1pct": .., "fpr_0.1pct": ..}
    mu: list[float] = field(default_factory=list)
    sigma: list[float] = field(default_factory=list)
    centroids: dict[str, list[float]] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ training
    @classmethod
    def fit(cls, X: np.ndarray, y: np.ndarray, families: list[str] | None = None, top_families: int = 20,
            params: dict | None = None, num_rounds: int = 400, X_val=None, y_val=None,
            verbose: bool = False) -> GBDTVerdictModel:
        import xgboost as xgb

        p = {"objective": "binary:logistic", "eval_metric": "auc", "tree_method": "hist",
             "max_depth": 8, "eta": 0.1, "subsample": 0.8, "colsample_bytree": 0.8,
             "min_child_weight": 1.0, "nthread": 0}
        p.update(params or {})
        dtrain = xgb.DMatrix(X, label=y, feature_names=_safe_names(FEATURE_NAMES))
        evals = [(dtrain, "train")]
        if X_val is not None:
            evals.append((xgb.DMatrix(X_val, label=y_val, feature_names=_safe_names(FEATURE_NAMES)), "val"))
        booster = xgb.train(p, dtrain, num_rounds, evals=evals, verbose_eval=50 if verbose else False)
        m = cls(booster=booster)
        m.mu = X.mean(axis=0).astype(float).tolist()
        m.sigma = [s if s > 0 else 1.0 for s in X.std(axis=0).astype(float).tolist()]
        if families is not None:
            m.fit_families(X, y, families, top_families)
        return m

    def fit_families(self, X: np.ndarray, y: np.ndarray, families: list[str], top: int = 20) -> None:
        fam = np.asarray(families, dtype=object)
        mal = (np.asarray(y) == 1) & (fam != "") & (fam != None)  # noqa: E711
        names, counts = np.unique(fam[mal], return_counts=True)
        keep = names[np.argsort(-counts)[:top]]
        Z = self._z(X)
        self.centroids = {str(f): Z[mal & (fam == f)].mean(axis=0).tolist() for f in keep}

    # ------------------------------------------------------------------ inference
    def _z(self, X) -> np.ndarray:
        return (np.asarray(X, dtype=np.float64) - np.asarray(self.mu)) / np.asarray(self.sigma)

    def _dm(self, X):
        import xgboost as xgb

        X = np.atleast_2d(np.asarray(X, dtype=np.float32))
        return xgb.DMatrix(X, feature_names=_safe_names(self.feature_names))

    def score_many(self, X) -> np.ndarray:
        return self.booster.predict(self._dm(X))

    def score(self, x) -> float:
        return float(self.score_many([x])[0])

    def contributions(self, X) -> np.ndarray:
        """TreeSHAP values, shape (n, d+1); last column is the bias (expected margin)."""
        return self.booster.predict(self._dm(X), pred_contribs=True)

    def attribute(self, x, top: int = 5) -> list[Attribution]:
        c = self.contributions([x])[0]
        order = np.argsort(-np.abs(c[:-1]))[:top]
        return [Attribution(self.feature_names[i], float(x[i]), round(float(c[i]), 4),
                            describe(self.feature_names[i], float(x[i])))
                for i in order if c[i] != 0]

    def family(self, x) -> tuple[str | None, float]:
        if not self.centroids:
            return None, float("inf")
        z = self._z([x])[0]
        best = min(self.centroids.items(), key=lambda kv: float(((z - np.asarray(kv[1])) ** 2).sum()))
        return best[0], math.dist(z.tolist(), best[1])

    # ------------------------------------------------------------------ persistence
    def save(self, path: str | Path) -> None:
        doc = {"format": "vitrine-gbdt-1", "feature_names": self.feature_names, "thresholds": self.thresholds,
               "mu": self.mu, "sigma": self.sigma, "centroids": self.centroids, "meta": self.meta,
               "booster": json.loads(bytes(self.booster.save_raw("json")).decode())}
        Path(path).write_text(json.dumps(doc, separators=(",", ":")))

    @classmethod
    def load(cls, path: str | Path) -> GBDTVerdictModel:
        import xgboost as xgb

        doc = json.loads(Path(path).read_text())
        if doc.get("format") != "vitrine-gbdt-1":
            raise ValueError("not a VITRINE GBDT model file")
        if doc["feature_names"] != FEATURE_NAMES:
            raise ValueError("model feature schema mismatch; retrain with scripts/train_ember.py")
        b = xgb.Booster()
        b.load_model(bytearray(json.dumps(doc["booster"]).encode()))
        return cls(booster=b, feature_names=doc["feature_names"], thresholds=doc["thresholds"], mu=doc["mu"],
                   sigma=doc["sigma"], centroids=doc["centroids"], meta=doc.get("meta", {}))


def _safe_names(names: list[str]) -> list[str]:
    # XGBoost rejects some characters ([, ], <) in feature names
    return [n.replace("[", "(").replace("]", ")").replace("<", "lt") for n in names]
