"""Verdict model: L2 logistic regression (pure Python) with exact linear-SHAP attribution,
plus nearest-centroid family assignment.

Why linear: for a linear model over standardized features, SHAP values with an
independent-feature, mean baseline are exactly w_i * (x_i - mu_i) / sigma_i, so
the attribution is faithful by construction. The EMBER-trained XGBoost + TreeSHAP model
(:mod:`vitrine.gbdt`) uses the same Attribution contract; this model backs CI and the demo.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from .features import FEATURE_NAMES, describe
from .models import Attribution


def _sigmoid(z: float) -> float:
    if z < -35:
        return 0.0
    if z > 35:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


@dataclass
class VerdictModel:
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    mu: list[float] = field(default_factory=list)
    sigma: list[float] = field(default_factory=list)
    weights: list[float] = field(default_factory=list)
    bias: float = 0.0
    centroids: dict[str, list[float]] = field(default_factory=dict)

    def _z(self, x: list[float]) -> list[float]:
        return [(xi - m) / s for xi, m, s in zip(x, self.mu, self.sigma)]

    def fit(self, X: list[list[float]], y: list[int], families: list[str] | None = None,
            epochs: int = 400, lr: float = 0.1, l2: float = 1e-2) -> VerdictModel:
        n, d = len(X), len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(d)]
        self.sigma = [math.sqrt(sum((r[j] - self.mu[j]) ** 2 for r in X) / n) or 1.0 for j in range(d)]
        Z = [self._z(r) for r in X]
        w, b = [0.0] * d, 0.0
        for _ in range(epochs):
            gw, gb = [0.0] * d, 0.0
            for zi, yi in zip(Z, y):
                err = _sigmoid(sum(a * c for a, c in zip(w, zi)) + b) - yi
                gb += err
                for j in range(d):
                    gw[j] += err * zi[j]
            w = [wj - lr * (g / n + l2 * wj) for wj, g in zip(w, gw)]
            b -= lr * gb / n
        self.weights, self.bias = w, b
        if families:
            groups: dict[str, list[list[float]]] = {}
            for zi, fam, yi in zip(Z, families, y):
                if yi:
                    groups.setdefault(fam, []).append(zi)
            self.centroids = {f: [sum(c) / len(rs) for c in zip(*rs)] for f, rs in groups.items()}
        return self

    def score(self, x: list[float]) -> float:
        z = self._z(x)
        return _sigmoid(sum(a * c for a, c in zip(self.weights, z)) + self.bias)

    def attribute(self, x: list[float], top: int = 5) -> list[Attribution]:
        z = self._z(x)
        contribs = [
            Attribution(n, xi, round(w * zi, 4), describe(n, xi))
            for n, xi, w, zi in zip(self.feature_names, x, self.weights, z)
        ]
        contribs.sort(key=lambda a: abs(a.contribution), reverse=True)
        return [a for a in contribs[:top] if a.contribution != 0]

    def family(self, x: list[float]) -> tuple[str | None, float]:
        if not self.centroids:
            return None, float("inf")
        z = self._z(x)
        best = min(self.centroids.items(), key=lambda kv: sum((a - b) ** 2 for a, b in zip(z, kv[1])))
        return best[0], math.dist(z, best[1])

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__, indent=1))

    @classmethod
    def load(cls, path: str | Path) -> VerdictModel:
        m = cls(**json.loads(Path(path).read_text()))
        if m.feature_names != FEATURE_NAMES:
            raise ValueError("model feature schema mismatch; retrain")
        return m


def evaluate(model: VerdictModel, X: list[list[float]], y: list[int], thr: float = 0.5) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for x, yi in zip(X, y):
        p = model.score(x) >= thr
        tp += p and yi
        fp += p and not yi
        tn += (not p) and not yi
        fn += (not p) and yi
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}
