"""Small statistics helpers shared by the benchmark scripts (intervals, bootstrap, paired tests)."""
from __future__ import annotations

import math

import numpy as np

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score 95 % interval for a binomial proportion k/n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rule_of_three(n: int) -> float:
    """Approximate one-sided 95 % upper bound on a rate when 0 events are seen in n trials."""
    return 3.0 / n if n else 1.0


def mcnemar_p(a: np.ndarray, b: np.ndarray) -> float:
    """Exact two-sided McNemar p-value for paired binary outcomes a, b."""
    from math import comb

    a, b = np.asarray(a, bool), np.asarray(b, bool)
    n01, n10 = int((~a & b).sum()), int((a & ~b).sum())
    n = n01 + n10
    if n == 0:
        return 1.0
    k = min(n01, n10)
    p = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return float(min(1.0, 2 * p))


def roc_metrics(y: np.ndarray, s: np.ndarray) -> tuple[float, float, float]:
    """(ROC AUC, TPR at FPR<=1 %, TPR at FPR<=0.1 %) from one ROC pass."""
    from sklearn.metrics import roc_curve

    fpr, tpr, _ = roc_curve(y, s)
    auc = float(np.trapezoid(tpr, fpr)) if hasattr(np, "trapezoid") else float(np.trapz(tpr, fpr))
    t1 = float(tpr[np.flatnonzero(fpr <= 0.01)[-1]])
    t01 = float(tpr[np.flatnonzero(fpr <= 0.001)[-1]])
    return auc, t1, t01


def stratified_indices(y: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    return np.concatenate([rng.choice(pos, pos.size), rng.choice(neg, neg.size)])


def bootstrap_roc(y: np.ndarray, scores: list[np.ndarray], b: int = 1000, seed: int = 0) -> dict:
    """Stratified bootstrap of ROC metrics, pooled over ``scores`` (one array per training seed).

    Each resample picks one seed's scores in turn, so the interval covers test-set sampling *and*
    training-seed variance. Returns point estimates (mean over seeds) and 95 % percentile CIs.
    """
    rng = np.random.default_rng(seed)
    draws = np.empty((b, 3))
    for i in range(b):
        idx = stratified_indices(y, rng)
        draws[i] = roc_metrics(y[idx], scores[i % len(scores)][idx])
    point = np.mean([roc_metrics(y, s) for s in scores], axis=0)
    lo, hi = np.percentile(draws, [2.5, 97.5], axis=0)
    names = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
    return {n: {"point": float(point[k]), "lo": float(lo[k]), "hi": float(hi[k])} for k, n in enumerate(names)}


def paired_bootstrap_diff(y: np.ndarray, a: list[np.ndarray], c: list[np.ndarray], b: int = 1000,
                          seed: int = 1) -> dict:
    """95 % CI of metric(a) - metric(c) on the same stratified resamples (seed-pooled)."""
    rng = np.random.default_rng(seed)
    d = np.empty((b, 3))
    for i in range(b):
        idx = stratified_indices(y, rng)
        d[i] = np.subtract(roc_metrics(y[idx], a[i % len(a)][idx]), roc_metrics(y[idx], c[i % len(c)][idx]))
    lo, hi = np.percentile(d, [2.5, 97.5], axis=0)
    names = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
    return {n: {"mean": float(d[:, k].mean()), "lo": float(lo[k]), "hi": float(hi[k])} for k, n in enumerate(names)}


def psi(a: np.ndarray, b: np.ndarray, bins: int = 10) -> float:
    """Population stability index of feature samples a (reference) vs b, on reference quantile bins."""
    ua = np.unique(a)
    if ua.size <= bins:  # discrete feature: one bin per value seen in either sample
        vals = np.union1d(ua, np.unique(b))
        pa = np.array([(a == v).mean() for v in vals]) if vals.size < 64 else None
        pb = np.array([(b == v).mean() for v in vals]) if vals.size < 64 else None
        if pa is not None:
            pa, pb = np.clip(pa, 1e-4, None), np.clip(pb, 1e-4, None)
            return float(np.sum((pb - pa) * np.log(pb / pa)))
    qs = np.unique(np.quantile(a, np.linspace(0, 1, bins + 1)))
    edges = np.concatenate([[-np.inf], qs[1:-1], [np.inf]])
    pa = np.histogram(a, edges)[0] / a.size
    pb = np.histogram(b, edges)[0] / b.size
    pa, pb = np.clip(pa, 1e-4, None), np.clip(pb, 1e-4, None)
    return float(np.sum((pb - pa) * np.log(pb / pa)))
