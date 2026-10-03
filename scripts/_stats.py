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
    # exact bounds at the edges (floating-point rounding otherwise leaves e.g. 1e-19 for k = 0)
    return (0.0 if k == 0 else max(0.0, c - h), 1.0 if k == n else min(1.0, c + h))


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
    """95 % CI of metric(a) - metric(c) on the same stratified resamples (seed-pooled).

    Returns, per metric, the plug-in ``point`` difference (mean over seeds), the bootstrap ``mean`` and
    the 2.5 / 97.5 percentiles ``lo`` / ``hi``."""
    rng = np.random.default_rng(seed)
    d = np.empty((b, 3))
    for i in range(b):
        idx = stratified_indices(y, rng)
        d[i] = np.subtract(roc_metrics(y[idx], a[i % len(a)][idx]), roc_metrics(y[idx], c[i % len(c)][idx]))
    lo, hi = np.percentile(d, [2.5, 97.5], axis=0)
    # plug-in point estimate: mean over seed pairs of the full-sample difference ("mean" is the
    # bootstrap-resample mean, kept for continuity with earlier result files)
    k = max(len(a), len(c))
    pt = np.mean([np.subtract(roc_metrics(y, a[i % len(a)]), roc_metrics(y, c[i % len(c)])) for i in range(k)],
                 axis=0)
    names = ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct")
    return {n: {"point": float(pt[j]), "mean": float(d[:, j].mean()), "lo": float(lo[j]), "hi": float(hi[j])}
            for j, n in enumerate(names)}


def psi_legacy(a: np.ndarray, b: np.ndarray, bins: int = 10) -> float:
    """PSI on reference deciles with a 1e-4 floor (the v1.1.0 definition, kept for comparison).

    Known defect: when a value (usually 0) holds more than one decile of the reference, the deciles
    collapse, so a feature that is 0 in >= 90 % of the reference falls into ONE bin and gets PSI 0
    whatever happens to its non-zero part. :func:`psi` fixes this.
    """
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


def psi_bins(ref: np.ndarray, bins: int = 10, mass: float | None = None, presorted: bool = False):
    """Point-mass-aware bins: (atoms, edges).

    Every value holding at least ``mass`` (default 1/bins) of ``ref`` is an atom with its own bin;
    the remaining values get ``bins`` quantile bins of their own. With few distinct values (<= 2*bins)
    every value is an atom.
    """
    mass = 1.0 / bins if mass is None else mass
    r = ref if presorted else np.sort(ref)
    first = np.r_[True, r[1:] != r[:-1]] if r.size else np.zeros(0, bool)
    vals = r[first]
    cnt = np.diff(np.r_[np.flatnonzero(first), r.size])
    if vals.size <= 2 * bins:
        return vals, np.array([-np.inf, np.inf])
    atoms = vals[cnt >= mass * r.size]
    rest = r[~np.isin(r, atoms)] if atoms.size else r
    if rest.size == 0:
        return atoms, np.array([-np.inf, np.inf])
    qs = np.unique(np.quantile(rest, np.linspace(0, 1, bins + 1)))
    return atoms, np.concatenate([[-np.inf], qs[1:-1], [np.inf]])


def bin_shares(x: np.ndarray, atoms: np.ndarray, edges: np.ndarray, presorted: bool = False) -> np.ndarray:
    """Shares of ``x`` in each atom, then in each half-open interval ``[e_i, e_i+1)`` of ``edges`` (atoms
    excluded from the intervals)."""
    xs = x if presorted else np.sort(x)
    a_cnt = np.searchsorted(xs, atoms, "right") - np.searchsorted(xs, atoms, "left")
    cum = np.searchsorted(xs, edges, "left")
    cum[-1] = xs.size  # last interval is closed at +inf
    iv = np.diff(cum).astype(float)
    if atoms.size:
        np.subtract.at(iv, np.clip(np.searchsorted(edges, atoms, "right") - 1, 0, iv.size - 1), a_cnt)
    return np.r_[a_cnt, iv] / max(xs.size, 1)


def psi(a: np.ndarray, b: np.ndarray, bins: int = 10, floor: float = 1e-4, pooled: bool = False) -> float:
    """Population stability index of ``b`` against reference ``a`` on point-mass-aware bins.

    Atoms (e.g. the 0 of a sparse count) get their own bin, the rest is cut into reference quantiles
    (``pooled=True``: quantiles of a and b together), and bin shares are floored at ``floor``.
    """
    sa, sb = np.sort(a), np.sort(b)
    atoms, edges = psi_bins(np.sort(np.concatenate([a, b])) if pooled else sa, bins, presorted=True)
    pa = np.clip(bin_shares(sa, atoms, edges, True), floor, None)
    pb = np.clip(bin_shares(sb, atoms, edges, True), floor, None)
    return float(np.sum((pb - pa) * np.log(pb / pa)))


def total_variation(a: np.ndarray, b: np.ndarray) -> float:
    """Total-variation distance between the empirical distributions of two discrete samples."""
    vals = np.union1d(np.unique(a), np.unique(b))
    pa = np.array([np.count_nonzero(a == v) for v in vals]) / a.size
    pb = np.array([np.count_nonzero(b == v) for v in vals]) / b.size
    return float(0.5 * np.abs(pa - pb).sum())


def bootstrap_threshold(y: np.ndarray, scores: list[np.ndarray], thresholds: list[float], b: int = 1000,
                        seed: int = 2) -> dict:
    """Recall and FPR at fixed (source-calibrated) thresholds: seed-pooled stratified bootstrap.

    Resample ``i`` uses training seed ``i % len(scores)`` with its own threshold, so the interval covers
    test-set sampling and seed variance. Point = mean over seeds. Also returns per-seed Wilson intervals.
    """
    y = np.asarray(y)
    rng = np.random.default_rng(seed)
    hits = [np.asarray(s) >= t for s, t in zip(scores, thresholds)]
    pos, neg = y == 1, y == 0
    draws = np.empty((b, 2))
    for i in range(b):
        idx = stratified_indices(y, rng)
        h, yy = hits[i % len(hits)][idx], y[idx]
        draws[i] = (h[yy == 1].mean(), h[yy == 0].mean())
    lo, hi = np.percentile(draws, [2.5, 97.5], axis=0)
    rec = [float(h[pos].mean()) for h in hits]
    fpr = [float(h[neg].mean()) for h in hits]
    return {"recall": {"point": float(np.mean(rec)), "lo": float(lo[0]), "hi": float(hi[0])},
            "fpr": {"point": float(np.mean(fpr)), "lo": float(lo[1]), "hi": float(hi[1])},
            "per_seed": [{"recall": r, "recall_wilson95": wilson(int(h[pos].sum()), int(pos.sum())),
                          "fpr": f, "fpr_wilson95": wilson(int(h[neg].sum()), int(neg.sum()))}
                         for r, f, h in zip(rec, fpr, hits)],
            "n_pos": int(pos.sum()), "n_neg": int(neg.sum()), "resamples": b}


def independent_bootstrap_diff(ya: np.ndarray, sa: list[np.ndarray], yb: np.ndarray, sb: list[np.ndarray],
                               b: int = 1000, seed: int = 3, ta: list[float] | None = None,
                               tb: list[float] | None = None) -> dict:
    """95 % CI of metric(test set A) - metric(test set B) for the SAME models scored on two different
    test sets, each resampled independently (stratified); resample ``i`` uses seed ``i % n_seeds`` on
    both sides. With thresholds ``ta``/``tb`` (per seed) recall and FPR differences are included."""
    rng = np.random.default_rng(seed)
    names = ["roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct"]
    if ta is not None:
        names += ["recall_at_source_threshold", "fpr_at_source_threshold"]

    def metrics(y, s, t):
        m = list(roc_metrics(y, s))
        if t is not None:
            h = s >= t
            m += [h[y == 1].mean(), h[y == 0].mean()]
        return m

    d = np.empty((b, len(names)))
    for i in range(b):
        k = i % len(sa)
        ia, ib = stratified_indices(ya, rng), stratified_indices(yb, rng)
        d[i] = np.subtract(metrics(ya[ia], sa[k][ia], None if ta is None else ta[k]),
                           metrics(yb[ib], sb[k][ib], None if tb is None else tb[k]))
    pt = np.mean([np.subtract(metrics(ya, a_, None if ta is None else ta[k]),
                              metrics(yb, b_, None if tb is None else tb[k]))
                  for k, (a_, b_) in enumerate(zip(sa, sb))], axis=0)
    lo, hi = np.percentile(d, [2.5, 97.5], axis=0)
    return {n: {"point": float(pt[j]), "lo": float(lo[j]), "hi": float(hi[j])} for j, n in enumerate(names)}
