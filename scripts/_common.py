"""Shared helpers for the benchmark scripts (data paths, loaders, metrics)."""
from __future__ import annotations

import csv
import datetime as _dt
import gzip
import json
import math
import os
import platform
import subprocess
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
RESULTS = REPO / "results"
FIGURES = REPO / "docs" / "figures"
_STARTED = _dt.datetime.now(_dt.timezone.utc)


def data_dir(arg: str | None = None) -> Path:
    return Path(arg or os.environ.get("VITRINE_DATA", REPO / "data"))


def load_split(data: Path, split: str, vectors: bool = True):
    p = data / "processed"
    shape = json.loads((p / f"{split}_shape.json").read_text())
    X = np.memmap(p / f"{split}_X.f32", dtype=np.float32, mode="r", shape=(shape["rows"], shape["cols"])) \
        if vectors else None
    F = np.load(p / f"{split}_F.npy")
    with open(p / f"{split}_meta.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    y = np.asarray([int(r["label"]) for r in rows], dtype=np.int8)
    meta = {"sha256": [r["sha256"] for r in rows], "avclass": [r["avclass"] for r in rows],
            "appeared": [r["appeared"] for r in rows]}
    return X, F, y, meta


def iter_jsonl_gz(path: Path):
    with gzip.open(path, "rt") as f:
        for ln in f:
            if ln.strip():
                yield json.loads(ln)


def tpr_at_fpr(y, s, fpr_target: float) -> tuple[float, float]:
    """(TPR, threshold) at the largest threshold whose FPR <= target (test-set ROC reading)."""
    from sklearn.metrics import roc_curve

    fpr, tpr, thr = roc_curve(y, s)
    ok = np.where(fpr <= fpr_target)[0]
    i = ok[-1]
    return float(tpr[i]), float(thr[i])


def threshold_for_fpr(y, s, fpr_target: float) -> float:
    """Score threshold giving FPR <= target on a (validation) set."""
    neg = np.sort(np.asarray(s)[np.asarray(y) == 0])
    k = int(np.floor(len(neg) * (1 - fpr_target)))
    k = min(max(k, 0), len(neg) - 1)
    return float(np.nextafter(neg[k], np.float32(2)))


def binary_metrics(y, s, thr: float) -> dict:
    y = np.asarray(y)
    p = np.asarray(s) >= thr
    tp = int((p & (y == 1)).sum())
    fp = int((p & (y == 0)).sum())
    fn = int((~p & (y == 1)).sum())
    tn = int((~p & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"threshold": thr, "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def provenance() -> dict:
    """Where a result came from: commit, command, UTC times, library versions, Actions run if any.

    ``git_dirty`` ignores the output folders (``results/``, ``docs/figures/``), so a run from a clean
    checkout of ``git_commit`` reproduces the file.
    """
    import importlib.metadata as md

    dirty = [ln for ln in _git("status", "--porcelain", "--untracked-files=no").splitlines()
             if not ln[3:].startswith(("results/", "docs/figures/"))]
    pk = {}
    for name in ("numpy", "scipy", "scikit-learn", "xgboost", "lightgbm", "hdbscan"):
        try:
            pk[name] = md.version(name)
        except md.PackageNotFoundError:
            pass
    argv = [a.replace("\\", "/") for a in sys.argv]
    argv = [("<data>" if i and argv[i - 1] == "--data" else a) for i, a in enumerate(argv)]
    cmd = "python " + " ".join([argv[0].split("/vitrine/")[-1], *argv[1:]])
    out = {"git_commit": _git("rev-parse", "HEAD"), "git_dirty": bool(dirty), "command": cmd,
           "started_utc": _STARTED.isoformat(timespec="seconds"),
           "finished_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
           "python": platform.python_version(), "platform": platform.platform(terse=True),
           "packages": pk}
    if os.environ.get("GITHUB_RUN_ID"):
        url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY')}"
        out.update(runner="github-actions", github_run_id=int(os.environ["GITHUB_RUN_ID"]),
                   github_run_url=f"{url}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    else:
        out["runner"] = "local"
    return out


def _clean(o):
    """JSON-safe copy: numpy scalars/arrays to Python, NaN/inf to null (strict JSON parsers reject NaN)."""
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    if isinstance(o, np.ndarray):
        return _clean(o.tolist())
    if isinstance(o, np.generic):
        o = o.item()
    if isinstance(o, float) and not math.isfinite(o):
        return None
    return o


def dump(name: str, obj) -> Path:
    """Write ``results/<name>`` as strict JSON with a ``provenance`` block (see :func:`provenance`)."""
    RESULTS.mkdir(exist_ok=True)
    p = RESULTS / name
    obj = {**obj, "provenance": provenance()} if isinstance(obj, dict) else obj
    p.write_text(json.dumps(_clean(obj), indent=2, allow_nan=False) + "\n")
    print(f"wrote {p}")
    return p
