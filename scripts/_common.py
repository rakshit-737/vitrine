"""Shared helpers for the benchmark scripts (data paths, loaders, metrics)."""
from __future__ import annotations

import csv
import gzip
import json
import os
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
RESULTS = REPO / "results"
FIGURES = REPO / "docs" / "figures"


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


def dump(name: str, obj) -> Path:
    RESULTS.mkdir(exist_ok=True)
    p = RESULTS / name
    p.write_text(json.dumps(obj, indent=2, default=float))
    print(f"wrote {p}")
    return p
