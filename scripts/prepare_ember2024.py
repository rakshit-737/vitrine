#!/usr/bin/env python
"""Vectorize the EMBER2024 Win32 subsample fetched by ``download_ember2024.py``.

Writes to ``<data>/ember2024/processed/`` for ``split`` in {train, test}:

* ``{split}_X2.f32``  EMBER feature-version-2 vector (2,381-dim) of the record translated by
  :mod:`vitrine.ember3` -- the *same* representation as the EMBER 2018 matrices, for cross-year runs
* ``{split}_X3.f32``  native EMBER feature-version-3 vector (2,568-dim), computed with the
  EMBER2024 authors' ``thrember`` code (``--thrember`` = path to ``EMBER2024/src`` at the pinned commit ``THREMBER_COMMIT``)
  -- used to reproduce the EMBER2024 paper baseline
* ``{split}_F.npy``   VITRINE's 91 interpretable features (on the translated record)
* ``{split}_meta.csv`` sha256, label, family, week_id, first_submission_date
* ``summary.json``    row counts and label balance per split / week (subsample-bias check)

    python scripts/prepare_ember2024.py --data D:/cyber-portfolio/datasets/vitrine \\
        --thrember D:/cyber-portfolio/datasets/vitrine/ref/EMBER2024/src
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import multiprocessing as mp
import os
import sys
import types
from collections import Counter
from pathlib import Path

for _v in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_v, "1")
import numpy as np  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitrine.ember import vectorize_many  # noqa: E402
from vitrine.ember3 import to_v2  # noqa: E402
from vitrine.features import FEATURE_NAMES, vector_raw  # noqa: E402

_EXTRACTOR = None
# FutureComputing4AI/EMBER2024 commit whose thrember/features.py we execute (fail closed on mismatch).
THREMBER_COMMIT = "0ef753e81d98bf209f71b03cd331dfc190b5b54d"
THREMBER_FEATURES_SHA256 = "aa9b29e2267a037ebec0b234234edfc2f8d2316e579ab1a0fba6878e70288eca"


def _check_thrember(path: str) -> None:
    import hashlib
    import subprocess

    f = Path(path) / "thrember" / "features.py"
    got = hashlib.sha256(f.read_bytes()).hexdigest()
    if got != THREMBER_FEATURES_SHA256:
        raise SystemExit(f"{f}: sha256 {got} != pinned {THREMBER_FEATURES_SHA256}")
    try:
        head = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        head = None  # not a git checkout: the file hash above is the binding check
    if head and head != THREMBER_COMMIT:
        raise SystemExit(f"thrember checkout at {head}, expected {THREMBER_COMMIT}")


def _thrember(path: str):
    """Import thrember's feature module without its binary-parsing-only ``signify`` dependency."""
    if "signify" not in sys.modules:  # only used when extracting from binaries, never here
        sig = types.ModuleType("signify")
        auth = types.ModuleType("signify.authenticode")
        auth.SignedPEFile = object
        sig.authenticode = auth
        sys.modules["signify"], sys.modules["signify.authenticode"] = sig, auth
    import importlib.util

    _check_thrember(path)

    spec = importlib.util.spec_from_file_location("thrember_features", Path(path) / "thrember" / "features.py")
    tf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tf)  # features.py only; thrember/__init__ pulls in polars etc.

    return tf.PEFeatureExtractor()


def _init(path: str) -> None:
    global _EXTRACTOR
    _EXTRACTOR = _thrember(path)


def _process(lines: list[bytes]):
    recs = [json.loads(ln) for ln in lines]
    recs = [r for r in recs if r.get("label") in (0, 1)]
    if not recs:
        return None
    X3 = np.vstack([_EXTRACTOR.process_raw_features(r) for r in recs]).astype(np.float32)
    v2 = [to_v2(r) for r in recs]
    X2 = vectorize_many(v2)
    F = np.asarray([vector_raw(r) for r in v2], dtype=np.float32)
    meta = [(r["sha256"], r["label"], r.get("family") or "", r.get("week_id"), r.get("first_submission_date"))
            for r in recs]
    return X2, X3, F, meta


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=os.environ.get("VITRINE_DATA", "data"))
    ap.add_argument("--thrember", required=True, help="path to EMBER2024/src (FutureComputing4AI/EMBER2024)")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    src = Path(a.data) / "ember2024"
    out = src / "processed"
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    with mp.Pool(a.workers, initializer=_init, initargs=(a.thrember,)) as pool:
        for split in ("train", "test"):
            files = sorted(src.glob(f"*_Win32_{split}.prefix.jsonl.gz"))
            f2, f3 = open(out / f"{split}_X2.f32", "wb"), open(out / f"{split}_X3.f32", "wb")
            Fs, n, per_week = [], 0, {}
            with open(out / f"{split}_meta.csv", "w", newline="") as mf:
                mw = csv.writer(mf)
                mw.writerow(["sha256", "label", "family", "week_id", "first_submission_date"])
                for p in files:
                    lines = gzip.open(p).read().splitlines()
                    batches = [lines[i : i + 250] for i in range(0, len(lines), 250)]
                    lab = Counter()
                    for res in pool.imap(_process, batches):
                        if res is None:
                            continue
                        X2, X3, F, meta = res
                        f2.write(X2.tobytes())
                        f3.write(X3.tobytes())
                        Fs.append(F)
                        mw.writerows(meta)
                        n += len(meta)
                        lab.update(m[1] for m in meta)
                    per_week[p.name.split("_Win32")[0]] = {"n": sum(lab.values()), "malicious": lab[1]}
                    print(f"{split} {p.name}: {sum(lab.values())} ({lab[1]} malicious)", flush=True)
            f2.close()
            f3.close()
            np.save(out / f"{split}_F.npy", np.vstack(Fs))
            summary[split] = {"rows": n, "malicious": sum(w["malicious"] for w in per_week.values()),
                              "weeks": len(per_week), "per_week": per_week}
    summary["dims"] = {"X2": 2381, "X3": _thrember(a.thrember).dim, "F": len(FEATURE_NAMES)}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print({k: (v["rows"], v["malicious"]) for k, v in summary.items() if k != "dims"}, summary["dims"])


if __name__ == "__main__":
    main()
