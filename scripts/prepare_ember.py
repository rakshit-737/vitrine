#!/usr/bin/env python
"""Stream the EMBER 2018 archive once and write compact, model-ready arrays.

Reads ``ember_dataset_2018_2.tar.bz2`` directly (no 10 GB extraction to disk) and writes to
``<data>/processed/``:

* ``{split}_X.f32``      EMBER v2 2381-dim vectors (float32, row-major; shape in ``{split}_shape.json``)
* ``{split}_F.npy``      VITRINE interpretable feature matrix (float32)
* ``{split}_meta.csv``   sha256, label, avclass, appeared
* ``{split}_struct.jsonl.gz``  structural record per sample (imports, sections, entry, general,
  string stats) -- used by the YARA and clustering benchmarks
* ``test_raw_sample.jsonl.gz``  full raw records for a deterministic 10 % of the test set
  (adversarial-perturbation benchmark)

Unlabeled training rows (label -1) are skipped. Usage::

    python scripts/prepare_ember.py --data D:/cyber-portfolio/datasets/vitrine [--workers 8]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import multiprocessing as mp
import os
import sys
import tarfile
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitrine.ember import vectorize_many  # noqa: E402
from vitrine.features import FEATURE_NAMES, vector_raw  # noqa: E402

BATCH = 2000


def _process(lines: list[bytes]):
    raws = []
    for ln in lines:
        r = json.loads(ln)
        if r["label"] == -1:
            continue
        raws.append(r)
    if not raws:
        return None
    X = vectorize_many(raws)
    F = np.asarray([vector_raw(r) for r in raws], dtype=np.float32)
    meta = [(r["sha256"], r["label"], r.get("avclass") or "", r.get("appeared", "")) for r in raws]
    struct = [json.dumps({
        "sha256": r["sha256"], "label": r["label"], "avclass": r.get("avclass") or "",
        "imports": r["imports"], "exports": r["exports"][:200], "section": r["section"],
        "general": r["general"], "strings": {k: v for k, v in r["strings"].items() if k != "printabledist"},
        "header": r["header"],
    }, separators=(",", ":")) for r in raws]
    sample = [json.dumps(r, separators=(",", ":")) for r in raws if int(r["sha256"][:4], 16) % 10 == 0]
    return X, F, meta, struct, sample


def _lines(fobj):
    batch = []
    for ln in fobj:
        batch.append(ln)
        if len(batch) >= BATCH:
            yield batch
            batch = []
    if batch:
        yield batch


class SplitWriter:
    def __init__(self, out: Path, split: str):
        self.split, self.out = split, out
        self.xf = open(out / f"{split}_X.f32", "wb")
        self.F: list[np.ndarray] = []
        self.meta = open(out / f"{split}_meta.csv", "w", newline="")
        self.mw = csv.writer(self.meta)
        self.mw.writerow(["sha256", "label", "avclass", "appeared"])
        self.struct = gzip.open(out / f"{split}_struct.jsonl.gz", "wt", compresslevel=4)
        self.n = 0

    def add(self, X, F, meta, struct):
        self.xf.write(np.ascontiguousarray(X, dtype=np.float32).tobytes())
        self.F.append(F)
        self.mw.writerows(meta)
        self.struct.write("\n".join(struct) + "\n")
        self.n += len(meta)

    def close(self):
        self.xf.close()
        self.meta.close()
        self.struct.close()
        np.save(self.out / f"{self.split}_F.npy", np.vstack(self.F) if self.F else np.zeros((0, len(FEATURE_NAMES))))
        (self.out / f"{self.split}_shape.json").write_text(json.dumps({"rows": self.n, "cols": 2381,
                                                                       "features": FEATURE_NAMES}))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=os.environ.get("VITRINE_DATA", "data"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--archive", default="ember_dataset_2018_2.tar.bz2")
    a = ap.parse_args()
    data = Path(a.data)
    out = data / "processed"
    out.mkdir(parents=True, exist_ok=True)
    writers = {"train": SplitWriter(out, "train"), "test": SplitWriter(out, "test")}
    sample = gzip.open(out / "test_raw_sample.jsonl.gz", "wt", compresslevel=4)
    t0 = time.time()
    with tarfile.open(data / a.archive, "r|bz2") as tar, mp.Pool(a.workers) as pool:
        for member in tar:
            name = Path(member.name).name
            if not name.endswith(".jsonl") or "features" not in name:
                continue
            split = "test" if name.startswith("test") else "train"
            print(f"[{time.time() - t0:7.0f}s] {member.name} -> {split}", flush=True)
            f = tar.extractfile(member)
            for res in pool.imap(_process, _lines(f), chunksize=1):
                if res is None:
                    continue
                X, F, meta, struct, smp = res
                writers[split].add(X, F, meta, struct)
                if split == "test" and smp:
                    sample.write("\n".join(smp) + "\n")
            print(f"    {split}: {writers[split].n} labeled rows so far", flush=True)
    for w in writers.values():
        w.close()
    sample.close()
    print(f"done in {time.time() - t0:.0f}s: " + ", ".join(f"{k}={w.n}" for k, w in writers.items()))


if __name__ == "__main__":
    main()
