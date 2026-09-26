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
import time
from pathlib import Path

# one BLAS thread per worker: default thread pools reserve ~1 GB of commit per process
for _v in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_v, "1")
import numpy as np  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _pbz2 import iter_decompressed  # noqa: E402

from vitrine.ember import vectorize_many  # noqa: E402
from vitrine.features import FEATURE_NAMES, vector_raw  # noqa: E402

BATCH = 1000


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


def _tar_members(chunks):
    """Minimal streaming ustar reader over an iterator of decompressed byte chunks.

    ``tarfile``'s stream mode reads lines through a tiny buffer and is far slower than the
    decompressor on this 10 GB archive; this reader yields (name, line-iterator) pairs.
    """
    chunks = iter(chunks)
    buf = bytearray()

    def fill(n: int) -> bool:
        while len(buf) < n:
            chunk = next(chunks, None)
            if chunk is None:
                return False
            buf.extend(chunk)
        return True

    while fill(512):
        hdr = bytes(buf[:512])
        del buf[:512]
        if hdr == b"\0" * 512:
            break
        name = hdr[:100].rstrip(b"\0").decode()
        prefix = hdr[345:500].rstrip(b"\0").decode()
        if prefix:
            name = prefix + "/" + name
        size = int(hdr[124:136].rstrip(b"\0 ").decode() or "0", 8)
        padded = (size + 511) // 512 * 512

        def body(size=size, padded=padded):
            remaining = size
            tail = b""
            while remaining > 0:
                if not buf:
                    fill(1)
                take = min(remaining, len(buf))
                chunk = tail + bytes(buf[:take])
                del buf[:take]
                remaining -= take
                parts = chunk.split(b"\n")
                tail = parts.pop()
                yield from parts
            if tail:
                yield tail
            fill(padded - size)
            del buf[: padded - size]

        yield Path(name).name, body()


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
    ap.add_argument("--train-frac", type=float, default=1.0,
                    help="deterministic (sha256-prefix) fraction of labeled training rows to keep")
    a = ap.parse_args()
    data = Path(a.data)
    out = data / "processed"
    out.mkdir(parents=True, exist_ok=True)
    writers = {"train": SplitWriter(out, "train"), "test": SplitWriter(out, "test")}
    sample = gzip.open(out / "test_raw_sample.jsonl.gz", "wt", compresslevel=4)
    t0 = time.time()

    def consume(name: str, fobj, pool) -> None:
        split = "test" if name.startswith("test") else "train"
        print(f"[{time.time() - t0:7.0f}s] {name} -> {split}", flush=True)
        # bounded in-flight window: Pool.imap would read the whole input into its task queue
        from collections import deque

        pending: deque = deque()

        def drain(block: bool) -> None:
            while pending and (block or pending[0].ready()):
                res = pending.popleft().get()
                if res is None:
                    continue
                X, F, meta, struct, smp = res
                writers[split].add(X, F, meta, struct)
                if split == "test" and smp:
                    sample.write("\n".join(smp) + "\n")

        def keep(ln: bytes) -> bool:
            head = ln[:200]
            if b'"label": -1' in head or b'"label":-1' in head:
                return False  # unlabeled: skip before paying for JSON parsing
            if split == "train" and a.train_frac < 1.0:
                i = head.find(b'"sha256": "')
                return i < 0 or int(head[i + 11 : i + 15], 16) < a.train_frac * 65536
            return True

        for batch in _lines(ln for ln in fobj if ln.strip() and keep(ln)):
            pending.append(pool.apply_async(_process, (batch,)))
            while len(pending) >= 2 * a.workers:
                pending[0].wait()
                drain(False)
        drain(True)
        print(f"    {split}: {writers[split].n} labeled rows so far", flush=True)

    extracted = data / "ember2018"
    with mp.Pool(a.workers) as pool:
        if extracted.is_dir():  # fast path: `tar -xjf` already run (bz2 streaming is single-threaded)
            for p in sorted(extracted.glob("*_features*.jsonl")):
                with open(p, "rb", buffering=1 << 24) as f:
                    consume(p.name, f, pool)
        else:
            dpool = mp.Pool(a.workers)
            for name, lines in _tar_members(iter_decompressed(data / a.archive, dpool, window=4 * a.workers)):
                if name.endswith(".jsonl") and "features" in name:
                    consume(name, lines, pool)
                else:
                    for _ in lines:  # skip member body
                        pass
            dpool.close()
    for w in writers.values():
        w.close()
    sample.close()
    print(f"done in {time.time() - t0:.0f}s: " + ", ".join(f"{k}={w.n}" for k, w in writers.items()))


if __name__ == "__main__":
    main()
