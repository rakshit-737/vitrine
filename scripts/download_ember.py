#!/usr/bin/env python
"""Download the EMBER 2018 (feature version 2) raw-feature dataset with checksum verification.

The archive contains *pre-extracted JSON features only* -- no PE binaries, no malware.
Resumable, chunked, parallel HTTP range download (the host is slow on some links), followed by
MD5 (as published by the GCS bucket) and SHA-256 verification.

    python scripts/download_ember.py --out D:/cyber-portfolio/datasets/vitrine

Licence / citation: EMBER is released by Endgame/Elastic for research use;
cite Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning
Models", arXiv:1804.04637 (2018).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import os
import sys
import time
import urllib.request
from pathlib import Path

DATASETS = {
    "2018": {
        "url": "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
        "size": 1_696_539_273,
        "md5": "45483514 19e305c9 79497e4a 40463b7f".replace(" ", ""),
        # as published in the elastic/ember README
        "sha256": "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812",
    },
}
CHUNK = 16 * 1024 * 1024


def _fetch_range(url: str, start: int, end: int, part: Path, retries: int = 50) -> None:
    want = end - start + 1
    for attempt in range(retries):
        have = part.stat().st_size if part.exists() else 0
        if have >= want:
            return
        req = urllib.request.Request(url, headers={"Range": f"bytes={start + have}-{end}",
                                                   "User-Agent": "vitrine-downloader"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(part, "ab") as f:
                while True:
                    buf = r.read(1 << 16)
                    if not buf:
                        break
                    f.write(buf)
        except Exception as e:  # noqa: BLE001 - network errors of all kinds: retry
            print(f"  chunk {start}: {type(e).__name__}: {e} (retry {attempt + 1})", file=sys.stderr)
            time.sleep(min(30, 2 ** min(attempt, 5)))
    raise RuntimeError(f"failed to fetch range {start}-{end}")


def _digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(1 << 20), b""):
            h.update(buf)
    return h.hexdigest()


def download(which: str, out: Path, workers: int) -> Path:
    meta = DATASETS[which]
    out.mkdir(parents=True, exist_ok=True)
    dest = out / meta["url"].rsplit("/", 1)[1]
    if dest.exists() and dest.stat().st_size == meta["size"]:
        print(f"{dest} already present")
    else:
        parts_dir = out / (dest.name + ".parts")
        parts_dir.mkdir(exist_ok=True)
        ranges = [(s, min(s + CHUNK, meta["size"]) - 1) for s in range(0, meta["size"], CHUNK)]
        done = 0
        with cf.ThreadPoolExecutor(workers) as ex:
            futs = {ex.submit(_fetch_range, meta["url"], s, e, parts_dir / f"{s:012d}.part"): s
                    for s, e in ranges}
            for fut in cf.as_completed(futs):
                fut.result()
                done += 1
                print(f"  {done}/{len(ranges)} chunks", flush=True)
        with open(dest, "wb") as f:
            for s, _ in ranges:
                p = parts_dir / f"{s:012d}.part"
                f.write(p.read_bytes())
                p.unlink()
        parts_dir.rmdir()
    print("verifying md5 ...")
    md5 = _digest(dest, "md5")
    if md5 != meta["md5"]:
        raise SystemExit(f"MD5 mismatch: {md5} != {meta['md5']} -- delete {dest} and retry")
    sha = _digest(dest, "sha256")
    if meta["sha256"] and sha != meta["sha256"]:
        raise SystemExit(f"SHA-256 mismatch: {sha}")
    (out / "checksums.txt").write_text(f"{sha}  {dest.name}\nmd5 {md5}\n")
    print(f"OK {dest} sha256={sha}")
    return dest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--which", default="2018", choices=sorted(DATASETS))
    ap.add_argument("--out", default=os.environ.get("VITRINE_DATA", "data"))
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    download(a.which, Path(a.out), a.workers)


if __name__ == "__main__":
    main()
