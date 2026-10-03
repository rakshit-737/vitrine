#!/usr/bin/env python
"""Fetch a deterministic, bandwidth-bounded subsample of EMBER2024 (Win32 PE subset, features only).

EMBER2024 (Joyce et al., KDD 2025) is distributed on Hugging Face as zip archives of weekly JSONL
files of *pre-extracted features* (EMBER feature version 3) -- no binaries. The full Win32 split is
15 GB compressed; on the development link (~0.5 MB/s) that is days of download, so instead we
use HTTP range requests against the pinned dataset revision:

1. read each archive's zip central directory (member name, offset, compressed size);
2. for every weekly member, fetch the first ``--mb`` MiB of its deflate stream;
3. inflate that prefix and keep the complete JSON lines.

This is a **per-week prefix subsample**: every week of the train period (2023-09-24 .. 2024-09-21)
and of the test period (2024-09-22 .. 2024-12-14) is represented with roughly the same count.
The byte ranges are a pure function of the pinned revision, so the SHA-256 of every fetched range
is recorded in ``ember2024_manifest.json`` (written after every member) and re-verified with
``--verify``. Members already in the manifest whose file exists are skipped (resumable).
Whether the prefix is label-/family-biased is checked and reported by ``prepare_ember2024.py``.

    python scripts/download_ember2024.py --out D:/cyber-portfolio/datasets/vitrine/ember2024 --mb 8
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import provenance  # noqa: E402

REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
BASE = f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{REVISION}"
ARCHIVES = {  # name -> (size, sha256 of the full archive = Git-LFS oid, for reference)
    "Win32_train.zip": (12_321_281_336, "6cf9dea847960115f65d405d38b6b09d38c87225c8288dafedf00fed2512b1d4"),
    "Win32_test.zip": (2_593_425_203, "c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb"),
}
MAX_INFLATE = 1 << 30  # bound on inflated bytes per member prefix
MANIFEST = Path(__file__).resolve().parents[1] / "results" / "ember2024_manifest.json"


def _get(url: str, a: int, b: int, retries: int = 30) -> bytes:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={a}-{b}", "User-Agent": "vitrine"})
            with urllib.request.urlopen(req, timeout=120) as r:
                if r.status != 206 or not (r.headers.get("Content-Range") or "").startswith(f"bytes {a}-{b}/"):
                    raise RuntimeError(f"server ignored Range (status {r.status})")  # never read a whole archive
                data = r.read(b - a + 1)
            if len(data) == b - a + 1:
                return data
        except Exception as e:  # noqa: BLE001 - retry on any network error
            print(f"  range {a}: {type(e).__name__}: {e} (retry {attempt + 1})", file=sys.stderr)
        time.sleep(min(30, 2 ** min(attempt, 5)))
    raise RuntimeError(f"failed range {a}-{b}")


def central_directory(name: str) -> list[dict]:
    size = ARCHIVES[name][0]
    url = f"{BASE}/{name}"
    tail = _get(url, size - 65536, size - 1)
    i = tail.rfind(b"PK\x06\x06")
    if i >= 0:
        cd_size, cd_off = struct.unpack("<QQ", tail[i + 40 : i + 56])
    else:
        i = tail.rfind(b"PK\x05\x06")
        cd_size, cd_off = struct.unpack("<II", tail[i + 12 : i + 20])
    cd = _get(url, cd_off, cd_off + cd_size - 1)
    out, p = [], 0
    while cd[p : p + 4] == b"PK\x01\x02":
        meth, = struct.unpack("<H", cd[p + 10 : p + 12])
        csz, usz = struct.unpack("<II", cd[p + 20 : p + 28])
        n, e, c = struct.unpack("<HHH", cd[p + 28 : p + 34])
        off, = struct.unpack("<I", cd[p + 42 : p + 46])
        fn = cd[p + 46 : p + 46 + n].decode()
        ex = cd[p + 46 + n : p + 46 + n + e]
        q = 0
        while q < len(ex):
            hid, hl = struct.unpack("<HH", ex[q : q + 4])
            if hid == 1:  # zip64 extended information
                vals = list(struct.unpack("<" + "Q" * (hl // 8), ex[q + 4 : q + 4 + hl // 8 * 8]))
                if usz == 0xFFFFFFFF:
                    usz = vals.pop(0)
                if csz == 0xFFFFFFFF:
                    csz = vals.pop(0)
                if off == 0xFFFFFFFF:
                    off = vals.pop(0)
            q += 4 + hl
        out.append({"archive": name, "member": fn, "method": meth, "csize": csz, "usize": usz, "offset": off})
        p += 46 + n + e + c
    return out


def fetch_member_prefix(m: dict, nbytes: int, out: Path) -> dict:
    url = f"{BASE}/{m['archive']}"
    dest = out / Path(m["member"]).name.replace(".jsonl", ".prefix.jsonl.gz")
    if dest.resolve().parent != out.resolve():  # zip-slip guard: member names come from the remote archive
        raise RuntimeError(f"unsafe member name {m['member']!r}")
    hdr = _get(url, m["offset"], m["offset"] + 29)
    n, e = struct.unpack("<HH", hdr[26:30])
    start = m["offset"] + 30 + n + e
    take = min(nbytes, m["csize"])
    blob = b"".join(_get(url, a, min(a + (1 << 21), start + take) - 1)
                    for a in range(start, start + take, 1 << 21))
    sha = hashlib.sha256(blob).hexdigest()
    raw = zlib.decompressobj(-15).decompress(blob, MAX_INFLATE)
    lines = raw.split(b"\n")
    if take < m["csize"]:
        lines = lines[:-1]  # drop the truncated last line
    lines = [ln for ln in lines if ln.strip()]
    with gzip.open(dest, "wb", compresslevel=5) as f:
        f.write(b"\n".join(lines) + b"\n")
    return {**m, "range_start": start, "range_len": take, "range_sha256": sha, "n_records": len(lines),
            "file": dest.name}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.environ.get("VITRINE_DATA", "data") + "/ember2024")
    ap.add_argument("--mb", type=float, default=8.0, help="compressed MiB fetched per weekly member")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--verify", action="store_true",
                    help="re-fetch every member and fail if a range hash differs from the committed manifest")
    ap.add_argument("--update-manifest", action="store_true", help="accept changed range hashes")
    ap.add_argument("--split", choices=["train", "test"], help="only this split")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    members = [m for name in ARCHIVES for m in central_directory(name)]
    print(f"{len(members)} weekly members; fetching {a.mb} MiB of each", flush=True)
    nbytes = int(a.mb * (1 << 20))
    if a.verify and not MANIFEST.exists():
        raise SystemExit(f"--verify: no manifest at {MANIFEST}")
    prev = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"members": []}
    if prev["members"] and prev.get("mib_per_member") != a.mb:
        raise SystemExit(f"manifest was written with --mb {prev.get('mib_per_member')}; pass the same value")
    known = {r["member"]: r for r in prev["members"]}
    todo = [m for m in members if m["member"] not in known or not (out / known[m["member"]]["file"]).exists()
            or a.verify]
    if a.split:
        todo = [m for m in todo if m["member"].endswith(f"_{a.split}.jsonl")]
    print(f"{len(todo)} to fetch ({len(known)} already in manifest)", flush=True)

    def save() -> None:
        MANIFEST.parent.mkdir(exist_ok=True)
        MANIFEST.write_text(json.dumps({
            "dataset": "EMBER2024 (joyce8/EMBER2024)", "revision": REVISION,
            "archives": {k: {"size": v[0], "sha256": v[1]} for k, v in ARCHIVES.items()},
            "mib_per_member": a.mb,
            "note": "weekly JSONL members are sha256-sorted, so each prefix is a sha256-range sample",
            "members": sorted(known.values(), key=lambda r: r["member"]),
            "provenance": provenance()}, indent=1))

    with cf.ThreadPoolExecutor(a.workers) as ex:
        for r in ex.map(lambda m: fetch_member_prefix(m, nbytes, out), todo):
            old = known.get(r["member"])
            if old and old["range_sha256"] != r["range_sha256"]:
                if a.verify or not a.update_manifest:
                    raise SystemExit(f"SHA-256 mismatch for {r['member']} (use --update-manifest to accept)")
            print(f"  {r['member']}: {r['n_records']} records sha256={r['range_sha256'][:16]}", flush=True)
            known[r["member"]] = r
            save()  # after every member, so a partial run keeps its hashes
    save()
    print(f"done: {sum(r['n_records'] for r in known.values())} records in {len(known)} members -> {out}")


if __name__ == "__main__":
    main()
