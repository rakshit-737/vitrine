"""Parallel bzip2 decompression by block splitting (stdlib + mmap only).

A .bz2 stream is a sequence of independently-compressed blocks, each introduced by the
bit-aligned 48-bit magic 0x314159265359 and followed by its 32-bit CRC. We locate every block
magic (C-speed ``bytes.find`` on the 5 byte-aligned bytes of each of the 8 bit-shifts, then a
48-bit check), re-wrap each block as a standalone one-block stream (header + block bits +
end-of-stream magic + combined CRC, which for one block equals the block CRC) and decompress
blocks in a process pool. Output order is preserved. On a contended laptop this turned a
~55-minute single-threaded decompression of the EMBER archive into minutes.
"""
from __future__ import annotations

import bz2
import mmap
from pathlib import Path

BLOCK_MAGIC = 0x314159265359
EOS_MAGIC = 0x177245385090
MASK48 = (1 << 48) - 1


def _keys(magic: int) -> list[tuple[int, bytes, int]]:
    """(shift s, 5 aligned bytes, offset of those bytes relative to byte k) for s in 0..7."""
    out = []
    for s in range(8):
        v = (magic << (8 - s)) if s else (magic << 8)
        b = v.to_bytes(7, "big")
        out.append((s, b[1:6], 1) if s else (0, b[0:5], 0))
    return out


def _read_bits(mm, bit: int, nbits: int) -> int:
    start = bit // 8
    end = (bit + nbits + 7) // 8
    v = int.from_bytes(mm[start:end], "big")
    total = (end - start) * 8
    return (v >> (total - (bit - start * 8) - nbits)) & ((1 << nbits) - 1)


def find_magics(path: str | Path, magic: int) -> list[int]:
    """Bit offsets of every occurrence of a 48-bit magic."""
    hits = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        n = len(mm)
        for s, key, rel in _keys(magic):
            i = mm.find(key)
            while i != -1:
                k = i - rel
                bit = 8 * k + s
                if k >= 0 and bit + 48 <= 8 * n and _read_bits(mm, bit, 48) == magic:
                    hits.append(bit)
                i = mm.find(key, i + 1)
    return sorted(set(hits))


def block_ranges(path: str | Path) -> tuple[bytes, list[tuple[int, int]]]:
    """Header ('BZh9') and (start_bit, end_bit) of every block (end = next magic).

    The scan is cached next to the archive as ``<name>.blocks.json`` (keyed by file size)."""
    import json

    path = Path(path)
    cache = path.with_name(path.name + ".blocks.json")
    size = path.stat().st_size
    if cache.exists():
        c = json.loads(cache.read_text())
        if c.get("size") == size:
            return c["header"].encode(), [tuple(x) for x in c["ranges"]]
    blocks = find_magics(path, BLOCK_MAGIC)
    eos = find_magics(path, EOS_MAGIC)
    with open(path, "rb") as f:
        header = f.read(4)
    if not header.startswith(b"BZh") or not blocks or not eos:
        raise ValueError("not a single-stream bzip2 file")
    ends = blocks[1:] + [eos[-1]]
    ranges = list(zip(blocks, ends))
    cache.write_text(json.dumps({"size": size, "header": header.decode(), "ranges": ranges}))
    return header, ranges


def decompress_block(args: tuple[str, bytes, int, int]) -> bytes:
    path, header, start, end = args
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        nbits = end - start
        body = _read_bits(mm, start, nbits)
        crc = _read_bits(mm, start + 48, 32)
    stream_bits = (body << 80) | (EOS_MAGIC << 32) | crc
    total = nbits + 80
    pad = (-total) % 8
    data = (stream_bits << pad).to_bytes((total + pad) // 8, "big")
    return bz2.decompress(header + data)


def iter_decompressed(path: str | Path, pool, window: int = 32):
    """Yield decompressed chunks in order, decompressing blocks in ``pool`` (bounded window)."""
    from collections import deque

    header, ranges = block_ranges(path)
    pending: deque = deque()
    it = iter(ranges)
    for start, end in it:
        pending.append(pool.apply_async(decompress_block, ((str(path), header, start, end),)))
        if len(pending) >= window:
            yield pending.popleft().get()
    while pending:
        yield pending.popleft().get()
