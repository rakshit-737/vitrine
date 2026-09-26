import bz2
import random
import sys
from multiprocessing.pool import ThreadPool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from _pbz2 import block_ranges, decompress_block, iter_decompressed  # noqa: E402


def test_parallel_block_decompression_roundtrip(tmp_path):
    rng = random.Random(0)
    words = [bytes(rng.choices(b"abcdefghijklmnop{}:,\" 0123456789", k=rng.randint(3, 12))) for _ in range(500)]
    data = b"\n".join(b" ".join(rng.choices(words, k=20)) for _ in range(20000))
    p = tmp_path / "x.bz2"
    p.write_bytes(bz2.compress(data, compresslevel=1))  # 100 kB blocks -> many blocks
    header, ranges = block_ranges(p)
    assert header == b"BZh1" and len(ranges) > 5
    assert decompress_block((str(p), header, *ranges[0])) == data[: len(decompress_block((str(p), header, *ranges[0])))]
    with ThreadPool(4) as pool:
        assert b"".join(iter_decompressed(p, pool, window=3)) == data
    assert (tmp_path / "x.bz2.blocks.json").exists()  # scan cached
