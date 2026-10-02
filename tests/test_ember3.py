"""EMBER2024 (feature version 3) -> v2 adapter on a 24-record fixture.

Fixture: 12 malicious + 12 benign records from the EMBER2024 Win32 train week 2023-10-01
(joyce8/EMBER2024, Apache-2.0); features only, no binaries.
"""
import gzip
import json
from pathlib import Path

import numpy as np

from vitrine.ember import VECTOR_DIM as DIM
from vitrine.ember import vectorize_many
from vitrine.ember3 import to_v2
from vitrine.features import FEATURE_NAMES, vector_raw

FIX = Path(__file__).parent / "fixtures" / "ember2024_sample.jsonl.gz"


def _recs():
    return [json.loads(ln) for ln in gzip.open(FIX).read().splitlines() if ln.strip()]


def test_to_v2_vectorizes():
    recs = _recs()
    assert len(recs) == 24 and {r["label"] for r in recs} == {0, 1}
    v2 = [to_v2(r) for r in recs]
    X = vectorize_many(v2)
    assert X.shape == (24, DIM) == (24, 2381)
    assert np.isfinite(X).all()
    F = np.asarray([vector_raw(r) for r in v2], dtype=np.float32)
    assert F.shape == (24, len(FEATURE_NAMES)) and np.isfinite(F).all()


def test_to_v2_schema_details():
    r = _recs()[0]
    before = json.dumps(r, sort_keys=True)
    v = to_v2(r)
    assert json.dumps(r, sort_keys=True) == before  # input untouched
    assert not v["header"]["coff"]["machine"].startswith("IMAGE_FILE_MACHINE_")
    assert v["header"]["optional"]["magic"] in ("PE32", "PE32_PLUS")
    assert v["general"]["vsize"] == r["header"]["optional"].get("sizeof_image", 0)
    assert all(":ordinal" not in f for fns in v["imports"].values() for f in fns)
