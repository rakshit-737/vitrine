"""EMBER-schema layer, GBDT model, structural YARA, API. Uses 40 real EMBER 2018 records
(features only, no binaries) committed as a fixture; real-data tests are skipped when absent."""
import gzip
import json
import os
import sys
from pathlib import Path

import numpy as np
import pytest

from vitrine.ember import VECTOR_DIM, block_slices, raw_features, vectorize, vectorize_many
from vitrine.features import FEATURE_NAMES, featurize_raw, vector_raw
from vitrine.synth import MALICIOUS_FAMILIES, make_sample
from vitrine.yara_synth import StructuralRule, imphash_from_imports, structural_atoms, synthesize_structural

FIX = Path(__file__).parent / "fixtures" / "ember2018_sample.jsonl.gz"
DATA = Path(os.environ.get("VITRINE_DATA", Path(__file__).parents[1] / "data"))
SYSTEM32 = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"


@pytest.fixture(scope="module")
def records():
    with gzip.open(FIX, "rt") as f:
        return [json.loads(ln) for ln in f]


def test_fixture_is_features_only(records):
    assert len(records) == 40 and {r["label"] for r in records} == {0, 1}
    assert all(set(r) >= {"histogram", "byteentropy", "imports", "section"} for r in records)


def test_vectorize_shape_and_blocks(records):
    X = vectorize_many(records)
    assert X.shape == (40, VECTOR_DIM) and X.dtype == np.float32
    sl = block_slices()
    np.testing.assert_allclose(X[:, sl["histogram"]].sum(axis=1), 1.0, rtol=1e-5)
    np.testing.assert_allclose(X[:, sl["byteentropy"]].sum(axis=1), 1.0, rtol=1e-5)
    assert np.all(X[:, sl["general"]][:, 0] == [r["general"]["size"] for r in records])
    # batch == single-sample path
    np.testing.assert_allclose(vectorize(records[3]), X[3], rtol=1e-6)


def test_raw_features_schema_matches_ember(records):
    pe = make_sample("downloader", 1)
    raw = raw_features(pe)
    ref = records[0]
    assert set(raw) >= set(ref) - {"md5", "appeared", "label", "avclass"}
    for k in ("general", "strings"):
        assert set(raw[k]) == set(ref[k])
    assert set(raw["header"]["optional"]) == set(ref["header"]["optional"])
    assert [d["name"] for d in raw["datadirectories"]] == [d["name"] for d in ref["datadirectories"]]
    assert sum(raw["histogram"]) == len(pe)
    assert vectorize(raw).shape == (VECTOR_DIM,)


def test_interpretable_features_on_real_records(records):
    F = np.asarray([vector_raw(r) for r in records])
    assert F.shape == (40, len(FEATURE_NAMES)) and np.isfinite(F).all()
    f = featurize_raw(records[0])
    assert 0 <= f["file_entropy"] <= 8 and f["n_sections"] == len(records[0]["section"]["sections"])


def test_gbdt_treeshap_additivity_and_roundtrip(records, tmp_path):
    pytest.importorskip("xgboost")
    from vitrine.gbdt import GBDTVerdictModel

    F = np.asarray([vector_raw(r) for r in records], dtype=np.float32)
    y = np.asarray([r["label"] for r in records])
    m = GBDTVerdictModel.fit(F, y, families=[r.get("avclass") or "" for r in records], num_rounds=20)
    C = m.contributions(F)
    margin = m.booster.predict(m._dm(F), output_margin=True)
    np.testing.assert_allclose(C.sum(axis=1), margin, atol=1e-4)
    attr = m.attribute(F[0], top=5)
    assert 0 < len(attr) <= 5 and all(a.feature in FEATURE_NAMES for a in attr)
    m.thresholds = {"fpr_1pct": 0.5, "fpr_0.1pct": 0.9}
    m.save(tmp_path / "g.json")
    m2 = GBDTVerdictModel.load(tmp_path / "g.json")
    np.testing.assert_allclose(m2.score_many(F), m.score_many(F), atol=1e-6)
    assert m2.thresholds["fpr_1pct"] == 0.5


def test_triage_with_gbdt(records, tmp_path):
    pytest.importorskip("xgboost")
    from vitrine.gbdt import GBDTVerdictModel
    from vitrine.triage import analyze, load_model

    F = np.asarray([vector_raw(r) for r in records], dtype=np.float32)
    y = np.asarray([r["label"] for r in records])
    GBDTVerdictModel.fit(F, y, num_rounds=10).save(tmp_path / "g.json")
    m = load_model(str(tmp_path / "g.json"))
    r = analyze(make_sample("injector", 3), m)
    assert r.attributions and r.verdict.value in {"BENIGN", "SUSPICIOUS", "MALICIOUS"}
    assert r.verdict.value != "BENIGN"  # capability floor at minimum


def test_structural_atoms_and_imphash(records):
    at = structural_atoms(records[0])
    assert any(a[0] == "imp" for a in at)
    ih = [a for a in at if a[0] == "imphash"]
    assert ih and ih[0][1] == imphash_from_imports(records[0]["imports"])


def test_structural_rule_synthesis_synthetic():
    benign = [structural_atoms(raw_features(make_sample("benign", 7000 + i))) for i in range(30)]
    for fam in MALICIOUS_FAMILIES:
        group = [structural_atoms(raw_features(make_sample(fam, 10 + i))) for i in range(5)]
        rule = synthesize_structural(f"s_{fam}", group, benign, fam)
        assert rule is not None, fam
        sib = [structural_atoms(raw_features(make_sample(fam, 500 + i))) for i in range(10)]
        assert all(rule.matches_atoms(s) for s in sib)
        assert not any(rule.matches_atoms(b) for b in benign)
        assert f"{rule.threshold} of (" in rule.text and 'import "pe"' in rule.text


def test_structural_rule_text_escapes():
    r = StructuralRule("x", [("sec", 'we"ird'), ("imp", "k.dll", "F")], 1)
    assert 'we\\"ird' in r.text


def test_api_roundtrip():
    """In-process API test over httpx's ASGI transport (no Starlette TestClient, which is deprecated)."""
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    import asyncio

    from vitrine.api import create_app

    async def run():
        app = create_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
            assert (await c.get("/health")).json()["status"] == "ok"
            octet = {"Content-Type": "application/octet-stream"}
            r = await c.post("/api/analyze", content=make_sample("keylogger", 4), headers=octet)
            assert r.status_code == 200 and r.json()["verdict"] in {"MALICIOUS", "SUSPICIOUS"}
            assert (await c.post("/api/analyze", content=b"not a pe", headers=octet)).status_code == 422
            assert (await c.post("/api/analyze", content=b"MZ")).status_code == 415  # no octet-stream type
            big = {**octet, "Content-Length": str(64 * 1024 * 1024)}
            assert (await c.post("/api/analyze", content=b"MZ", headers=big)).status_code == 413
            assert (await c.post("/api/yara/validate", json={"text": "x" * 70000})).status_code == 422
            assert (await c.get("/docs")).status_code == 404
            assert (await c.get("/openapi.json")).status_code == 200
            assert (await c.get("/health", headers={"Host": "evil.example"})).status_code == 400
            assert "VITRINE" in (await c.get("/")).text
            rule = 'rule a {\n strings:\n  $a = "zzz"\n condition:\n  1 of them\n}'
            v = await c.post("/api/yara/validate", json={"text": rule})
            assert v.status_code == 200 and v.json()["strings"] == 1
            # concurrent uploads are served (bounded by the analysis slots), none dropped
            rs = await asyncio.gather(*[c.post("/api/analyze", content=make_sample("benign", i), headers=octet)
                                        for i in range(5)])
            assert all(x.status_code == 200 for x in rs)

    asyncio.run(run())


# ---------------- real data (skipped when absent)
@pytest.mark.realdata
@pytest.mark.skipif(not SYSTEM32.exists(), reason="needs a Windows System32 directory")
def test_dissector_agrees_with_pefile_on_system32():
    pefile = pytest.importorskip("pefile")
    from vitrine.dissect import dissect

    files = sorted(SYSTEM32.glob("*.dll"))[:60]
    for f in files:
        data = f.read_bytes()
        rep = dissect(data)
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[0, 1])
        ref = {}
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            ref.setdefault(e.dll.decode(), []).extend(
                f"ordinal{i.ordinal}" if i.import_by_ordinal else i.name.decode() for i in e.imports)
        assert rep.imports == ref, f
        ex = [s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name] \
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
        assert rep.exports == ex, f


@pytest.mark.realdata
@pytest.mark.skipif(not (DATA / "models" / "vitrine_xgb.json").exists(), reason="needs trained EMBER model")
def test_trained_model_quality_on_processed_test():
    sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
    from sklearn.metrics import roc_auc_score

    from vitrine.gbdt import GBDTVerdictModel

    m = GBDTVerdictModel.load(DATA / "models" / "vitrine_xgb.json")
    F = np.load(DATA / "processed" / "test_F.npy")
    import csv

    with open(DATA / "processed" / "test_meta.csv", newline="") as f:
        y = np.asarray([int(r["label"]) for r in csv.DictReader(f)])
    idx = np.random.default_rng(0).choice(len(y), 20000, replace=False)
    assert roc_auc_score(y[idx], m.score_many(F[idx])) > 0.97
