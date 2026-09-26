import json

import pytest

from vitrine.capabilities import tag
from vitrine.cli import main
from vitrine.dissect import PEParseError, dissect, entropy, is_packed
from vitrine.features import FEATURE_NAMES, featurize
from vitrine.model import VerdictModel, evaluate
from vitrine.models import Verdict
from vitrine.synth import MALICIOUS_FAMILIES, append_benign_section, build_pe, corpus, make_sample, CODE
from vitrine.triage import analyze, train_default
from vitrine.yara_synth import match, parse, synthesize, validate
from vitrine.features import vector


@pytest.fixture(scope="module")
def model():
    return train_default(n_per_family=10)


@pytest.fixture(scope="module")
def benign():
    return [make_sample("benign", 5000 + i) for i in range(30)]


# ---------------- dissector
def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"A" * 100) == 0.0
    assert abs(entropy(bytes(range(256))) - 8.0) < 1e-9


def test_dissect_roundtrip_imports_and_sections():
    pe = build_pe([(".text", b"\x90" * 100, CODE)], {"KERNEL32.dll": ["ExitProcess", "Sleep"], "USER32.dll": ["MessageBoxA"]})
    rep = dissect(pe)
    assert rep.machine == 0x14C
    assert [s.name for s in rep.sections] == [".text", ".idata"]
    assert rep.imports == {"KERNEL32.dll": ["ExitProcess", "Sleep"], "USER32.dll": ["MessageBoxA"]}
    assert len(rep.imphash) == 32
    assert rep.sections[0].executable and not rep.sections[0].writable


def test_imphash_stable_across_seeds():
    a, b = dissect(make_sample("injector", 1)), dissect(make_sample("injector", 2))
    assert a.imphash == b.imphash and a.sha256 != b.sha256


@pytest.mark.parametrize("blob", [b"", b"NOTPE" * 20, b"MZ" + b"\0" * 10, b"MZ" + b"\0" * 58 + b"\xff\xff\xff\x00"])
def test_malformed_inputs_raise_cleanly(blob):
    with pytest.raises(PEParseError):
        dissect(blob)


def test_truncated_pe_does_not_crash():
    pe = make_sample("downloader", 3)
    for cut in (0x100, 0x3F0, 0x500, len(pe) // 2):
        try:
            dissect(pe[:cut])
        except PEParseError:
            pass


def test_packing_detection():
    assert is_packed(dissect(make_sample("packed", 1)))
    assert not is_packed(dissect(make_sample("benign", 1)))
    assert not is_packed(dissect(make_sample("injector", 1)))


# ---------------- capabilities / features
def test_capabilities():
    ids = lambda fam: {c.attack_id for c in tag(dissect(make_sample(fam, 0)))}
    assert "T1055.002" in ids("injector")
    assert {"T1105", "T1071.001"} <= ids("downloader")
    assert "T1056.001" in ids("keylogger")
    assert ids("benign") == set()


def test_feature_schema():
    f = featurize(dissect(make_sample("benign", 0)))
    assert list(f) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in f.values())


# ---------------- model
def test_model_heldout_quality(model):
    test = corpus(8, seed=3)
    m = evaluate(model, [vector(dissect(b)) for _, b in test], [int(f in MALICIOUS_FAMILIES) for f, _ in test])
    assert m["f1"] >= 0.95 and m["fpr"] <= 0.05


def test_attribution_is_exact_linear_shap(model):
    x = vector(dissect(make_sample("keylogger", 11)))
    full = model.attribute(x, top=len(FEATURE_NAMES))
    z = sum(a.contribution for a in full)
    base = sum(w * (0 - 0) for w in model.weights) + model.bias  # mean input => z-scores 0
    import math
    assert abs(1 / (1 + math.exp(-(base + z))) - model.score(x)) < 1e-3


def test_family_assignment(model):
    for fam in MALICIOUS_FAMILIES:
        assert model.family(vector(dissect(make_sample(fam, 999))))[0] == fam


def test_model_save_load(tmp_path, model):
    p = tmp_path / "m.json"
    model.save(p)
    m2 = VerdictModel.load(p)
    x = vector(dissect(make_sample("injector", 5)))
    assert m2.score(x) == pytest.approx(model.score(x))


# ---------------- YARA
def test_yara_synthesis_specificity_and_coverage(benign):
    for fam in MALICIOUS_FAMILIES:
        group = [make_sample(fam, 100 + i) for i in range(5)]
        sibs = [make_sample(fam, 300 + i) for i in range(15)]
        rule = synthesize(f"t_{fam}", group, benign, fam)
        assert rule is not None
        validate(rule, benign, sibs)
        assert rule.specificity == 1.0, fam
        assert rule.coverage >= 0.9, fam
        others = [make_sample(o, 7) for o in MALICIOUS_FAMILIES if o != fam]
        assert not any(match(rule, o) for o in others), fam


def test_yara_text_roundtrip_and_escaping(benign):
    rule = synthesize("x", [make_sample("injector", 1)], benign, "injector")
    strs, thr = parse(rule.text)
    assert strs == rule.strings and thr == rule.threshold
    assert "Global\\inj_mtx_31" in strs  # backslash escaped in text, unescaped on parse
    assert 'Global\\\\inj_mtx_31' in rule.text


def test_yara_requires_mz(benign):
    rule = synthesize("x", [make_sample("injector", 1)], benign)
    assert not match(rule, b"XX" + make_sample("injector", 1)[2:])


# ---------------- pipeline
def test_triage_injector(model, benign):
    r = analyze(make_sample("injector", 4242), model, benign)
    assert r.verdict == Verdict.MALICIOUS and r.family == "injector"
    assert r.attributions and r.yara and r.yara.specificity == 1.0
    json.dumps(r.to_dict())


def test_triage_benign(model, benign):
    r = analyze(make_sample("benign", 77777), model, benign)
    assert r.verdict == Verdict.BENIGN and r.yara is None and not r.route_to_dynamic


def test_packed_routes_to_dynamic(model):
    r = analyze(make_sample("packed", 5), model)
    assert r.packed and r.route_to_dynamic


def test_adversarial_capability_floor(model):
    adv = append_benign_section(make_sample("injector", 77), seed=1)
    assert dissect(adv).imports  # still valid PE
    r = analyze(adv, model)
    assert "T1055.002" in {c.attack_id for c in r.capabilities}
    assert r.verdict != Verdict.BENIGN


def test_cli(tmp_path, capsys):
    main(["gen-corpus", str(tmp_path / "c"), "-n", "2"])
    f = next((tmp_path / "c" / "downloader").iterdir())
    main(["analyze", str(f), "--json", "--benign-dir", str(tmp_path / "c" / "benign")])
    out = capsys.readouterr().out
    d = json.loads(out[out.index("{"):])
    assert d["verdict"] in {"MALICIOUS", "SUSPICIOUS"}
