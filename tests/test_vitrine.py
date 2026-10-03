import json
import math

import pytest

from vitrine.capabilities import norm_api, tag
from vitrine.cli import main
from vitrine.dissect import PEParseError, dissect, entropy, is_packed
from vitrine.features import FEATURE_NAMES, featurize
from vitrine.model import VerdictModel, evaluate
from vitrine.models import Verdict
from vitrine.synth import CODE, MALICIOUS_FAMILIES, append_benign_section, build_pe, corpus, make_sample
from vitrine.triage import analyze, train_default, vector_bytes
from vitrine.yara_synth import match, parse, synthesize, validate


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
    pe = build_pe([(".text", b"\x90" * 100, CODE)],
                  {"KERNEL32.dll": ["ExitProcess", "Sleep"], "USER32.dll": ["MessageBoxA"]})
    rep = dissect(pe)
    assert rep.machine == 0x14C and not rep.pe32plus
    assert [s.name for s in rep.sections] == [".text", ".idata"]
    assert rep.imports == {"KERNEL32.dll": ["ExitProcess", "Sleep"], "USER32.dll": ["MessageBoxA"]}
    assert len(rep.imphash) == 32
    assert rep.sections[0].executable and not rep.sections[0].writable
    assert rep.entry_section == ".text"


def test_dissect_pe32plus_with_exports():
    pe = build_pe([(".text", b"\x90" * 64, CODE)], {"KERNEL32.dll": ["ExitProcess", "VirtualAlloc"]},
                  pe32plus=True, is_dll=True, exports=["Zeta", "Alpha"])
    rep = dissect(pe)
    assert rep.pe32plus and rep.machine == 0x8664 and rep.is_dll
    assert rep.imports == {"KERNEL32.dll": ["ExitProcess", "VirtualAlloc"]}  # 8-byte thunks
    assert rep.exports == ["Alpha", "Zeta"]
    assert rep.image_base == 0x140000000


def test_imphash_matches_pefile_convention():
    pe = build_pe([(".text", b"\x90" * 64, CODE)], {"KERNEL32.dll": ["ExitProcess"], "user32.dll": ["MessageBoxA"]})
    import hashlib

    assert dissect(pe).imphash == hashlib.md5(b"kernel32.exitprocess,user32.messageboxa").hexdigest()


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


def test_fuzz_bitflips_never_crash():
    import random

    rng = random.Random(0)
    base = bytearray(make_sample("injector", 9))
    for _ in range(300):
        b = bytearray(base)
        for _ in range(rng.randint(1, 12)):
            b[rng.randrange(0, 0x600)] = rng.randrange(256)
        try:
            dissect(bytes(b))
        except PEParseError:
            pass


def test_packing_detection():
    assert is_packed(dissect(make_sample("packed", 1)))
    assert not is_packed(dissect(make_sample("benign", 1)))
    assert not is_packed(dissect(make_sample("injector", 1)))


# ---------------- capabilities / features
def test_norm_api():
    assert norm_api("SetWindowsHookExA") == norm_api("SetWindowsHookExW") == "setwindowshookex"
    assert norm_api("ZwUnmapViewOfSection") == "ntunmapviewofsection"


def test_capabilities():
    ids = lambda fam: {c.attack_id for c in tag(dissect(make_sample(fam, 0)))}  # noqa: E731
    assert "T1055.002" in ids("injector")
    assert {"T1105", "T1071.001"} <= ids("downloader")
    assert "T1056.001" in ids("keylogger")
    assert ids("benign") == set()


def test_signature_and_manifest_urls_are_not_embedded_urls():
    """CRL/AIA URLs inside an Authenticode blob and manifest XML namespaces are not network indicators."""
    rdata = b"\0".join([b"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">",
                        b"<ws2 xmlns:ws2=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">", b"\0"])
    cert = b"0\x82\x05\x00" + b"\0".join([b"Fhttp://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl0a",
                                         b"Ehttp://crl.example.test/pki/crl/products/Root_2010-06-23.crl0Z",
                                         b"http://cps.example.test/repository/policy0"]) + b"\0" * 64
    text = (".text", b"\xc3" + b"\x90" * 63, CODE)
    pe = build_pe([text, (".rdata", rdata, 0x40000040)], certificate=cert)
    rep = dissect(pe)
    assert rep.data_directories[4][1] == len(cert) and rep.overlay_size == 0
    assert any("cps.example.test" in s for s in rep.signature_strings)
    assert "T1071.001" not in {c.attack_id for c in tag(rep)}
    # the same URL outside the certificate table still counts
    pe2 = build_pe([text, (".rdata", b"http://cps.example.test/repository/policy0\0", 0x40000040)])
    assert "T1071.001" in {c.attack_id for c in tag(dissect(pe2))}


def test_feature_schema():
    f = featurize(dissect(make_sample("benign", 0)))
    assert list(f) == FEATURE_NAMES
    assert all(isinstance(v, float) and math.isfinite(v) for v in f.values())


# ---------------- model
def test_model_heldout_quality(model):
    test = corpus(8, seed=3)
    m = evaluate(model, [vector_bytes(b) for _, b in test], [int(f in MALICIOUS_FAMILIES) for f, _ in test])
    assert m["f1"] >= 0.95 and m["fpr"] <= 0.05


def test_attribution_is_exact_linear_shap(model):
    x = vector_bytes(make_sample("keylogger", 11))
    full = model.attribute(x, top=len(FEATURE_NAMES))
    z = sum(a.contribution for a in full)
    assert abs(1 / (1 + math.exp(-(model.bias + z))) - model.score(x)) < 1e-3


def test_family_assignment(model):
    for fam in MALICIOUS_FAMILIES:
        assert model.family(vector_bytes(make_sample(fam, 999)))[0] == fam


def test_model_save_load(tmp_path, model):
    p = tmp_path / "m.json"
    model.save(p)
    m2 = VerdictModel.load(p)
    x = vector_bytes(make_sample("injector", 5))
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
    assert "Global\\\\inj_mtx_31" in rule.text


def test_yara_requires_mz(benign):
    rule = synthesize("x", [make_sample("injector", 1)], benign)
    assert not match(rule, b"XX" + make_sample("injector", 1)[2:])


# ---------------- pipeline
def test_triage_injector(model, benign):
    r = analyze(make_sample("injector", 4242), model, benign)
    assert r.verdict == Verdict.MALICIOUS and r.family == "injector"
    assert r.attributions and r.yara and r.yara.specificity == 1.0
    assert r.structural_rule and 'import "pe"' in r.structural_rule
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


def test_cli_scan(tmp_path, capsys):
    main(["gen-corpus", str(tmp_path / "c"), "-n", "1"])
    main(["scan", str(tmp_path / "c"), "--recursive"])
    lines = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.startswith("{")]
    assert len(lines) == 7 and all("verdict" in ln for ln in lines)
