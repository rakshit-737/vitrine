"""Tests for the benchmark-statistics helper and the static demo builder (no real data needed)."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
pytest.importorskip("sklearn")


def test_bootstrap_ci_brackets_point_and_paired_diff():
    from bench_ci import bootstrap

    rng = np.random.default_rng(0)
    y = np.r_[np.ones(2000), np.zeros(2000)].astype(int)
    good = y + rng.normal(0, 0.6, y.size)
    bad = y + rng.normal(0, 1.5, y.size)
    r = bootstrap(y, {"vitrine_xgb": good, "other": bad}, B=40)
    for name in ("vitrine_xgb", "other"):
        m = r["per_model"][name]
        assert m["roc_auc"]["lo"] <= m["point"]["roc_auc"] <= m["roc_auc"]["hi"]
    d = r["paired_diff_vitrine_xgb_minus"]["other"]["roc_auc"]
    assert d["lo"] > 0  # the clearly better scorer wins on every resample


def test_static_demo_has_no_backend_calls(tmp_path, monkeypatch):
    import build_demo

    out = tmp_path / "demo.html"
    monkeypatch.setattr(sys, "argv", ["build_demo.py", "--out", str(out)])
    build_demo.main()
    html = out.read_text(encoding="utf-8")
    assert "const DEMO =" in html and 'id="pick"' in html
    assert 'id="drop"' not in html
    assert "synthetic_benign.exe" in html
    assert "fetch(" not in html and 'id="validate"' not in html and "VITRINE docs" in html


def test_stats_helpers():
    from _stats import bootstrap_roc, mcnemar_p, psi, rule_of_three, wilson

    lo, hi = wilson(0, 2999)
    assert lo == 0.0 and 0 < hi < 2 * rule_of_three(2999)
    assert wilson(7, 7)[1] == 1.0
    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi
    a = np.array([1, 1, 1, 0] * 50, bool)
    assert mcnemar_p(a, a) == 1.0 and mcnemar_p(a, ~a) < 1e-6
    rng = np.random.default_rng(0)
    x = rng.normal(size=5000)
    assert psi(x, x) < 1e-3 < psi(x, x + 1)
    assert psi(np.r_[np.zeros(900), np.ones(100)], np.r_[np.zeros(500), np.ones(500)]) > 0.2  # binary shift
    y = np.r_[np.ones(500), np.zeros(500)].astype(int)
    r = bootstrap_roc(y, [y + rng.normal(0, 0.5, y.size), y + rng.normal(0, 0.5, y.size)], b=30)
    assert r["roc_auc"]["lo"] <= r["roc_auc"]["point"] <= r["roc_auc"]["hi"]


def test_psi_sees_shift_behind_a_point_mass():
    """A feature that is 0 in >= 90 % of the reference used to collapse into one decile bin (PSI 0)."""
    from _stats import psi, psi_legacy, total_variation

    rng = np.random.default_rng(1)
    a = np.r_[np.zeros(9000), rng.exponential(1, 1000)]
    b = np.r_[np.zeros(9000), rng.exponential(5, 1000)]  # same zero share, very different non-zero part
    assert psi_legacy(a, b) == 0.0
    assert psi(a, b) > 0.1 and psi(a, b, pooled=True) > 0.1
    assert psi(a, a) == 0.0
    assert total_variation(np.ones(10), np.ones(10)) == 0.0
    assert total_variation(np.zeros(10), np.ones(10)) == 1.0


def test_threshold_and_two_sample_bootstraps():
    from _stats import bootstrap_threshold, independent_bootstrap_diff, paired_bootstrap_diff

    rng = np.random.default_rng(2)
    y = np.r_[np.ones(800), np.zeros(800)].astype(int)
    s1 = [y + rng.normal(0, 0.7, y.size) for _ in range(2)]
    r = bootstrap_threshold(y, s1, [0.5, 0.5], b=60)
    assert r["recall"]["lo"] <= r["recall"]["point"] <= r["recall"]["hi"]
    assert r["fpr"]["lo"] <= r["fpr"]["point"] <= r["fpr"]["hi"] and len(r["per_seed"]) == 2
    s2 = [y + rng.normal(0, 1.4, y.size) for _ in range(2)]
    d = independent_bootstrap_diff(y, s1, y, s2, b=60, ta=[0.5, 0.5], tb=[0.5, 0.5])
    assert d["roc_auc"]["lo"] > 0 and "recall_at_source_threshold" in d
    p = paired_bootstrap_diff(y, s1, s2, b=30)
    assert p["roc_auc"]["point"] > 0 and p["roc_auc"]["lo"] > 0


def test_dump_writes_strict_json_with_provenance(tmp_path, monkeypatch):
    import json

    import _common

    monkeypatch.setattr(_common, "RESULTS", tmp_path)
    out = _common.dump("x.json", {"a": float("nan"), "b": np.float32(0.5), "c": np.arange(2)})
    doc = json.loads(out.read_text(), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    assert doc["a"] is None and doc["b"] == 0.5 and doc["c"] == [0, 1]
    assert {"git_commit", "command", "started_utc", "runner"} <= set(doc["provenance"])


def test_committed_demo_has_no_namespace_or_pki_url_hits():
    """The published demo must not show the manifest-namespace / certificate URL false hits the tagger now filters."""
    import json
    import re

    page = Path(__file__).resolve().parents[1] / "docs" / "demo" / "index.html"
    if not page.exists():
        pytest.skip("docs/demo is not shipped in the sdist")
    html = page.read_text(encoding="utf-8")
    demo = json.loads(re.search(r"const DEMO = (\{.*?\});\n</script>", html, re.S).group(1))
    assert demo
    for name, rep in demo.items():
        for c in rep["capabilities"]:
            if c["attack_id"] == "T1071.001":
                ev = " ".join(c["evidence"])
                assert "xmlns" not in ev and "schemas.microsoft.com" not in ev and "/pki" not in ev, name
