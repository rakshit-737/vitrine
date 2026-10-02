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
    assert lo < 1e-12 and 0 < hi < 2 * rule_of_three(2999)
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
