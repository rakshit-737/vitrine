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
    monkeypatch.setattr(build_demo, "OUT", out)
    build_demo.main()
    html = out.read_text(encoding="utf-8")
    assert "const DEMO =" in html and 'id="pick"' in html
    assert 'id="drop"' not in html
    assert "synthetic_benign.exe" in html
