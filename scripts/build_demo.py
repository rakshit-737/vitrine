#!/usr/bin/env python
"""Build the static, server-less demo of the triage UI for the docs site (``docs/demo/index.html``).

The real UI POSTs files to the FastAPI service. GitHub Pages has no backend, so this script runs
the same ``analyze()`` pipeline offline and embeds the JSON results in a copy of
``vitrine/static/index.html`` with a sample picker instead of the upload box:

* synthetic, inert PE samples (``vitrine.synth``) scored by the linear demo model (linear SHAP);
* optionally (``--model``), a few real Windows System32 binaries scored by the EMBER-trained
  XGBoost model (TreeSHAP). Only the analysis JSON is embedded, never the binaries.

Nothing is uploaded or executed in the browser.

    python scripts/build_demo.py [--model <data>/models/vitrine_xgb.json] [--out docs/demo/index.html]
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import _common  # noqa: F401  (puts the repo on sys.path)

from vitrine.synth import MALICIOUS_FAMILIES, make_sample
from vitrine.triage import analyze, load_model, train_default

REPO = Path(__file__).resolve().parents[1]
REAL = ["notepad.exe", "cmd.exe", "kernel32.dll"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(REPO / "docs" / "demo" / "index.html"), help="output HTML file")
    ap.add_argument("--model", help="EMBER-trained vitrine_xgb.json; adds real System32 examples")
    ap.add_argument("--system32", default="C:/Windows/System32", help="where the real examples are read from")
    a = ap.parse_args()
    out = Path(a.out)
    m = train_default()
    benign = [make_sample("benign", 5000 + i) for i in range(40)]
    samples = {}
    for fam in ["benign", *MALICIOUS_FAMILIES]:
        sibs = [make_sample(fam, 9000 + i) for i in range(10)]
        d = analyze(make_sample(fam, 1234), m, benign, sibs).to_dict()
        samples[f"synthetic_{fam}.exe (demo model)"] = d
    if a.model:
        xm = load_model(a.model)
        for name in REAL:
            p = Path(a.system32) / name
            if p.exists():
                samples[f"{name} (Windows System32, EMBER-trained XGBoost)"] = analyze(p.read_bytes(), xm).to_dict()
    html = (REPO / "vitrine" / "static" / "index.html").read_text(encoding="utf-8")
    picker = ('<p><a href="../">&larr; VITRINE docs</a></p>\n'
              '    <label for="pick">Static demo (no backend): pick a precomputed example</label> '
              '<select id="pick"></select>\n'
              '    <p class="muted">Precomputed with <code>scripts/build_demo.py</code>. Synthetic samples are inert '
              'and scored by the linear demo model; System32 entries are real benign Windows files scored by the '
              'EMBER-trained XGBoost model. Run <code>vitrine serve</code> locally to analyze your own files.</p>')
    start = html.index('<div id="drop"')
    end = html.index("</div>", start) + len("</div>")
    html = html[:start] + picker + html[end:]
    data = json.dumps(samples, default=str)
    html = html.replace("<script>\n", f"<script>\nconst DEMO = {data};\n</script>\n<script>\n", 1)
    # drop the upload handlers, run() and the API validation (no backend on Pages)
    html = html[: html.index("const drop = $(")] + html[html.index("function render"):]
    html = re.sub(r'\$\("validate"\)\.onclick = async \(\) => \{.*?\n\};\n', "", html, flags=re.S)
    html = html.replace('<button id="validate">Validate against benign corpus</button> ', "")
    boot = """
const pick = $("pick");
pick.innerHTML = Object.keys(DEMO).map((k) => `<option>${esc(k)}</option>`).join("");
pick.onchange = () => { $("status").textContent = pick.value; render(DEMO[pick.value]); };
pick.onchange();
"""
    html = html.replace("</script>\n</body>", boot + "</script>\n</body>", 1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, {len(samples)} samples)")


if __name__ == "__main__":
    main()
