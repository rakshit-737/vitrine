#!/usr/bin/env python
"""Build the static, server-less demo of the triage UI for the docs site (``docs/demo/index.html``).

The real UI POSTs files to the FastAPI service. GitHub Pages has no backend, so this script runs
the same ``analyze()`` pipeline offline on *synthetic, inert* PE samples (see ``vitrine.synth``)
with the demo model, embeds the JSON results in a copy of ``vitrine/static/index.html`` and
replaces the upload box with a sample picker. Nothing is uploaded or executed in the browser.

    python scripts/build_demo.py
"""
from __future__ import annotations

import json
from pathlib import Path

import _common  # noqa: F401  (puts the repo on sys.path)

from vitrine.synth import MALICIOUS_FAMILIES, make_sample
from vitrine.triage import analyze, train_default

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "demo" / "index.html"


def main() -> None:
    m = train_default()
    benign = [make_sample("benign", 5000 + i) for i in range(40)]
    samples = {}
    for fam in ["benign", *MALICIOUS_FAMILIES]:
        sibs = [make_sample(fam, 9000 + i) for i in range(10)]
        d = analyze(make_sample(fam, 1234), m, benign, sibs).to_dict()
        samples[f"synthetic_{fam}.exe"] = d
    html = (REPO / "vitrine" / "static" / "index.html").read_text(encoding="utf-8")
    picker = ('<label for="pick">Static demo (no backend): pick a synthetic, inert sample</label> '
              '<select id="pick"></select>\n'
              '    <p class="muted">Precomputed with <code>scripts/build_demo.py</code> using the synthetic demo '
              'model. Run <code>vitrine serve</code> locally to analyze your own files.</p>')
    start = html.index('<div id="drop"')
    end = html.index("</div>", start) + len("</div>")
    html = html[:start] + picker + html[end:]
    shim = f"""<script>
const DEMO = {json.dumps(samples, default=str)};
</script>
<script>
"""
    html = html.replace("<script>\n", shim, 1)
    js_start = html.index("const drop = $(")
    js_end = html.index("async function run")
    html = html[:js_start] + html[js_end:]
    boot = """
const pick = $("pick");
pick.innerHTML = Object.keys(DEMO).map((k) => `<option>${esc(k)}</option>`).join("");
pick.onchange = () => { $("status").textContent = pick.value; render(DEMO[pick.value]); };
pick.onchange();
"""
    html = html.replace("async function run", boot + "async function run", 1)
    html = html.replace('$("validate").onclick = async () => {',
                        '$("validate").onclick = async () => { $("vres").textContent = '
                        '"validation needs the local API (vitrine serve --benign-dir ...)"; return;', 1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(samples)} samples)")


if __name__ == "__main__":
    main()
