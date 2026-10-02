#!/usr/bin/env python
"""Render the static demo (docs/demo/index.html) headless and save the README hero screenshot.

    pip install playwright && python -m playwright install chromium
    python scripts/screenshot_demo.py [--sample injector] [--out docs/figures/demo_triage.png]
"""
from __future__ import annotations

import argparse
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", default="injector", help="substring of the demo option to show")
    ap.add_argument("--out", default=str(REPO / "docs" / "figures" / "demo_triage.png"))
    ap.add_argument("--dark", action="store_true", help="dark colour scheme")
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=1,
                        color_scheme="dark" if a.dark else "light")
        pg.goto((REPO / "docs" / "demo" / "index.html").as_uri())
        opt = next(o for o in pg.locator("#pick option").all_inner_texts() if a.sample in o)
        pg.select_option("#pick", label=opt)
        pg.wait_for_timeout(300)
        pg.screenshot(path=a.out, full_page=True)
        b.close()
    print(f"wrote {a.out} ({Path(a.out).stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
