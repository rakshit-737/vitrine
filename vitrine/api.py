"""FastAPI service + analyst triage UI.

Uploaded bytes are held in memory, parsed and discarded: nothing is written to disk and nothing
is executed. Bind to localhost (default) -- this is a lab tool, not an internet-facing service.

    vitrine serve --model vitrine_xgb.json --benign-dir C:/Windows/System32   # http://127.0.0.1:8000
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import __version__
from .dissect import PEParseError
from .triage import analyze, load_model, train_default
from .yara_synth import match, parse

MAX_UPLOAD = 32 * 1024 * 1024
STATIC = Path(__file__).parent / "static"


class RuleIn(BaseModel):
    text: str


def _load_benign(d: str | None, limit: int = 400) -> list[bytes]:
    if not d:
        return []
    out = []
    for p in sorted(Path(d).iterdir()):
        if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys"}:
            try:
                out.append(p.read_bytes())
            except OSError:
                continue
            if len(out) >= limit:
                break
    return out


def create_app(model_path: str | None = None, benign_dir: str | None = None, benign_limit: int = 400) -> FastAPI:
    app = FastAPI(title="VITRINE", version=__version__,
                  description="Static-first explainable PE triage. Never executes uploaded files.")
    model = load_model(model_path) if model_path else train_default()
    benign = _load_benign(benign_dir, benign_limit)
    kind = type(model).__name__

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "model": kind, "benign_corpus": len(benign)}

    @app.get("/api/model")
    def model_info():
        return {"model": kind, "thresholds": getattr(model, "thresholds", {}) or {"malicious": 0.7, "suspicious": 0.3},
                "meta": getattr(model, "meta", {}), "families": sorted(getattr(model, "centroids", {}) or {})}

    @app.post("/api/analyze")
    async def analyze_ep(request: Request, rules: bool = True):
        data = await request.body()
        if not data:
            raise HTTPException(400, "empty body: POST the file bytes as application/octet-stream")
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, f"file larger than {MAX_UPLOAD} bytes")
        try:
            res = analyze(data, model, benign if (rules and benign) else None)
        except PEParseError as e:
            raise HTTPException(422, f"not a parseable PE: {e}") from e
        return res.to_dict()

    @app.post("/api/yara/validate")
    def validate_rule(rule: RuleIn):
        strs, thr = parse(rule.text)
        if not strs:
            raise HTTPException(422, "no text strings found (native validator supports text strings + 'N of them')")
        hits = sum(match(rule.text, b) for b in benign)
        return {"strings": len(strs), "threshold": thr, "benign_total": len(benign), "benign_hits": hits,
                "specificity": (1 - hits / len(benign)) if benign else None}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC / "index.html").read_text(encoding="utf-8")

    return app
