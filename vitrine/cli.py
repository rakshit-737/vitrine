"""VITRINE command-line interface (static analysis only; nothing is ever executed)."""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from .dissect import MAX_SIZE, PEParseError
from .model import evaluate
from .models import TriageResult
from .synth import FAMILIES, MALICIOUS_FAMILIES, append_benign_section, corpus, make_sample
from .triage import analyze, load_model, train_default, vector_bytes
from .yara_synth import synthesize, validate

PE_SUFFIXES = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi", ".vitrine"}


def _print(res: TriageResult) -> None:
    print(f"sha256   {res.sha256}")
    print(f"verdict  {res.verdict.value}  score={res.score:.3f}  family={res.family}")
    print(f"packed   {res.packed}   route_to_dynamic={res.route_to_dynamic}")
    print("top drivers (SHAP, log-odds; + pushes toward malicious):")
    for a in res.attributions:
        print(f"  {a.contribution:+.3f}  {a.explanation}")
    if res.capabilities:
        print("capabilities:")
        for c in res.capabilities:
            print(f"  [{c.attack_id}] {c.name}: {', '.join(c.evidence[:4])}")
    for n in res.notes:
        print(f"note: {n}")
    if res.yara:
        print(f"yara: specificity={res.yara.specificity} coverage={res.yara.coverage}")
        print(res.yara.text)
    if res.structural_rule:
        print(res.structural_rule)


MAX_FILE = 32 * 1024 * 1024  # same cap as the API upload limit


def _load_dir(d: str | None, limit: int = 400) -> list[bytes]:
    """Read up to ``limit`` PE files (by suffix, each at most 32 MiB) from ``d``; 0 = no limit."""
    if not d:
        return []
    out = []
    for p in sorted(Path(d).iterdir()):
        if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
            try:
                if p.stat().st_size <= MAX_FILE:
                    out.append(p.read_bytes())
            except OSError:
                continue
            if limit and len(out) >= limit:
                break
    return out


def _model(path: str | None):
    return load_model(path) if path else train_default()


def _read_pe(p: Path) -> bytes:
    """Read a file for analysis, refusing files over the parser's 128 MiB cap *before* reading them
    (analysis needs roughly 15x the file size in memory)."""
    size = p.stat().st_size
    if size > MAX_SIZE:
        raise PEParseError(f"file too large ({size:,} bytes > {MAX_SIZE:,}); skipped without reading")
    return p.read_bytes()


def cmd_gen(a) -> None:
    out = Path(a.out)
    for fam in FAMILIES:
        (out / fam).mkdir(parents=True, exist_ok=True)
    for i, (fam, data) in enumerate(corpus(a.n, a.seed)):
        (out / fam / f"{fam}_{i:04d}.exe.vitrine").write_bytes(data)
    print(f"wrote synthetic inert corpus to {out}")


def cmd_train(a) -> None:
    m = train_default(a.n, a.seed)
    test = corpus(10, a.seed + 1)
    print(json.dumps(evaluate(m, [vector_bytes(b) for _, b in test],
                              [int(f in MALICIOUS_FAMILIES) for f, _ in test]), indent=1))
    m.save(a.out)
    print(f"saved model to {a.out}")


def cmd_analyze(a) -> None:
    m = _model(a.model)
    res = analyze(_read_pe(Path(a.file)), m,
                  _load_dir(a.benign_dir, a.benign_limit) if a.benign_dir else None, _load_dir(a.siblings_dir))
    if a.json:
        print(json.dumps(res.to_dict(), indent=1))
    else:
        _print(res)


def cmd_scan(a) -> None:
    """Triage every PE in a directory; JSON lines to stdout, summary to stderr."""
    m = _model(a.model)
    files = [p for p in sorted(Path(a.dir).rglob("*") if a.recursive else Path(a.dir).iterdir())
             if p.is_file() and p.suffix.lower() in PE_SUFFIXES]
    if a.limit:
        files = files[: a.limit]
    verdicts: Counter = Counter()
    t0 = time.time()
    for p in files:
        try:
            r = analyze(_read_pe(p), m)
        except (PEParseError, OSError, ValueError) as e:
            verdicts["PARSE_ERROR"] += 1
            print(json.dumps({"path": str(p), "error": str(e)}))
            continue
        verdicts[r.verdict.value] += 1
        print(json.dumps({"path": str(p), "verdict": r.verdict.value, "score": r.score, "packed": r.packed,
                          "route_to_dynamic": r.route_to_dynamic,
                          "capabilities": [c.attack_id for c in r.capabilities]}))
    dt = time.time() - t0
    print(f"{len(files)} files in {dt:.1f}s: {dict(verdicts)}", file=sys.stderr)


def cmd_serve(a) -> None:
    import uvicorn

    from .api import create_app

    hosts = ["127.0.0.1", "localhost", *a.allowed_host]
    uvicorn.run(create_app(a.model, a.benign_dir, allowed_hosts=hosts, enable_docs=a.enable_docs),
                host=a.host, port=a.port, limit_concurrency=16)


def cmd_demo(a) -> None:
    print("== VITRINE demo (synthetic inert PEs only) ==\n")
    m = train_default()
    test = corpus(10, seed=7)
    metrics = evaluate(m, [vector_bytes(b) for _, b in test], [int(f in MALICIOUS_FAMILIES) for f, _ in test])
    print("held-out metrics (synthetic, easy by construction):", {k: round(v, 3) for k, v in metrics.items()})
    benign = [make_sample("benign", 5000 + i) for i in range(40)]

    print("\n-- 1. explainable verdict: injector --")
    inj_sibs = [make_sample("injector", 9000 + i) for i in range(10)]
    _print(analyze(make_sample("injector", 1234), m, benign, inj_sibs))

    print("\n-- 2. packing routing --")
    _print(analyze(make_sample("packed", 42), m, benign, [make_sample("packed", 43)]))

    print("\n-- 3. per-family auto-YARA specificity/coverage --")
    for fam in MALICIOUS_FAMILIES:
        group = [make_sample(fam, 100 + i) for i in range(5)]
        sibs = [make_sample(fam, 200 + i) for i in range(20)]
        r = synthesize(f"vitrine_family_{fam}", group, benign, fam)
        if r:
            validate(r, benign, sibs)
            print(f"  {fam:11s} strings={len(r.strings)} thr={r.threshold} "
                  f"specificity={r.specificity:.2f} coverage={r.coverage:.2f}")

    print("\n-- 4. adversarial: append benign section + pad GUI imports --")
    s = make_sample("injector", 77)
    adv = append_benign_section(s, seed=1)
    for label, d in (("original", s), ("perturbed", adv)):
        r = analyze(d, m)
        print(f"  {label:9s} score={r.score:.3f} verdict={r.verdict.value} "
              f"caps={[c.attack_id for c in r.capabilities]}")


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """Show a default only when it says something (not None, False or an empty list)."""

    def _get_help_string(self, action):
        if action.default is None or action.default is False or action.default == []:
            return action.help
        return super()._get_help_string(action)


def main(argv: list[str] | None = None) -> int:
    from . import __version__

    fmt = _HelpFormatter
    p = argparse.ArgumentParser(prog="vitrine", description=__doc__, formatter_class=fmt)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-corpus", help="write synthetic inert PE corpus", formatter_class=fmt)
    g.add_argument("out", help="output directory (one sub-folder per family)")
    g.add_argument("-n", type=int, default=10, help="samples per family")
    g.add_argument("--seed", type=int, default=0, help="RNG seed")
    g.set_defaults(fn=cmd_gen)
    t = sub.add_parser("train", help="train the linear demo model on the synthetic corpus", formatter_class=fmt)
    t.add_argument("--out", default="vitrine_model.json", help="where to save the model JSON")
    t.add_argument("-n", type=int, default=20, help="training samples per family")
    t.add_argument("--seed", type=int, default=0, help="RNG seed")
    t.set_defaults(fn=cmd_train)
    an = sub.add_parser("analyze", help="statically analyze a PE file", formatter_class=fmt)
    an.add_argument("file", help="PE file to analyze (read only, never executed)")
    an.add_argument("--model", help="model file (EMBER-trained vitrine_xgb.json or linear demo model); "
                    "default: train the synthetic demo model")
    an.add_argument("--benign-dir", help="benign corpus for YARA specificity validation")
    an.add_argument("--benign-limit", type=int, default=400, help="max benign PE files to load (0 = all)")
    an.add_argument("--siblings-dir", help="suspected same-family samples for YARA coverage")
    an.add_argument("--json", action="store_true", help="print the full JSON report")
    an.set_defaults(fn=cmd_analyze)
    sc = sub.add_parser("scan", help="triage every PE in a directory (JSON lines)", formatter_class=fmt)
    sc.add_argument("dir", help="directory to scan")
    sc.add_argument("--model", help="model file (default: synthetic demo model)")
    sc.add_argument("--limit", type=int, default=0, help="stop after this many files (0 = all)")
    sc.add_argument("--recursive", action="store_true", help="descend into sub-directories")
    sc.set_defaults(fn=cmd_scan)
    sv = sub.add_parser("serve", help="run the FastAPI service + triage UI", formatter_class=fmt)
    sv.add_argument("--model", help="model file (default: synthetic demo model)")
    sv.add_argument("--benign-dir", help="benign corpus for rule validation (first 400 PE files)")
    sv.add_argument("--host", default="127.0.0.1", help="bind address (keep localhost for a lab tool)")
    sv.add_argument("--port", type=int, default=8000, help="TCP port")
    sv.add_argument("--allowed-host", action="append", default=[], help="extra Host header to accept")
    sv.add_argument("--enable-docs", action="store_true", help="serve /docs (loads Swagger UI from a CDN)")
    sv.set_defaults(fn=cmd_serve)
    d = sub.add_parser("demo", help="end-to-end demo on synthetic samples", formatter_class=fmt)
    d.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    try:
        a.fn(a)
    except ImportError as e:
        extra = "api" if getattr(e, "name", "") in ("fastapi", "uvicorn", "starlette") else "ml"
        print(f"vitrine: missing optional dependency {e.name!r}; install it with: pip install 'vitrine[{extra}]'",
              file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"vitrine: no such file: {e.filename}", file=sys.stderr)
        return 2
    except PEParseError as e:
        print(f"vitrine: not a parseable PE file: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
