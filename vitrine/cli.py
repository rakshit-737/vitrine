"""VITRINE command-line interface (static analysis only; nothing is ever executed)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .dissect import dissect
from .features import vector
from .model import VerdictModel, evaluate
from .models import TriageResult
from .synth import FAMILIES, MALICIOUS_FAMILIES, append_benign_section, corpus, make_sample
from .triage import analyze, train_default
from .yara_synth import synthesize, validate


def _print(res: TriageResult) -> None:
    print(f"sha256   {res.sha256}")
    print(f"verdict  {res.verdict.value}  score={res.score:.3f}  family={res.family}")
    print(f"packed   {res.packed}   route_to_dynamic={res.route_to_dynamic}")
    print("top drivers:")
    for a in res.attributions:
        print(f"  {a.contribution:+.3f}  {a.explanation}")
    if res.capabilities:
        print("capabilities:")
        for c in res.capabilities:
            print(f"  [{c.attack_id}] {c.name}: {', '.join(c.evidence)}")
    for n in res.notes:
        print(f"note: {n}")
    if res.yara:
        print(f"yara: specificity={res.yara.specificity} coverage={res.yara.coverage}")
        print(res.yara.text)


def _load_dir(d: str | None) -> list[bytes]:
    if not d:
        return []
    return [p.read_bytes() for p in sorted(Path(d).iterdir()) if p.is_file()]


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
    print(json.dumps(evaluate(m, [vector(dissect(b)) for _, b in test],
                              [int(f in MALICIOUS_FAMILIES) for f, _ in test]), indent=1))
    m.save(a.out)
    print(f"saved model to {a.out}")


def cmd_analyze(a) -> None:
    m = VerdictModel.load(a.model) if a.model else train_default()
    res = analyze(Path(a.file).read_bytes(), m, _load_dir(a.benign_dir) if a.benign_dir else None,
                  _load_dir(a.siblings_dir))
    if a.json:
        print(json.dumps(res.to_dict(), indent=1))
    else:
        _print(res)


def cmd_demo(a) -> None:
    print("== VITRINE demo (synthetic inert PEs only) ==\n")
    m = train_default()
    test = corpus(10, seed=7)
    metrics = evaluate(m, [vector(dissect(b)) for _, b in test], [int(f in MALICIOUS_FAMILIES) for f, _ in test])
    print("held-out metrics:", {k: round(v, 3) for k, v in metrics.items()})
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vitrine", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-corpus", help="write synthetic inert PE corpus")
    g.add_argument("out"), g.add_argument("-n", type=int, default=10), g.add_argument("--seed", type=int, default=0)
    g.set_defaults(fn=cmd_gen)
    t = sub.add_parser("train", help="train verdict model on synthetic corpus")
    t.add_argument("--out", default="vitrine_model.json"), t.add_argument("-n", type=int, default=20)
    t.add_argument("--seed", type=int, default=0)
    t.set_defaults(fn=cmd_train)
    an = sub.add_parser("analyze", help="statically analyze a PE file")
    an.add_argument("file"), an.add_argument("--model")
    an.add_argument("--benign-dir", help="benign corpus for YARA specificity validation")
    an.add_argument("--siblings-dir", help="suspected same-family samples for YARA coverage")
    an.add_argument("--json", action="store_true")
    an.set_defaults(fn=cmd_analyze)
    d = sub.add_parser("demo", help="end-to-end demo on synthetic samples")
    d.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
