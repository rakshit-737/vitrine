#!/usr/bin/env python
"""Auto-YARA benchmark on real data: per-family structural rules from EMBER 2018.

For the most frequent AVClass families in the EMBER 2018 *training* malware, synthesize a
``pe``-module rule (imports / section names / imphash) with :func:`synthesize_structural`,
tuned against 20k *training* benign samples. Then, on the *out-of-time* test set, measure

  * coverage     -- recall on test samples of the same family (siblings seen 1-2 months later)
  * specificity  -- 1 - hit-rate on all 100k test benign samples
  * cross-family -- hit-rate on test malware of *other* families
  * optional: hit-rate on a local benign corpus (e.g. C:/Windows/System32), via VITRINE's dissector

Baselines: (a) exact-imphash rule of the group's most common imphash, (b) naive frequency rule
(the 8 most frequent imports in the group, all required, no benign filtering) -- a yarGen-like
string-frequency approach without the benign-corpus step.

    python scripts/bench_yara.py --data D:/.../vitrine [--benign-dir C:/Windows/System32 --benign-limit 3000]
"""
from __future__ import annotations

import argparse
import hashlib
from collections import Counter
from pathlib import Path

import numpy as np
from _common import REPO, data_dir, dump, iter_jsonl_gz, load_split

from vitrine.yara_synth import StructuralRule, structural_atoms, synthesize_structural


def _pick(sha: str, mod: int) -> bool:
    return int(sha[:6], 16) % mod == 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--families", type=int, default=15)
    ap.add_argument("--group", type=int, default=400, help="training samples per family rule")
    ap.add_argument("--benign-dir", default=None)
    ap.add_argument("--benign-limit", type=int, default=3000)
    a = ap.parse_args()
    data = data_dir(a.data)
    p = data / "processed"

    _, _, ytr, mtr = load_split(data, "train", vectors=False)
    _, _, yte, mte = load_split(data, "test", vectors=False)
    tr_c = Counter(f for f, y in zip(mtr["avclass"], ytr) if y == 1 and f)
    te_c = Counter(f for f, y in zip(mte["avclass"], yte) if y == 1 and f)
    fams = [f for f, _ in tr_c.most_common() if te_c[f] >= 30][: a.families]
    print("families:", fams)

    rng = np.random.default_rng(0)
    groups: dict[str, list[set]] = {f: [] for f in fams}
    benign_train: list[set] = []
    for rec in iter_jsonl_gz(p / "train_struct.jsonl.gz"):
        if rec["label"] == 0:
            if _pick(rec["sha256"], 25):  # ~4 % of 300k benign -> ~12k
                benign_train.append(structural_atoms(rec))
        elif rec["avclass"] in groups:
            g = groups[rec["avclass"]]
            if len(g) < a.group * 4:
                g.append(structural_atoms(rec))
    for f in fams:
        g = groups[f]
        if len(g) > a.group:
            groups[f] = [g[i] for i in rng.choice(len(g), a.group, replace=False)]
    print(f"benign training pool: {len(benign_train)}")

    test_benign: list[set] = []
    test_mal: list[tuple[str, set]] = []
    for rec in iter_jsonl_gz(p / "test_struct.jsonl.gz"):
        at = structural_atoms(rec)
        if rec["label"] == 0:
            test_benign.append(at)
        else:
            test_mal.append((rec["avclass"], at))

    local: list[set] = []
    if a.benign_dir:
        from vitrine.dissect import PEParseError, dissect
        from vitrine.ember import raw_from_report

        files = sorted(x for x in Path(a.benign_dir).iterdir() if x.suffix.lower() in {".dll", ".exe", ".sys"})
        for fpath in files[: a.benign_limit]:
            try:
                rep = dissect(fpath.read_bytes())
            except (PEParseError, OSError):
                continue
            local.append(structural_atoms(raw_from_report(rep)))
        print(f"local benign corpus: {len(local)} files from {a.benign_dir}")

    def score(rule, fam):
        sib = [at for f, at in test_mal if f == fam]
        oth = [at for f, at in test_mal if f != fam]
        r = {"coverage_test": float(np.mean([rule.matches_atoms(s) for s in sib])) if sib else None,
             "n_test_siblings": len(sib),
             "benign_fp_test": int(sum(rule.matches_atoms(b) for b in test_benign)),
             "cross_family_hits": float(np.mean([rule.matches_atoms(s) for s in oth])) if oth else None}
        r["specificity_test"] = 1 - r["benign_fp_test"] / max(len(test_benign), 1)
        if local:
            r["local_benign_fp"] = int(sum(rule.matches_atoms(b) for b in local))
        return r

    rows = []
    rules_txt = []
    for fam in fams:
        g = groups[fam]
        row = {"family": fam, "n_group": len(g), "n_train_family": tr_c[fam]}
        rule = synthesize_structural(f"vitrine_{fam}", g, benign_train, fam)
        row["vitrine"] = None if rule is None else {"atoms": len(rule.atoms), "threshold": rule.threshold,
                                                    **score(rule, fam)}
        if rule:
            rules_txt.append(rule.text.replace('import "pe"\n\n', ""))
        ih = Counter(next((x[1] for x in s if x[0] == "imphash"), "") for s in g).most_common(1)[0][0]
        row["imphash_baseline"] = score(StructuralRule("ih", [("imphash", ih)], 1, fam, len(g)), fam) if ih else None
        freq = [x for x, _ in Counter(x for s in g for x in s if x[0] == "imp").most_common(8)]
        row["frequency_baseline"] = score(StructuralRule("fq", freq, len(freq), fam, len(g)), fam) if freq else None
        v = row["vitrine"] or {}
        print(f"{fam:14s} vitrine cov={v.get('coverage_test')} fp={v.get('benign_fp_test')} "
              f"| imphash cov={(row['imphash_baseline'] or {}).get('coverage_test')} "
              f"| freq cov={(row['frequency_baseline'] or {}).get('coverage_test')} "
              f"fp={(row['frequency_baseline'] or {}).get('benign_fp_test')}", flush=True)
        rows.append(row)

    def agg(key, field):
        vals = [r[key][field] for r in rows if r.get(key) and r[key].get(field) is not None]
        return float(np.mean(vals)) if vals else None

    summary = {k: {"mean_coverage": agg(k, "coverage_test"), "mean_specificity": agg(k, "specificity_test"),
                   "total_benign_fp": int(sum(r[k]["benign_fp_test"] for r in rows if r.get(k))),
                   "mean_cross_family": agg(k, "cross_family_hits"),
                   "total_local_fp": int(sum(r[k].get("local_benign_fp", 0) for r in rows if r.get(k))),
                   "rules": sum(1 for r in rows if r.get(k))}
               for k in ("vitrine", "imphash_baseline", "frequency_baseline")}
    print(summary)
    dump("yara_structural.json", {"n_test_benign": len(test_benign), "n_local_benign": len(local),
                                  "benign_train_pool": len(benign_train), "summary": summary, "families": rows})
    out = REPO / "results" / "rules"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ember2018_families.yar").write_text('import "pe"\n\n' + "\n".join(rules_txt))
    print("sha256(rules)", hashlib.sha256("\n".join(rules_txt).encode()).hexdigest()[:16])


if __name__ == "__main__":
    main()
