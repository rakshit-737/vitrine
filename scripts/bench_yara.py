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
    ap.add_argument("--min-support", type=float, default=0.2)
    ap.add_argument("--benign-pool-mod", type=int, default=10, help="keep 1/N of training benign for tuning")
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
            if _pick(rec["sha256"], a.benign_pool_mod):
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

    # ---- synthesize every rule first, then stream the test set once (memory-bounded)
    rules: dict[tuple[str, str], StructuralRule] = {}
    meta_rows = {}
    rules_txt = []
    for fam in fams:
        g = groups[fam]
        meta_rows[fam] = {"family": fam, "n_group": len(g), "n_train_family": tr_c[fam]}
        rule = synthesize_structural(f"vitrine_{fam}", g, benign_train, fam, min_support=a.min_support)
        if rule:
            rules[(fam, "vitrine")] = rule
            rules_txt.append(rule.text.replace('import "pe"\n\n', ""))
        ih = Counter(next((x[1] for x in s if x[0] == "imphash"), "") for s in g).most_common(1)[0][0]
        if ih:
            rules[(fam, "imphash_baseline")] = StructuralRule("ih", [("imphash", ih)], 1, fam, len(g))
        freq = [x for x, _ in Counter(x for s in g for x in s if x[0] == "imp").most_common(8)]
        if freq:
            rules[(fam, "frequency_baseline")] = StructuralRule("fq", freq, len(freq), fam, len(g))
    del groups

    cnt = {k: Counter() for k in rules}
    n_benign = 0
    for rec in iter_jsonl_gz(p / "test_struct.jsonl.gz"):
        at = structural_atoms(rec)
        if rec["label"] == 0:
            n_benign += 1
            for k, r in rules.items():
                if r.matches_atoms(at):
                    cnt[k]["benign_fp"] += 1
        else:
            fam_rec = rec["avclass"]
            for k, r in rules.items():
                which = "sib" if fam_rec == k[0] else "oth"
                cnt[k][which + "_total"] += 1
                if r.matches_atoms(at):
                    cnt[k][which + "_hits"] += 1

    n_local = 0
    if a.benign_dir:
        from vitrine.dissect import PEParseError, dissect
        from vitrine.ember import raw_from_report

        files = sorted(x for x in Path(a.benign_dir).iterdir() if x.suffix.lower() in {".dll", ".exe", ".sys"})
        for fpath in files[: a.benign_limit]:
            try:
                at = structural_atoms(raw_from_report(dissect(fpath.read_bytes())))
            except (PEParseError, OSError):
                continue
            n_local += 1
            for k, r in rules.items():
                if r.matches_atoms(at):
                    cnt[k]["local_fp"] += 1
        print(f"local benign corpus: {n_local} files from {a.benign_dir}")

    rows = []
    for fam in fams:
        row = dict(meta_rows[fam])
        for kind in ("vitrine", "imphash_baseline", "frequency_baseline"):
            k = (fam, kind)
            if k not in rules:
                row[kind] = None
                continue
            c = cnt[k]
            row[kind] = {
                "atoms": len(rules[k].atoms), "threshold": rules[k].threshold,
                "coverage_test": c["sib_hits"] / c["sib_total"] if c["sib_total"] else None,
                "n_test_siblings": c["sib_total"], "benign_fp_test": c["benign_fp"],
                "specificity_test": 1 - c["benign_fp"] / max(n_benign, 1),
                "cross_family_hits": c["oth_hits"] / c["oth_total"] if c["oth_total"] else None,
            }
            if n_local:
                row[kind]["local_benign_fp"] = c["local_fp"]
        v = row["vitrine"] or {}
        print(f"{fam:14s} vitrine cov={v.get('coverage_test')} fp={v.get('benign_fp_test')} "
              f"| imphash cov={(row['imphash_baseline'] or {}).get('coverage_test')} "
              f"| freq cov={(row['frequency_baseline'] or {}).get('coverage_test')} "
              f"fp={(row['frequency_baseline'] or {}).get('benign_fp_test')}", flush=True)
        rows.append(row)

    def agg(key, field):
        vals = [r[key][field] for r in rows if r.get(key) and r[key].get(field) is not None]
        return float(np.mean(vals)) if vals else None

    def cov_all(key):  # families without a rule count as zero coverage
        return float(np.mean([(r[key] or {}).get("coverage_test") or 0.0 for r in rows]))

    summary = {k: {"coverage_all_families": cov_all(k), "mean_coverage_where_rule": agg(k, "coverage_test"),
                   "mean_specificity": agg(k, "specificity_test"),
                   "total_benign_fp": int(sum(r[k]["benign_fp_test"] for r in rows if r.get(k))),
                   "mean_cross_family": agg(k, "cross_family_hits"),
                   "total_local_fp": int(sum(r[k].get("local_benign_fp", 0) for r in rows if r.get(k))),
                   "rules": sum(1 for r in rows if r.get(k))}
               for k in ("vitrine", "imphash_baseline", "frequency_baseline")}
    print(summary)
    dump("yara_structural.json", {"min_support": a.min_support, "n_test_benign": n_benign, "n_local_benign": n_local,
                                  "benign_train_pool": len(benign_train), "summary": summary, "families": rows})
    out = REPO / "results" / "rules"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ember2018_families.yar").write_text('import "pe"\n\n' + "\n".join(rules_txt))
    print("sha256(rules)", hashlib.sha256("\n".join(rules_txt).encode()).hexdigest()[:16])


if __name__ == "__main__":
    main()
