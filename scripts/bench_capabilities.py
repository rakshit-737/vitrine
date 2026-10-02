#!/usr/bin/env python
"""Validate VITRINE's capability tagger and packing heuristic against EMBER2024's capa and packer labels.

EMBER2024 records carry Mandiant capa output (ATT&CK ``ttps``, MBC behaviours) and AV-derived
``packer`` tags. For every record of the local subsample (all 64 weeks) that has capa output, we run
VITRINE's import/string capability rules on the v3->v2 translated record and compare per rule:

* precision / recall vs capa's ATT&CK techniques (exact ID, or same parent technique for
  sub-techniques: VITRINE ``T1055.002`` vs capa ``T1055``/``T1055.002``), Wilson 95 % CIs;
* for anti-debugging (T1622), capa reports it under MBC ``B0001`` (Debugger Detection), so that
  rule is also scored against MBC.

Packing: VITRINE's packed flag (packer-like section name, or high-entropy section with a tiny import
table) vs a non-empty ``packer`` tag, on all records.

Note the labels are themselves tools (capa sees code; VITRINE sees only imports/strings), so this
measures agreement, not ground truth. Streams the files; under 1 GB RAM.

    python scripts/bench_capabilities.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import re
from collections import Counter

from _common import data_dir, dump, iter_jsonl_gz
from _stats import wilson

from vitrine.capabilities import RULES, tag_raw
from vitrine.ember3 import to_v2
from vitrine.features import FEATURE_NAMES, vector_raw

TID = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]")
IDS = sorted({r.attack_id for r in RULES})
MBC = re.compile(r"\[([BCE]\d{4}(?:\.\d{3})?)\]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    a = ap.parse_args()
    src = data_dir(a.data) / "ember2024"
    files = sorted(src.glob("*_Win32_*.prefix.jsonl.gz"))
    tp, fp, fn = Counter(), Counter(), Counter()
    dbg = Counter()
    pk = Counter()
    n_caps = n_all = 0
    i_pn, i_he, i_it = (FEATURE_NAMES.index(k) for k in ("packer_section_name", "n_high_entropy_sections",
                                                           "imports_tiny"))
    for p in files:
        for r in iter_jsonl_gz(p):
            v2 = to_v2(r)
            n_all += 1
            f = vector_raw(v2)
            packed = f[i_pn] > 0 or (f[i_he] > 0 and f[i_it] > 0)
            tagged = bool(r.get("packer"))
            pk[(bool(packed), tagged)] += 1
            if not r.get("ttps") and not r.get("mbc"):
                continue
            n_caps += 1
            capa = {m for t in r.get("ttps") or [] for m in TID.findall(t.get("Technique", ""))}
            parents = capa | {c.split(".")[0] for c in capa}
            mbc = {m for t in r.get("mbc") or [] for m in MBC.findall(t.get("Behavior", ""))}
            mine = {c.attack_id for c in tag_raw(v2)}
            for t in IDS:
                pred = t in mine
                truth = t in capa or t.split(".")[0] in parents
                tp[t] += pred and truth
                fp[t] += pred and not truth
                fn[t] += truth and not pred
            pred = "T1622" in mine
            truth = "B0001" in mbc or any(m.startswith("B0001") for m in mbc)
            dbg["tp"] += pred and truth
            dbg["fp"] += pred and not truth
            dbg["fn"] += truth and not pred
        print(f"{p.name}: {n_caps} with capa output so far", flush=True)

    def pr(t, f_, n_):
        return {"tp": t, "fp": f_, "fn": n_,
                "precision": t / (t + f_) if t + f_ else None, "precision_ci95": wilson(t, t + f_),
                "recall": t / (t + n_) if t + n_ else None, "recall_ci95": wilson(t, t + n_)}

    rules = []
    for t in IDS:
        rs = [r for r in RULES if r.attack_id == t]
        rules.append({"rule": " / ".join(r.name for r in rs), "attack_id": t,
                      "high_risk": any(r.high_risk for r in rs), **pr(tp[t], fp[t], fn[t])})
    tp_pk, fp_pk, fn_pk = pk[(True, True)], pk[(True, False)], pk[(False, True)]
    res = {"n_records": n_all, "n_with_capa_output": n_caps,
           "label_source": "EMBER2024 capa ttps/mbc and AV-derived packer tags (joyce8/EMBER2024 rev 3d23efef)",
           "rules_vs_capa_attack": rules,
           "anti_debug_T1622_vs_mbc_B0001": pr(dbg["tp"], dbg["fp"], dbg["fn"]),
           "packing_vs_packer_tag": {**pr(tp_pk, fp_pk, fn_pk), "flagged": tp_pk + fp_pk, "tagged": tp_pk + fn_pk}}
    dump("capabilities_ember2024.json", res)
    for r in sorted(rules, key=lambda r: -(r["tp"] + r["fp"])):
        print(f"{r['attack_id']:10s} {r['rule'][:34]:34s} P={r['precision']} R={r['recall']} tp={r['tp']} fp={r['fp']}")
    print("T1622 vs MBC", res["anti_debug_T1622_vs_mbc_B0001"])
    print("packing", res["packing_vs_packer_tag"])


if __name__ == "__main__":
    main()
