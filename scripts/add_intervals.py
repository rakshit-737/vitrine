#!/usr/bin/env python
"""Derive 95 % intervals and like-for-like summaries from the committed result files.

Reads results/{adversarial,benign_system32,yara_structural,ember_benchmark}.json (counts are exact or
recoverable from rate x n) and writes results/intervals.json:

* adversarial detection rates: Wilson 95 % intervals (n = 3,000) and unpaired two-proportion z tests
  XGB vs tuned LightGBM (paired McNemar needs per-sample outcomes, which the run did not store);
* System32 false positives: 0 / 2,999 -> rule-of-three 95 % upper bound, floor rate with Wilson CI;
* auto-YARA: per-family coverage and benign-FP Wilson intervals, coverage on the *same* families
  (where VITRINE emits a rule) for every generator, the rule-set (not mean per-rule) specificity,
  and the list of VITRINE rules with (near-)zero out-of-time coverage;
* SHAP deletion test: top-k / random-k ratio.

    python scripts/add_intervals.py
"""
from __future__ import annotations

import argparse
import json
import math

from _common import RESULTS, dump
from _stats import rule_of_three, wilson


def z_two_prop(p1: float, p2: float, n: int) -> tuple[float, float]:
    p = (p1 + p2) / 2
    se = math.sqrt(2 * p * (1 - p) / n) or 1e-12
    z = (p1 - p2) / se
    return z, math.erfc(abs(z) / math.sqrt(2))


def main() -> None:
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    out = {}
    adv = json.loads((RESULTS / "adversarial.json").read_text())
    n = adv["n_malware"]
    rows = []
    for r in adv["rows"]:
        row = {"perturbation": r["perturbation"]}
        for m, v in r.items():
            if isinstance(v, dict):
                k = round(v["detection_rate"] * n)
                row[m] = {"detection_rate": k / n, "ci95": wilson(k, n)}
        z, p = z_two_prop(r["vitrine_xgb"]["detection_rate"], r["lgbm_ember_2018"]["detection_rate"], n)
        row["xgb_vs_lgbm2018_unpaired"] = {"z": z, "p": p}
        rows.append(row)
    out["adversarial"] = {"n": n, "rows": rows}

    b = json.loads((RESULTS / "benign_system32.json").read_text())
    nb = b["n_parsed"]
    floor = b["triage"]["SUSPICIOUS_by_capability_floor"]
    out["system32"] = {"n": nb, "fp_upper95_when_zero": rule_of_three(nb),
                       "floor_rate": floor / nb, "floor_ci95": wilson(floor, nb)}

    y = json.loads((RESULTS / "yara_structural.json").read_text())
    nben = y["n_test_benign"]
    fams = y["families"]
    with_rule = [f["family"] for f in fams if f.get("vitrine")]
    gens = ("vitrine", "imphash_baseline", "frequency_baseline")
    per = []
    for f in fams:
        e = {"family": f["family"]}
        for g in gens:
            v = f.get(g)
            if not v:
                e[g] = None
                continue
            k = round(v["coverage_test"] * v["n_test_siblings"])
            e[g] = {"coverage": v["coverage_test"], "coverage_ci95": wilson(k, v["n_test_siblings"]),
                    "n_test_siblings": v["n_test_siblings"], "benign_fp": v["benign_fp_test"],
                    "benign_fp_rate_ci95": wilson(v["benign_fp_test"], nben)}
        per.append(e)
    same = {}
    for g in gens:
        cov = [e[g]["coverage"] for e in per if e["family"] in with_rule and e[g]]
        same[g] = sum(cov) / len(cov) if cov else None
    tot_fp = y["summary"]["vitrine"]["total_benign_fp"]
    out["yara"] = {
        "families_with_vitrine_rule": with_rule,
        "mean_coverage_on_vitrine_families": same,
        "vitrine_ruleset_benign_fp": tot_fp, "vitrine_ruleset_specificity": 1 - tot_fp / nben,
        "vitrine_ruleset_fp_rate_ci95": wilson(tot_fp, nben),
        "vitrine_rules_under_1pct_coverage": [e["family"] for e in per
                                              if e["vitrine"] and e["vitrine"]["coverage"] < 0.01],
        "imphash_fp_by_family": {e["family"]: e["imphash_baseline"]["benign_fp"] for e in per},
        "imphash_zero_fp_families_with_coverage": [e["family"] for e in per if e["imphash_baseline"]["benign_fp"] == 0
                                                   and e["imphash_baseline"]["coverage"] > 0],
        "per_family": per}

    eb = json.loads((RESULTS / "ember_benchmark.json").read_text())
    dt = eb["shap_faithfulness"]["deletion_test"]
    out["shap_deletion_ratio_topk_over_random"] = {k: v["mean_score_drop_shap_topk"] / v["mean_score_drop_random_k"]
                                                   for k, v in dt.items()}
    dump("intervals.json", out)
    print(json.dumps({k: v for k, v in out["yara"].items() if k != "per_family"}, indent=1))
    print(out["shap_deletion_ratio_topk_over_random"], out["system32"])


if __name__ == "__main__":
    main()
