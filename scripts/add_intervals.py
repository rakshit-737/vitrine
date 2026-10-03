#!/usr/bin/env python
"""Derive 95 % intervals and like-for-like summaries from the committed result files.

Reads results/{adversarial,benign_system32,yara_structural,ember_benchmark}.json (counts are exact or
recoverable from rate x n) and writes results/intervals.json:

* adversarial detection rates: Wilson 95 % intervals (n = 3,000 malware; rates are 3-draw means, the
  interval covers malware sampling, the draw range covers donor sampling). Paired XGB-vs-LightGBM
  tests are the exact McNemar p-values stored by ``bench_adversarial.py`` (draw 0);
* System32 false positives: 0 / 2,999 -> rule-of-three 95 % upper bound, floor rate with Wilson CI;
* auto-YARA: per-family coverage and benign-FP Wilson intervals, coverage on the *same* families
  (where VITRINE emits a rule) for every generator, the rule-set (not mean per-rule) specificity,
  and the list of VITRINE rules with (near-)zero out-of-time coverage; macro (mean per-family) and
  pooled (all test siblings) coverage with family-bootstrap CIs, and a paired family-level test
  (exact sign-flip and Wilcoxon) of VITRINE vs the benign-filtered imphash baseline;
* SHAP deletion test: top-k / random-k ratio.

    python scripts/add_intervals.py
"""
from __future__ import annotations

import argparse
import itertools
import json

import numpy as np
from _common import RESULTS, dump
from _stats import rule_of_three, wilson


def sign_flip_p(d: np.ndarray) -> float:
    """Exact two-sided sign-flip (paired permutation) p-value of mean(d) = 0."""
    d = d[d != 0]
    if d.size == 0:
        return 1.0
    obs = abs(d.mean())
    stats = [abs((d * np.array(s)).mean()) for s in itertools.product((1, -1), repeat=d.size)]
    return float(np.mean(np.array(stats) >= obs - 1e-12))


def yara_family_stats(fams: list[dict], gens: tuple[str, ...], ref: str = "vitrine", base: str = "imphash_filtered",
                      b: int = 10000) -> dict:
    """Macro and pooled coverage per generator (abstention = 0) with family-bootstrap CIs, plus a paired
    family-level comparison of ``ref`` with ``base``."""
    from scipy.stats import wilcoxon

    n = np.array([next(v["n_test_siblings"] for v in f.values() if isinstance(v, dict) and "n_test_siblings" in v)
                  for f in fams], float)
    cov = {g: np.array([(f.get(g) or {}).get("coverage_test", 0.0) for f in fams]) for g in gens}
    rng = np.random.default_rng(0)
    idx = rng.integers(0, len(fams), (b, len(fams)))

    def summ(c):
        macro = c[idx].mean(axis=1)
        pooled = (c[idx] * n[idx]).sum(axis=1) / n[idx].sum(axis=1)
        return {"macro": float(c.mean()), "macro_ci95": [float(v) for v in np.percentile(macro, [2.5, 97.5])],
                "pooled": float((c * n).sum() / n.sum()),
                "pooled_ci95": [float(v) for v in np.percentile(pooled, [2.5, 97.5])]}

    out = {"n_families": len(fams), "n_test_siblings": int(n.sum()), "family_bootstrap_resamples": b,
           "coverage": {g: summ(cov[g]) for g in gens}}
    d = cov[ref] - cov[base]
    hits = cov[ref] * n
    out[f"{ref}_minus_{base}"] = {
        **summ(d), "per_family": {f["family"]: float(x) for f, x in zip(fams, d)},
        "n_families_ref_better": int((d > 0).sum()), "n_families_base_better": int((d < 0).sum()),
        "sign_flip_p_two_sided": sign_flip_p(d),
        "wilcoxon_p_two_sided": float(wilcoxon(d[d != 0]).pvalue) if (d != 0).sum() > 1 else None,
        "largest_family_share_of_ref_hits": {fams[int(np.argmax(hits))]["family"]: float(hits.max() / hits.sum())}}
    return out


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
        row["draw_range"] = {m: [min(v["draw_rates"]), max(v["draw_rates"])] for m, v in r.items()
                             if isinstance(v, dict) and "draw_rates" in v}
        if "mcnemar_p_xgb_vs_lgbm2018_draw0" in r:
            row["mcnemar_p_xgb_vs_lgbm2018_draw0"] = r["mcnemar_p_xgb_vs_lgbm2018_draw0"]
        rows.append(row)
    out["adversarial"] = {"n": n, "rows": rows,
                          "note": "Wilson CI on the 3-draw mean rate with n = 3,000 malware; paired tests are "
                                  "exact McNemar on draw 0 (adversarial.json)"}

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
        "per_family": per,
        "family_level": yara_family_stats(fams, ("vitrine", "imphash_filtered", "frequency_filtered",
                                                 "imphash_baseline", "frequency_baseline", "vitrine_no_abstain"))}

    eb = json.loads((RESULTS / "ember_benchmark.json").read_text())
    dt = eb["shap_faithfulness"]["deletion_test"]
    out["shap_deletion_ratio_topk_over_random"] = {k: v["mean_score_drop_shap_topk"] / v["mean_score_drop_random_k"]
                                                   for k, v in dt.items()}
    dump("intervals.json", out)
    print(json.dumps({k: v for k, v in out["yara"].items() if k != "per_family"}, indent=1))
    print(out["shap_deletion_ratio_topk_over_random"], out["system32"])


if __name__ == "__main__":
    main()
