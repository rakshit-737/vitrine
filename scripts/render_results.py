#!/usr/bin/env python
"""Fill the ``@@KEY@@`` tokens of ``templates/`` from the committed result files.

Numbers in README, the docs and the paper that come from a result JSON are written as tokens in
``templates/<path>`` and rendered to ``<path>``; edit the template, never the rendered file. Every
token must resolve, and rendering fails on an unknown token or a missing result file.

    python scripts/render_results.py           # write README.md, docs/*.md, paper/main.tex
    python scripts/render_results.py --check   # CI: rendered files are current and no @@ token is left
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "results"
TEMPLATES = REPO / "templates"
TOKEN = re.compile(r"@@([A-Z0-9_]+)@@")
LEFTOVER = re.compile(r"@@[A-Za-z0-9_]+@@")
TEXT_SUFFIXES = {".md", ".tex", ".bib", ".json", ".py", ".yml", ".yaml", ".toml", ".cff", ".txt", ".html", ".in"}


def load(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


class F:
    """Number formatting for one output format (Markdown or LaTeX)."""

    def __init__(self, tex: bool):
        self.tex = tex
        self.pc = r"\%" if tex else " %"
        self.dash = "--" if tex else "-"
        self.minus = "$-$" if tex else "−"

    def num(self, x: float, d: int = 4, sign: bool = False) -> str:
        s = f"{abs(x):.{d}f}"
        if x < 0 and float(s) != 0:
            return self.minus + s
        return ("+" if sign and float(s) != 0 else "") + s

    def ci(self, lo: float, hi: float, d: int = 4, sign: bool = False) -> str:
        a, b = self.num(lo, d, sign), self.num(hi, d, sign)
        if lo < 0 or (sign and hi > 0):
            return f"{a} to {b}"
        return f"{a}{self.dash}{b}"

    def pci(self, p: float, lo: float, hi: float, d: int = 4, sign: bool = False) -> str:
        return f"{self.num(p, d, sign)} ({self.ci(lo, hi, d, sign)})"

    def pct(self, x: float, d: int = 1) -> str:
        return f"{100 * x:.{d}f}{self.pc}"

    def pctci(self, p: float, lo: float, hi: float, d: int = 1) -> str:
        return f"{100 * p:.{d}f}{self.pc} ({100 * lo:.{d}f}{self.dash}{100 * hi:.{d}f})"

    def pt(self, x: float, d: int = 1, sign: bool = False) -> str:
        return self.num(100 * x, d, sign)

    def ptci(self, p: float, lo: float, hi: float, d: int = 1, sign: bool = False) -> str:
        return f"{self.pt(p, d, sign)} ({self.ci(100 * lo, 100 * hi, d, sign)})"

    def code(self, s: str) -> str:
        return r"\texttt{" + s.replace("_", r"\_") + "}" if self.tex else f"`{s}`"


def _pli(d: dict) -> tuple[float, float, float]:
    return d.get("point", d.get("mean")), d["lo"], d["hi"]


def values(f: F) -> dict[str, str]:  # noqa: C901 - one flat table of tokens
    drift = load("ember2024_drift.json")
    sec = load("ember_secondary.json")
    par = load("ember2024_drift_parity.json")
    xp = load("extractor_parity.json")
    al = load("ember2024_drift_align.json")
    v: dict[str, str] = {}

    # ---- EMBER 2018 verdict model and published reference
    m = drift["matrix"]["ember2018->ember2018_test"]
    v["V3AUC"] = f.pci(*_pli(m["roc_auc"]))
    v["V3T1"] = f.pctci(*_pli(m["tpr_at_fpr_1pct"]))
    v["V3T01"] = f.pctci(*_pli(m["tpr_at_fpr_0.1pct"]))
    v["V3AUCPT"] = f.num(m["roc_auc"]["point"])
    v["V3T1PT"] = f.pct(m["tpr_at_fpr_1pct"]["point"])
    v["V3T01PT"] = f.pct(m["tpr_at_fpr_0.1pct"]["point"])

    def pubdiff(key: str) -> str:
        d = sec["vitrine_minus_published"][key]
        return (f"AUC {f.pci(*_pli(d['roc_auc']), sign=True)}, "
                f"TPR @ 1{f.pc} FPR {f.ptci(*_pli(d['tpr_at_fpr_1pct']), sign=True)} pt, "
                f"TPR @ 0.1{f.pc} FPR {f.ptci(*_pli(d['tpr_at_fpr_0.1pct']), sign=True)} pt")
    v["PUBDIFF3"] = pubdiff("seed_pooled_3_seeds")
    v["PUBDIFF0"] = pubdiff("seed0_saved_triage_model")
    pd = sec["vitrine_minus_published"]["seed_pooled_3_seeds"]
    a = pd["roc_auc"]
    v["PUBAUC"] = f"{f.num(-a['point'])} ({f.num(-a['hi'])}{f.dash}{f.num(-a['lo'])})"
    t1, t01 = pd["tpr_at_fpr_1pct"], pd["tpr_at_fpr_0.1pct"]
    v["PUBDIFF"] = (f"{v['PUBAUC']} AUC, {f.pt(-t1['point'])} ({f.pt(-t1['hi'])}{f.dash}{f.pt(-t1['lo'])}) "
                    f"points of TPR at 1{f.pc} FPR and {f.pt(-t01['point'])} ({f.pt(-t01['hi'])}{f.dash}"
                    f"{f.pt(-t01['lo'])}) at 0.1{f.pc} FPR")
    v["PUBDIFFAUCPT"] = f.num(a["point"], sign=True)
    v["PUBDIFFAUCCI"] = f.ci(a["lo"], a["hi"], sign=True)
    v["PUBDIFFT01PT"] = f.pt(t01["point"], sign=True)
    v["PUBDIFFT01CI"] = f.ci(100 * t01["lo"], 100 * t01["hi"], 1, sign=True)
    v["PUBDIFFT1PT"] = f.pt(t1["point"], sign=True)

    # ---- SHAP deletion and packing
    k = sec["shap_deletion_test"]["k"]
    ks = ("1", "3", "5", "10")
    v["DELTOP"] = " / ".join(f"{k[i]['mean_score_drop_shap_topk']:.3f} ({k[i]['shap_topk_ci95'][0]:.3f}{f.dash}"
                             f"{k[i]['shap_topk_ci95'][1]:.3f})" for i in ks)
    v["DELRND"] = " / ".join(f"{k[i]['mean_score_drop_random_k']:.3f} ({k[i]['random_k_ci95'][0]:.3f}{f.dash}"
                             f"{k[i]['random_k_ci95'][1]:.3f})" for i in ks)
    v["DELRATIO"] = " / ".join(f"{k[i]['ratio_topk_over_random']:.0f} ({k[i]['ratio_ci95'][0]:.0f}{f.dash}"
                               f"{k[i]['ratio_ci95'][1]:.0f})" for i in ks)
    r = [k[i]["ratio_topk_over_random"] for i in ks]
    v["SHAPRATIO"] = f"{min(r):.0f}{f.dash}{max(r):.0f}"
    ps = sec["packing_subsets"]
    names = {"vitrine_xgb": "VITRINE", "lgbm_ember_2018": "LightGBM EMBER-2018 config",
             "lgbm_ember_paper": "LightGBM paper defaults"}
    v["PACKAUC"] = "; ".join(
        f"{n} {ps[key]['packed']['point']:.4f} vs {ps[key]['unpacked']['point']:.4f} unpacked, difference "
        f"{f.pci(*_pli(ps[key]['packed_minus_unpacked']), sign=True)}" for key, n in names.items())
    v["PACKFPR"] = "; ".join(
        f"{n} {f.pctci(b['packed'], *b['packed_wilson95'])} vs {f.pct(b['unpacked'])} unpacked"
        for key, n in names.items() for b in [ps[key]["benign_fpr_at_val_1pct_threshold"]])

    # ---- cross-time drift
    dr = drift["drop_2018test_minus_2024test"]["ember2018"]
    v["DROPAUC"] = f"{dr['roc_auc']['point']:.3f}"
    v["DROPREC"] = f"{100 * dr['recall_at_source_threshold']['point']:.1f}"
    v["DROPRECPT"] = f"{100 * dr['recall_at_source_threshold']['point']:.0f}"
    da = dr["roc_auc"]
    v["DROPAUCCI"] = f"{f.num(da['point'])} ({f.num(da['lo'])}{f.dash}{f.num(da['hi'])})"
    rc = dr["recall_at_source_threshold"]
    v["DROPRECCI"] = f"{100 * rc['point']:.1f} ({100 * rc['lo']:.1f}{f.dash}{100 * rc['hi']:.1f})"
    pa = drift["paired"]["2024test: ember2024 - ember2018_sub"]["roc_auc"]
    v["PAIREDAUC"] = f"{f.num(pa['point'], 3, True)} ({f.num(pa['lo'], 3)}{f.dash}{f.num(pa['hi'], 3)})"
    wk = drift["weekly_2018_model_on_2024"]
    lo_w, hi_w = min(wk, key=lambda w: w["roc_auc"]), max(wk, key=lambda w: w["roc_auc"])
    v["WEEKRANGE"] = (f"from {lo_w['roc_auc']:.3f} (week {lo_w['week']}; {lo_w['roc_auc_ci95'][0]:.3f}{f.dash}"
                      f"{lo_w['roc_auc_ci95'][1]:.3f}) to {hi_w['roc_auc']:.3f} (week {hi_w['week']}; "
                      f"{hi_w['roc_auc_ci95'][0]:.3f}{f.dash}{hi_w['roc_auc_ci95'][1]:.3f})")
    pdp = sec["published_2018_model_on_2024"]["drop_2018test_minus_2024test"]["roc_auc"]
    v["PUBDROP"] = f"{f.num(pdp['point'])} ({f.num(pdp['lo'])}{f.dash}{f.num(pdp['hi'])})"

    rows = [("ember2018->ember2018_test", "2018 (276k) $\\rightarrow$ 2018"),
            ("ember2018->ember2024_test", "2018 (276k) $\\rightarrow$ 2024"),
            ("ember2018_sub->ember2024_test", "2018 (99k) $\\rightarrow$ 2024"),
            ("ember2024->ember2024_test", "2024 (99k) $\\rightarrow$ 2024"),
            ("ember2024->ember2018_test", "2024 (99k) $\\rightarrow$ 2018")]
    tr = []
    for key, label in rows:
        c = drift["matrix"][key]
        b = c["at_source_1pct_threshold"]["bootstrap_seed_pooled"]
        tr.append(f"{label} & {f.pci(*_pli(c['roc_auc']))} & {f.pctci(*_pli(c['tpr_at_fpr_1pct']))} & "
                  f"{f.pctci(*_pli(b['fpr']), d=2)} / {f.pctci(*_pli(b['recall']))}\\\\")
    v["TABLEROWS"] = "\n".join(tr)

    # ---- definition and extractor parity
    s32 = par["parity_system32"]
    mz = s32["n_embedded_mz"]
    w = mz["exact_agreement_wilson95"]
    v["MZAGREE"] = f"{f.pct(mz['exact_agreement'])} ({100 * w[0]:.1f}{f.dash}{100 * w[1]:.1f})"
    tv = mz["total_variation_ci95"]
    v["MZTV"] = f"{mz['total_variation']:.2f} ({tv[0]:.2f}{f.dash}{tv[1]:.2f})"
    v["MZPSI"] = f"{mz['psi_v2_vs_v3_same_files']:.1f} ({mz['psi_ci95'][0]:.1f}{f.dash}{mz['psi_ci95'][1]:.1f})"
    fl = mz["psi_by_floor"]
    v["MZFLOOR"] = f"{fl['0.001']:.1f} at a 1e-3 floor to {fl['1e-06']:.1f} at 1e-6"
    v["S32HOST"] = s32["provenance"]["platform"] if "provenance" in s32 else "local"
    ent = [e for e in xp["features"] if e["feature"].endswith("entropy") and e["class"] == "parser"]
    e = max(ent, key=lambda e: e["psi_extractor_same_files"])
    v["ENTPSI"] = (f"{e['psi_extractor_same_files']:.2f} ({e['psi_extractor_ci95'][0]:.2f}{f.dash}"
                   f"{e['psi_extractor_ci95'][1]:.2f}; {f.code(e['feature'])})")

    # ---- ranking
    rk = drift["drift_ranking"]
    faithful = [x for x in rk["features"] if x["faithful"]]
    K = rk["k"]
    top = faithful[:K]
    pattern = {"both_classes": "both classes", "benign_only": "benign only", "malicious_only": "malware only",
               "mixed": "mixed", "stable": "stable"}

    def rk_ci(x: dict) -> str:
        lo, hi = x["rank_faithful_ci95"]
        return str(lo) if lo == hi else f"{lo}{f.dash}{hi}"

    def item(x: dict) -> str:
        return (f"{f.code(x['feature'])} (weight {x['drift_weight']:.2f}, rank {rk_ci(x)}, "
                f"PSI benign {x['psi_benign']:.2f} / malware {x['psi_malicious']:.2f})")
    tops = rk["faithful_top_k_by_binning"]
    order = [x["feature"] for x in faithful]
    core = sorted(set.intersection(*(set(t["top_k"]) for t in tops.values())), key=order.index)
    stable = [x["feature"] for x in top if x["p_in_faithful_top_k"] >= 0.95]
    fam = rk["top_family_control"]
    ov = {k2: t["overlap_with_primary"] for k2, t in tops.items() if k2 != "primary"}
    ovtxt = ", ".join(f"{t}/{K} ({n.replace('_', ' ')})" for n, t in ov.items())
    v["RANKLIST"] = "; ".join(item(x) for x in top)
    nl = chr(10)
    table = [f"| # | Feature | Group | Shift | PSI benign (95 % CI) | PSI malware (95 % CI) | Weight (95 % CI) "
             f"| Rank (95 % CI) | P(top {K}) |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for x in top:
        table.append(
            f"| {x['rank_faithful']} | `{x['feature']}` | {x['group'].replace('_', ' ')} | "
            f"{pattern[x['shift_pattern']]} | {x['psi_benign']:.2f} ({x['psi_benign_ci95'][0]:.2f}-"
            f"{x['psi_benign_ci95'][1]:.2f}) | {x['psi_malicious']:.2f} ({x['psi_malicious_ci95'][0]:.2f}-"
            f"{x['psi_malicious_ci95'][1]:.2f}) | {x['drift_weight']:.3f} ({x['drift_weight_ci95'][0]:.3f}-"
            f"{x['drift_weight_ci95'][1]:.3f}) | {rk_ci(x)} | {x['p_in_faithful_top_k']:.2f} |")
    v["RANKSECTION"] = (
        f"**Ranking of the faithful features** (top {K}, `ember2024_drift.json`; 200 bootstrap resamples):"
        + nl + nl + nl.join(table) + nl + nl +
        f"{len(stable)} of the {K} are in the top {K} in at least 95 % of the resamples. The top {K} is "
        f"robust to the binning and to the dominant family: it overlaps the primary list in {ovtxt}; the "
        f"last control drops {f.code(fam['family'])} ({100 * fam['share_of_2018_test_malware']:.0f} % of "
        f"the 2018 test malware, {100 * fam['share_of_2024_test_malware']:.0f} % of 2024's). {len(core)} "
        f"features are in every variant's top {K}: {', '.join(f.code(c) for c in core)}. Benign-side "
        f"shifts (signing size, DLL share) read as collection and selection artifacts, both-class shifts "
        f"(section virtual-size ratio, import count, OS and linker versions, size) as toolchain change; "
        f"that reading is a hypothesis, not a measurement.")
    v["RANKTEXT"] = (f"Among faithful features the drift-weighted top {K} is " + ", ".join(
        f"{f.code(x['feature'])} ({x['drift_weight']:.2f})" for x in top) +
        f" (weights; {len(stable)} of {K} are in the top {K} in at least 95{f.pc} of 200 bootstrap resamples). "
        f"{len(core)} features stay in the top {K} under decile and pooled-quantile binning and without "
        f"the {f.code(fam['family'])} family: {', '.join(f.code(c) for c in core)}.")
    v["RANKSUMMARY"] = (f"benign-side selection shifts (signing size, DLL share) and both-class toolchain shifts "
                        f"(section virtual-size ratio, import count, OS and linker versions, size); "
                        f"{len(core)} of the top {K} survive every binning and family control")

    # ---- removal ablation (bench_drift_parity.py)
    ab = par["faithful_ablation"]
    gm = ab["group_matched_random"]
    n = gm["n_draws"]
    sm = gm["summary"]
    s24, s18, t24 = sm["ember2024_test:roc_auc"], sm["ember2018_test:roc_auc"], sm["ember2024_test:tpr_at_fpr_1pct"]
    a24 = ab["ablated_minus_full"]["ember2024_test"]["roc_auc"]
    a18 = ab["ablated_minus_full"]["ember2018_test"]["roc_auc"]
    b24 = ab["ablated_minus_full"]["ember2024_test"]["tpr_at_fpr_1pct"]
    v["ABLSECTION"] = (
        f"Retraining the 2018 model ({par['training_rows']:,} rows, 3 seeds) without the faithful top {K} changes "
        f"2024-test AUC by {f.pci(*_pli(a24), sign=True)}, 2024-test TPR @ 1 % FPR by "
        f"{f.ptci(*_pli(b24), sign=True)} pt and 2018-test AUC by {f.pci(*_pli(a18), sign=True)} (paired "
        f"bootstrap). It does not help on 2024. Against {n} group-matched random removals of {K} faithful "
        f"features, each compared with the full and top-{K} models of the same seed (Monte Carlo p that the "
        f"top-{K} removal is at least as damaging as chance): on 2024 AUC it is ordinary "
        f"({s24['n_draws_worse_than_topk']} of {n} draws hurt more; random mean {f.num(s24['mean'], sign=True)}, "
        f"2.5-97.5 % of draws {f.ci(s24['p2.5'], s24['p97.5'], sign=True)}; p = {s24['mc_p_topk_more_damaging']:.2f}), "
        f"while on 2024 TPR @ 1 % FPR ({t24['n_draws_worse_than_topk']} of {n}; p = "
        f"{t24['mc_p_topk_more_damaging']:.2f}) and on 2018 AUC ({s18['n_draws_worse_than_topk']} of {n}; p = "
        f"{s18['mc_p_topk_more_damaging']:.2f}) it hurts more than any random draw: the ranked features carry "
        f"signal in both periods, and dropping them does not recover robustness "
        f"(`ember2024_drift_parity.json`, GitHub Actions [run {par['provenance'].get('github_run_id', 'local')}]"
        f"({par['provenance'].get('github_run_url', '')}), job `parity`).")
    v["ABLTEXT"] = (
        f"Retraining without the faithful top {K} changes 2024 AUC by {f.pci(*_pli(a24), sign=True)} and 2018 AUC by "
        f"{f.pci(*_pli(a18), sign=True)}; against {n} seed- and group-matched random removals it is ordinary on "
        f"2024 AUC ({s24['n_draws_worse_than_topk']} of {n} draws hurt more, Monte Carlo "
        f"$p = {s24['mc_p_topk_more_damaging']:.2f}$) but more damaging than every draw on 2018 AUC and on 2024 "
        f"TPR at 1{f.pc} FPR ($p = {s18['mc_p_topk_more_damaging']:.2f}$), so removal does not recover robustness.")

    # ---- oracle alignment (bench_drift_align.py)
    g = al["groups"]
    base = al["baseline"]
    tkey = f"faithful_top{K}"
    rs = al["random_draws_summary"]
    drift24 = drift["matrix"]["ember2018->ember2024_test"]["roc_auc"]["point"]
    drift18 = drift["matrix"]["ember2018->ember2018_test"]["roc_auc"]["point"]

    def dauc(name: str) -> str:
        e = g[name]
        ci = e.get("aligned_minus_original_ci", {}).get("roc_auc")
        s = f.num(e["aligned_minus_original"]["roc_auc"], sign=True)
        return s + (f" ({f.ci(ci['lo'], ci['hi'], sign=True)})" if ci else "")

    def verdict(name: str) -> str:
        e = g[name]
        ci = e.get("aligned_minus_original_ci", {}).get("roc_auc")
        p = e["aligned_minus_original"]["roc_auc"]
        lo, hi = (ci["lo"], ci["hi"]) if ci else (p, p)
        if lo > 0:
            return f"recovers {100 * e['share_of_auc_drop_recovered']:.0f}{f.pc} of the AUC drop ({dauc(name)} AUC)"
        if hi < 0:
            return (f"does not recover the drop but lowers 2024 AUC further, by {f.num(-p)} "
                    f"({f.num(-hi)}{f.dash}{f.num(-lo)}), {100 * -e['share_of_auc_drop_recovered']:.0f}{f.pc} "
                    f"of the drop's size")
        return f"changes 2024 AUC by {dauc(name)}, no detectable recovery"

    singles = [x for x in g if x.startswith("feature:") and x != "feature:n_embedded_mz"]
    best = max(singles, key=lambda x: g[x]["aligned_minus_original"]["roc_auc"])
    worst = min(singles, key=lambda x: g[x]["aligned_minus_original"]["roc_auc"])
    n_up = sum(1 for x in singles if g[x].get("aligned_minus_original_ci", {}).get("roc_auc", {}).get("lo", -1) > 0)
    run = al["provenance"].get("github_run_url", "")
    rid = str(al["provenance"].get("github_run_id", "local"))
    v["ALIGNRUN"], v["ALIGNRUNID"] = run, rid
    nbetter = rs["n_draws_recovering_at_least_topk"]  # random sets with a 2024 AUC at least the top-k's
    v["ALIGNSUMMARY"] = verdict(tkey)
    v["ALIGNSECTION"] = (
        f"An oracle intervention on the frozen 2018 models (3 seeds): per class, 2024 test values of a feature "
        f"group are quantile-mapped onto the 2018 test marginal (within-class ranks kept; it uses the labels, "
        f"so it is an analysis tool, not a correction), and the 2024 test is re-scored (paired bootstrap, "
        f"{al['bootstrap_resamples']:,} resamples pooled over seeds). The models were retrained in the Actions job "
        f"with `bench_drift.py`'s recipe and score {base['ember2018_test']['roc_auc']:.4f} on 2018 and "
        f"{base['ember2024_test']['roc_auc']:.4f} on 2024 (the committed `bench_drift.py` models: "
        f"{drift18:.4f} and {drift24:.4f}). Change in 2024 AUC after alignment:\n\n"
        "| Aligned group | Features | Δ AUC on 2024 (95 % CI) | Share of the 2018 → 2024 drop |\n"
        "| --- | --- | --- | --- |\n"
        + "".join(
            f"| {label} | {g[k2]['n_features']} | {dauc(k2)} | "
            f"{f.num(100 * g[k2]['share_of_auc_drop_recovered'], 0, True)} % |\n"
            for k2, label in [(tkey, f"faithful top {K}"), ("all_91", "all 91 features"),
                              ("faithful_all", "all faithful features"),
                              ("non_faithful_redefined_or_proxy", "redefined and proxy features"),
                              (best, f"best single top-{K} feature, `{best.split(':', 1)[1]}`"),
                              (worst, f"worst single top-{K} feature, `{worst.split(':', 1)[1]}`"),
                              ("feature:n_embedded_mz", "`n_embedded_mz` alone")])
        + f"\n**(negative result)** Aligning the ranked features {verdict(tkey)}; "
        f"{nbetter} of {rs['n_draws']} group-matched random sets of {K} faithful features end with at least the "
        f"2024 AUC of the top {K} (mean {f.num(rs['mean_dauc'], sign=True)}, 2.5-97.5 % of draws "
        f"{f.ci(rs['p2.5'], rs['p97.5'], sign=True)}; Monte Carlo p = {rs['mc_p_topk_recovers_more']:.2f} for "
        f"\"the top {K} recovers more\"). Only {n_up} of the {K} single features raise 2024 AUC when aligned "
        f"alone. Marginal alignment keeps the 2024 dependence between features, so the aligned rows are "
        f"combinations the 2018 models were not trained on: the shift is not a marginal-only one, and the "
        f"ranking does not identify features whose 2018 marginals would restore the model. GitHub Actions "
        f"[run {rid}]({run}) (`.github/workflows/drift-heavy.yml`, job `align`), "
        f"`results/ember2024_drift_align.json`.")
    v["ALIGNTEXT"] = (
        f"Giving the faithful top {K} their 2018 class-conditional marginals on the 2024 test set (an oracle "
        f"quantile mapping that uses the labels) {verdict(tkey)}; all 91 features: {dauc('all_91')} AUC; "
        f"{nbetter} of {rs['n_draws']} group-matched random sets of {K} end at least as high as the top {K} "
        f"(Monte Carlo $p = {rs['mc_p_topk_recovers_more']:.2f}$ for the top {K} recovering more). The shift "
        f"is not marginal-only.")
    return v


def render(text: str, vals: dict[str, str], where: str) -> str:
    missing = sorted({m for m in TOKEN.findall(text) if m not in vals})
    if missing:
        raise SystemExit(f"{where}: unknown token(s) {missing}")
    out = TOKEN.sub(lambda m: vals[m.group(1)], text)
    left = LEFTOVER.findall(out)
    if left:
        raise SystemExit(f"{where}: unresolved {left}")
    return out


def tracked_leftovers() -> list[str]:
    files = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True, check=True)
    bad = []
    for name in files.stdout.splitlines():
        if name.startswith("templates/") or name == "scripts/render_results.py" or name.startswith("tests/"):
            continue
        p = REPO / name
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            t = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(t.splitlines(), 1):
            if LEFTOVER.search(line):
                bad.append(f"{name}:{i}: {line.strip()[:100]}")
    return bad


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if a rendered file is stale or a token is left")
    a = ap.parse_args()
    md, tex = values(F(False)), values(F(True))
    stale = []
    for t in sorted(p for p in TEMPLATES.rglob("*") if p.is_file()):
        rel = t.relative_to(TEMPLATES)
        out = render(t.read_text(encoding="utf-8").replace("\r\n", "\n"),tex if t.suffix == ".tex" else md, str(rel))
        dest = REPO / rel
        cur = dest.read_text(encoding="utf-8").replace("\r\n", "\n") if dest.exists() else None
        if cur != out:
            if a.check:
                stale.append(str(rel))
            else:
                dest.write_text(out, encoding="utf-8", newline="\n")
                print(f"rendered {rel}")
    left = tracked_leftovers()
    if stale:
        print("stale rendered files (run python scripts/render_results.py):", *stale, sep="\n  ")
    if left:
        print("unresolved @@ tokens:", *left, sep="\n  ")
    if a.check and (stale or left):
        sys.exit(1)
    if not a.check and left:
        sys.exit(1)


if __name__ == "__main__":
    main()
