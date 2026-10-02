#!/usr/bin/env python
"""Adversarial-robustness benchmark (feature-space simulation of functionality-preserving edits).

Takes the out-of-time EMBER 2018 test malware (deterministic 10 % raw sample) that each model
*detects* at its validation-calibrated 1 %-FPR threshold, applies classic evasions that do not
change program behaviour, recomputes the features, and reports the evasion rate:

  overlay   append a whole benign PE's bytes as overlay (byte/string statistics shift)
  section   add a new benign-content data section (+ byte statistics)
  imports   import-table padding with a benign donor's imports
  header    copy a benign donor's header fields (timestamp, linker/OS versions, dll characteristics)
  all       all of the above

Edits are simulated on the EMBER raw-feature dict (as in feature-space attack studies), not by
rewriting binaries -- so this is an *upper bound on what a naive attacker achieves cheaply*, and
exactly the evasions the spec lists. The VITRINE triage row adds the capability floor: a sample
stays flagged (>= SUSPICIOUS) if a high-risk capability rule fires, whatever the score says.

    python scripts/bench_adversarial.py --data D:/.../vitrine
"""
from __future__ import annotations

import argparse
import copy

import numpy as np
from _common import data_dir, dump, iter_jsonl_gz, load_split, threshold_for_fpr

from vitrine.ember import vectorize_many
from vitrine.features import FEATURE_NAMES, vector_raw
from vitrine.gbdt import GBDTVerdictModel


def _add_bytes(r: dict, d: dict) -> None:
    """Append donor d's bytes (its whole file) to r: update every byte-level statistic."""
    r["histogram"] = [a + b for a, b in zip(r["histogram"], d["histogram"])]
    r["byteentropy"] = [a + b for a, b in zip(r["byteentropy"], d["byteentropy"])]
    s, t = r["strings"], d["strings"]
    n = s["numstrings"] + t["numstrings"]
    s["avlength"] = (s["avlength"] * s["numstrings"] + t["avlength"] * t["numstrings"]) / max(n, 1)
    s["numstrings"] = n
    s["printabledist"] = [a + b for a, b in zip(s["printabledist"], t["printabledist"])]
    s["printables"] += t["printables"]
    p = np.asarray(s["printabledist"], dtype=float) / max(s["printables"], 1)
    s["entropy"] = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    for k in ("paths", "urls", "registry", "MZ"):
        s[k] += t[k]
    r["general"]["size"] += d["general"]["size"]


def perturb(r: dict, d: dict, kind: str) -> dict:
    r = copy.deepcopy(r)
    if kind in ("overlay", "all"):
        _add_bytes(r, d)
    if kind in ("section", "all"):
        _add_bytes(r, d)
        sz = d["general"]["size"]
        ent = max((s["entropy"] for s in d["section"]["sections"]), default=5.0)
        r["section"]["sections"].append({"name": ".rdata", "size": (sz + 511) // 512 * 512, "entropy": min(ent, 6.5),
                                         "vsize": sz, "props": ["CNT_INITIALIZED_DATA", "MEM_READ"]})
        r["general"]["vsize"] += (sz + 4095) // 4096 * 4096
    if kind in ("imports", "all"):
        for dll, fs in d["imports"].items():
            cur = r["imports"].setdefault(dll, [])
            cur.extend(f for f in fs if f not in cur)
        r["general"]["imports"] = sum(len(v) for v in r["imports"].values())
    if kind in ("header", "all"):
        r["header"]["coff"]["timestamp"] = d["header"]["coff"]["timestamp"]
        for k in ("dll_characteristics", "major_linker_version", "minor_linker_version",
                  "major_operating_system_version", "minor_operating_system_version",
                  "major_image_version", "minor_image_version"):
            r["header"]["optional"][k] = copy.deepcopy(d["header"]["optional"][k])
        r["general"]["has_debug"] = d["general"]["has_debug"]
    return r


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--draws", type=int, default=3, help="independent donor draws per perturbation")
    a = ap.parse_args()
    data = data_dir(a.data)
    md = data / "models"
    rng = np.random.default_rng(0)

    mal, ben = [], []
    for r in iter_jsonl_gz(data / "processed" / "test_raw_sample.jsonl.gz"):
        (mal if r["label"] == 1 else ben).append(r)
    mal = [mal[i] for i in rng.choice(len(mal), min(a.n, len(mal)), replace=False)]
    # donors: signed, GUI, import-rich benign programs (what an attacker would borrow from)
    donors = [b for b in ben if b["general"]["imports"] >= 50 and b["general"]["size"] < 4_000_000] or ben
    print(f"malware={len(mal)} donors={len(donors)}")

    _, _, ytr, mtr = load_split(data, "train", vectors=False)
    val = np.asarray([m == "2018-10" for m in mtr["appeared"]])
    yv = ytr[val]

    import lightgbm as lgb

    xgbm = GBDTVerdictModel.load(md / "vitrine_xgb.json")
    models = {"vitrine_xgb": ("F", xgbm.score_many, xgbm.thresholds["fpr_1pct"])}
    for name in ("lgbm_ember_paper", "lgbm_ember_2018"):
        if (md / f"{name}.txt").exists():
            bst = lgb.Booster(model_file=str(md / f"{name}.txt"))
            thr = threshold_for_fpr(yv, np.load(md / f"{name}_val_scores.npy"), 0.01)
            models[name] = ("X", bst.predict, thr)

    results = {"n_malware": len(mal), "threshold": "validation-calibrated 1% FPR (score models)"}
    hr = FEATURE_NAMES.index("high_risk_capabilities")
    from _stats import mcnemar_p, wilson

    # triage operating point: score >= 1 % threshold OR capability floor; measure its benign FPR on the
    # test set and give the score-only model the same FPR budget for a fair comparison
    _, Fte, yte, _ = load_split(data, "test", vectors=False)
    s_te = np.load(md / "vitrine_xgb_test_scores.npy")
    thr1 = xgbm.thresholds["fpr_1pct"]
    tri_fpr = float(((s_te[yte == 0] >= thr1) | (Fte[yte == 0, hr] > 0)).mean())
    thr_matched = threshold_for_fpr(yte, s_te, tri_fpr)
    results["triage_benign_fpr_test"] = tri_fpr
    results["xgb_threshold_at_triage_fpr"] = thr_matched
    donor_hr = np.asarray([vector_raw(d)[hr] > 0 for d in donors])
    clean = [d for d, h in zip(donors, donor_hr) if not h]
    pools = {"any_benign_donor": donors, "donors_without_high_risk_capability": clean}
    results["donors"] = {"n": len(donors), "with_high_risk_capability": float(donor_hr.mean())}
    results["draws"] = a.draws
    results["pools"] = {}
    kinds = ["none", "overlay", "section", "imports", "header", "all"]
    names = [*models, "vitrine_triage", "xgb_at_triage_fpr"]
    for pool, dl in pools.items():
        rows = []
        base, floor0 = {}, None
        for kind in kinds:
            acc = {n: [] for n in names}
            extra = {"floor_only": [], "floor_switched_on_by_donor": []}
            for draw in range(1 if kind == "none" else a.draws):
                rr = np.random.default_rng(1000 * draw + kinds.index(kind))
                raws = mal if kind == "none" else [perturb(r, dl[rr.integers(len(dl))], kind) for r in mal]
                F = np.asarray([vector_raw(r) for r in raws], dtype=np.float32)
                X = vectorize_many(raws)
                dets = {}
                for name, (inp, fn, thr) in models.items():
                    dets[name] = fn(F if inp == "F" else X) >= thr
                sx = xgbm.score_many(F)
                fl = F[:, hr] > 0
                dets["vitrine_triage"] = (sx >= thr1) | fl
                dets["xgb_at_triage_fpr"] = sx >= thr_matched
                if kind == "none":
                    base, floor0 = dets, fl
                for n_ in names:
                    acc[n_].append(dets[n_])
                fo = dets["vitrine_triage"] & ~(sx >= thr1)
                extra["floor_only"].append(fo.mean())
                extra["floor_switched_on_by_donor"].append((fo & ~floor0).mean())
            row = {"perturbation": kind}
            for n_ in names:
                k = int(np.mean([d.sum() for d in acc[n_]]).round())
                row[n_] = {"detection_rate": float(np.mean([d.mean() for d in acc[n_]])),
                           "draw_rates": [float(d.mean()) for d in acc[n_]],
                           "ci95_wilson_draw0": wilson(int(acc[n_][0].sum()), len(mal)),
                           "evasion_rate_of_detected": float(np.mean([(base[n_] & ~d).sum() / max(base[n_].sum(), 1)
                                                                      for d in acc[n_]])),
                           "mean_detected": k}
            row["floor_only_rate"] = float(np.mean(extra["floor_only"]))
            row["floor_switched_on_by_donor_rate"] = float(np.mean(extra["floor_switched_on_by_donor"]))
            if "lgbm_ember_2018" in acc:
                row["mcnemar_p_xgb_vs_lgbm2018_draw0"] = mcnemar_p(acc["vitrine_xgb"][0], acc["lgbm_ember_2018"][0])
            row["mcnemar_p_triage_vs_xgb_matched_draw0"] = mcnemar_p(acc["vitrine_triage"][0],
                                                                     acc["xgb_at_triage_fpr"][0])
            print(pool, kind, {k_: round(v["detection_rate"], 4) for k_, v in row.items() if isinstance(v, dict)},
                  "floor-only", round(row["floor_only_rate"], 4),
                  "switched", round(row["floor_switched_on_by_donor_rate"], 4), flush=True)
            rows.append(row)
        results["pools"][pool] = rows
    results["rows"] = results["pools"]["any_benign_donor"]
    results["capability_floor_benign_flag_rate"] = float((Fte[yte == 0, hr] > 0).mean())
    results["capability_floor_malware_flag_rate"] = float((Fte[yte == 1, hr] > 0).mean())
    print("triage benign FPR", tri_fpr, "floor benign flag rate", results["capability_floor_benign_flag_rate"])
    dump("adversarial.json", results)


if __name__ == "__main__":
    main()
