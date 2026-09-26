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

    hr = FEATURE_NAMES.index("high_risk_capabilities")
    kinds = ["none", "overlay", "section", "imports", "header", "all"]
    results = {"n_malware": len(mal), "threshold": "validation-calibrated 1% FPR", "rows": []}
    det_base = {}
    for kind in kinds:
        raws = mal if kind == "none" else [perturb(r, donors[rng.integers(len(donors))], kind) for r in mal]
        F = np.asarray([vector_raw(r) for r in raws], dtype=np.float32)
        X = vectorize_many(raws)
        row = {"perturbation": kind}
        for name, (inp, fn, thr) in models.items():
            det = fn(F if inp == "F" else X) >= thr
            if kind == "none":
                det_base[name] = det
            base = det_base[name]
            row[name] = {"detection_rate": float(det.mean()),
                         "evasion_rate_of_detected": float((base & ~det).sum() / max(base.sum(), 1))}
        # VITRINE triage: score OR capability floor
        det = (xgbm.score_many(F) >= xgbm.thresholds["fpr_1pct"]) | (F[:, hr] > 0)
        if kind == "none":
            det_base["vitrine_triage"] = det
        base = det_base["vitrine_triage"]
        row["vitrine_triage"] = {"detection_rate": float(det.mean()),
                                 "evasion_rate_of_detected": float((base & ~det).sum() / max(base.sum(), 1))}
        print(kind, {k: round(v["detection_rate"], 4) for k, v in row.items() if isinstance(v, dict)}, flush=True)
        results["rows"].append(row)

    # the price of the capability floor: benign samples it would flag for review
    _, Fte, yte, _ = load_split(data, "test", vectors=False)
    results["capability_floor_benign_flag_rate"] = float((Fte[yte == 0, hr] > 0).mean())
    results["capability_floor_malware_flag_rate"] = float((Fte[yte == 1, hr] > 0).mean())
    print("floor benign flag rate", results["capability_floor_benign_flag_rate"])
    dump("adversarial.json", results)


if __name__ == "__main__":
    main()
