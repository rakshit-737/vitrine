#!/usr/bin/env python
"""Real-benign specificity: triage the PE files of a clean Windows install (read-only).

Every file is parsed by VITRINE's dissector (never executed), turned into EMBER raw features,
and scored by each trained model at its validation-calibrated thresholds. Because all of these
files are benign, every MALICIOUS/SUSPICIOUS verdict is a false positive. This also measures the
domain shift between EMBER's LIEF-extracted 2018 training data and 2026-era Windows binaries
parsed by VITRINE's own extractor. Files stay where they are; nothing is copied or committed.

    python scripts/bench_benign.py --data D:/.../vitrine --dir C:/Windows/System32 --limit 4000
"""
from __future__ import annotations

import argparse
import time
from collections import Counter
from pathlib import Path

import numpy as np
from _common import data_dir, dump, load_split, threshold_for_fpr

from vitrine.capabilities import HIGH_RISK_ATTACK_IDS, tag
from vitrine.dissect import PEParseError, dissect, is_packed
from vitrine.ember import raw_from_report, vectorize_many
from vitrine.features import vector_raw
from vitrine.gbdt import GBDTVerdictModel


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--dir", default="C:/Windows/System32")
    ap.add_argument("--limit", type=int, default=4000)
    a = ap.parse_args()
    data = data_dir(a.data)
    md = data / "models"

    files = sorted(p for p in Path(a.dir).iterdir()
                   if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys"})
    rng = np.random.default_rng(0)
    if len(files) > a.limit:
        files = [files[i] for i in sorted(rng.choice(len(files), a.limit, replace=False))]
    raws, caps, packed, errors, sizes = [], [], [], Counter(), []
    t0 = time.time()
    for p in files:
        try:
            b = p.read_bytes()
            rep = dissect(b)
            raw = raw_from_report(rep, b)
        except PEParseError as e:
            errors[str(e).split(" at ")[0]] += 1
            continue
        except OSError:
            errors["unreadable"] += 1
            continue
        raws.append(raw)
        sizes.append(len(b))
        caps.append({c.attack_id for c in tag(rep)})
        packed.append(is_packed(rep))
    dt = time.time() - t0
    print(f"parsed {len(raws)}/{len(files)} in {dt:.0f}s; errors={dict(errors)}")

    F = np.asarray([vector_raw(r) for r in raws], dtype=np.float32)
    X = vectorize_many(raws)
    _, _, ytr, mtr = load_split(data, "train", vectors=False)
    yv = ytr[np.asarray([m == "2018-10" for m in mtr["appeared"]])]

    out = {"corpus": a.dir, "n_files": len(files), "n_parsed": len(raws), "parse_errors": dict(errors),
           "seconds": round(dt, 1), "files_per_second": round(len(raws) / max(dt, 1e-9), 1),
           "median_size_kb": float(np.median(sizes) / 1024) if sizes else 0,
           "packed_rate": float(np.mean(packed)) if packed else 0, "models": {}}
    xgbm = GBDTVerdictModel.load(md / "vitrine_xgb.json")
    s = xgbm.score_many(F)
    out["models"]["vitrine_xgb"] = {
        f"fp_rate_at_val_{t}": float((s >= xgbm.thresholds[k]).mean())
        for t, k in (("1pct", "fpr_1pct"), ("0.1pct", "fpr_0.1pct"))}
    out["models"]["vitrine_xgb"]["mean_score"] = float(s.mean())
    import lightgbm as lgb

    for name in ("lgbm_ember_paper", "lgbm_ember_2018"):
        if not (md / f"{name}.txt").exists():
            continue
        sv = np.load(md / f"{name}_val_scores.npy")
        sc = lgb.Booster(model_file=str(md / f"{name}.txt")).predict(X)
        out["models"][name] = {f"fp_rate_at_val_{t}": float((sc >= threshold_for_fpr(yv, sv, f)).mean())
                               for t, f in (("1pct", 0.01), ("0.1pct", 0.001))}
        out["models"][name]["mean_score"] = float(sc.mean())

    # full triage verdicts (thresholds + capability floor)
    mal = s >= xgbm.thresholds["fpr_0.1pct"]
    sus = (s >= xgbm.thresholds["fpr_1pct"]) & ~mal
    floor = np.asarray([bool(c & HIGH_RISK_ATTACK_IDS) for c in caps]) & ~mal & ~sus
    out["triage"] = {"MALICIOUS": int(mal.sum()), "SUSPICIOUS_by_score": int(sus.sum()),
                     "SUSPICIOUS_by_capability_floor": int(floor.sum()),
                     "BENIGN": int((~mal & ~sus & ~floor).sum())}
    cap_counts = Counter(c for cs in caps for c in cs)
    out["capability_hit_rates"] = {k: round(v / max(len(caps), 1), 4) for k, v in cap_counts.most_common()}
    print(out["models"], out["triage"])
    dump("benign_system32.json", out)


if __name__ == "__main__":
    main()
