#!/usr/bin/env python
"""Is the EMBER 2018 -> EMBER2024 drift attribution confounded by the v2 <-> v3 schema translation?

The cross-dataset PSI in ``ember2024_drift.json`` compares a 2018 value computed by EMBER v2 with a
2024 value computed by EMBER v3 (thrember) and translated by :mod:`vitrine.ember3`. Where the two
extractors define a feature differently, PSI measures the definition change, not the files.

1. Definition audit: every one of the 91 named features is put in one class
     * ``redefined``  -- v3 has no equivalent, the nearest counter is used (string IOC counters);
     * ``proxy``      -- same concept, derived from a different field (general flags, vsize);
     * ``parser``     -- same definition, different PE parser (LIEF 0.9 vs pefile in thrember);
     * ``byte_level`` -- same definition on raw bytes, no parser involved (histograms, strings).
2. Parity on overlap data: both definitions of each ``redefined`` counter are computed on the same
   benign files (a deterministic sample of local ``C:/Windows/System32`` PEs; regexes copied from
   elastic/ember v2 and thrember v3). Reported: Spearman rho, exact agreement, and the PSI between the
   two definitions on identical files -- PSI that a definition change alone produces.
3. Attribution restricted to faithful features (``parser`` + ``byte_level``) with every feature
   tagged as shifting in both classes, benign only, or malicious only (PSI >= 0.25 / < 0.1).
4. Ablation of the top-10 faithful drift features on the 2018 model (3 seeds) versus 20 random
   draws of 10 faithful features matched by feature group (1 seed each); in-period (2018) cost and
   cross-time (2024) change reported side by side. To fit the shared laptop, all models are trained
   on the 99,144-row 2018 subsample used for ``ember2018_sub`` in ``bench_drift.py``.

    python scripts/bench_drift_parity.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np
from _common import RESULTS, data_dir, dump
from _stats import paired_bootstrap_diff, psi
from bench_drift import load18, load24, score, train

from vitrine.features import FEATURE_NAMES

REDEFINED = {
    "n_embedded_mz": "v2: count of b'MZ' anywhere in the file; v3: strings containing '!This program ' (dos_msg)",
    "n_paths": "v2: 'c:\\' case-insensitive anywhere; v3: strings matching r'\\bC:/' (forward slash, case-sensitive)",
    "n_registry": "v2: 'HKEY_' anywhere; v3: strings matching r'\\b(?:KHEY_|KHLM|HKCU)'",
    "n_urls": "v2: 'http(s)://' anywhere; v3: strings matching the thrember url regex (also ftp)",
}
PROXY = {
    "has_signature": "v2 LIEF flag; v3 SECURITY data-directory size > 0",
    "has_debug": "v2 LIEF has_debug; v3 DEBUG data-directory size > 0",
    "has_tls": "v2 LIEF has_tls; v3 TLS data-directory size > 0",
    "has_relocations": "v2 LIEF flag; v3 BASERELOC data-directory size > 0",
    "has_resources": "v2 LIEF flag; v3 RESOURCE data-directory size > 0",
    "vsize_to_size": "v2 LIEF virtual_size; v3 optional.sizeof_image",
}
BYTE_LEVEL = {"size_kb", "file_entropy", "high_entropy_window_frac", "n_strings", "avg_string_len",
              "string_entropy", "printable_ratio"}


def feature_class(n: str) -> str:
    if n in REDEFINED:
        return "redefined"
    if n in PROXY:
        return "proxy"
    if n in BYTE_LEVEL:
        return "byte_level"
    return "parser"


def feature_group(n: str) -> str:
    if n.startswith("cap:") or n in ("capability_count", "high_risk_capabilities"):
        return "capability"
    if n.startswith("api_") or n in ("n_dlls", "n_imports", "n_ordinal_imports", "n_exports", "imports_tiny"):
        return "imports"
    if "section" in n or n.startswith("entry_") or n == "max_vsize_ratio":
        return "sections"
    if n in BYTE_LEVEL or n == "unaccounted_ratio":
        return "bytes_strings"
    return "header"


# v2 (elastic/ember features.py, as in vitrine/ember.py) and v3 (thrember features.py) definitions
_ALL = re.compile(rb"[\x20-\x7f]{5,}")
V2 = {"n_embedded_mz": re.compile(rb"MZ"), "n_paths": re.compile(rb"c:\\", re.I),
      "n_registry": re.compile(rb"HKEY_"), "n_urls": re.compile(rb"https?://", re.I)}
V3 = {"n_embedded_mz": re.compile("!This program "), "n_paths": re.compile("\\bC:/"),
      "n_registry": re.compile("\\b(?:KHEY_|KHLM|HKCU)"),
      "n_urls": re.compile("\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+")}


def parity(root: Path, n: int) -> dict:
    from scipy.stats import spearmanr

    files = sorted(p for p in root.glob("*") if p.suffix.lower() in (".dll", ".exe", ".sys") and p.is_file())
    files = [p for p in files if 0 < p.stat().st_size <= 8 << 20][:: max(1, len(files) // n)][:n]
    v2 = {k: [] for k in V2}
    v3 = {k: [] for k in V3}
    used = 0
    for p in files:
        try:
            b = p.read_bytes()
        except OSError:
            continue
        if b[:2] != b"MZ":
            continue
        used += 1
        strs = [s.decode() for s in _ALL.findall(b)]
        for k in V2:
            v2[k].append(len(V2[k].findall(b)))
            v3[k].append(sum(1 for s in strs if V3[k].search(s)))
    out = {"corpus": f"{root} (benign; deterministic every-k-th sample of PE files <= 8 MiB)", "n_files": used}
    for k in V2:
        a, c = np.array(v2[k], float), np.array(v3[k], float)
        rho = spearmanr(a, c).statistic if a.std() and c.std() else float("nan")
        out[k] = {"definition": REDEFINED[k], "v2_mean": float(a.mean()), "v3_mean": float(c.mean()),
                  "v2_median": float(np.median(a)), "v3_median": float(np.median(c)),
                  "exact_agreement": float((a == c).mean()), "spearman_rho": float(rho),
                  "psi_v2_vs_v3_same_files": psi(a, c)}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--system32", default="C:/Windows/System32")
    ap.add_argument("--parity-files", type=int, default=600)
    ap.add_argument("--draws", type=int, default=20)
    ap.add_argument("--boot", type=int, default=500)
    ap.add_argument("--k", type=int, default=10)
    a = ap.parse_args()
    t0 = time.time()
    res = {"description": __doc__.split("\n\n")[0],
           "feature_classes": {n: feature_class(n) for n in FEATURE_NAMES},
           "definitions": {**REDEFINED, **PROXY}}
    s32 = Path(a.system32)
    res["parity_system32"] = parity(s32, a.parity_files) if s32.exists() else {"skipped": "no System32"}
    print(json.dumps(res["parity_system32"], indent=1), flush=True)

    # ---- attribution restricted to faithful features, tagged by class pattern
    drift = json.loads((RESULTS / "ember2024_drift.json").read_text())
    feats = []
    for f in drift["feature_drift"]:
        pb, pm = f["psi_benign"], f["psi_malicious"]
        pattern = ("both_classes" if pb >= 0.25 and pm >= 0.25 else
                   "benign_only" if pb >= 0.25 and pm < 0.1 else
                   "malicious_only" if pm >= 0.25 and pb < 0.1 else
                   "stable" if max(pb, pm) < 0.1 else "mixed")
        feats.append({**f, "class": feature_class(f["feature"]), "group": feature_group(f["feature"]),
                      "shift_pattern": pattern})
    res["all_features_top15"] = [{k: f[k] for k in ("feature", "class", "shift_pattern", "psi_benign",
                                                     "psi_malicious", "drift_weight")} for f in feats[:15]]
    faithful = [f for f in feats if f["class"] in ("parser", "byte_level")]
    res["faithful_attribution"] = [{k: f[k] for k in ("feature", "class", "group", "shift_pattern", "psi_benign",
                                                      "psi_malicious", "mean_abs_shap_2018", "drift_weight")}
                                   for f in faithful[:15]]
    res["faithful_both_class_top"] = [f["feature"] for f in faithful if f["shift_pattern"] == "both_classes"][:a.k]

    # ---- ablation on faithful features vs group-matched random draws
    data = data_dir(a.data)
    d18, d24 = load18(data), load24(data)
    F18, y18, m18 = d18["train"]
    fit18 = m18 != "2018-10"
    rng = np.random.default_rng(0)  # identical subsample to bench_drift.py's ember2018_sub
    fit24n = int((d24["train"][2] <= 47).sum())
    sub = np.sort(rng.choice(np.flatnonzero(fit18), fit24n, replace=False))
    X, y = F18[sub], y18[sub]
    targets = {"ember2018_test": d18["test"][:2], "ember2024_test": d24["test"][:2]}
    seeds = [0, 1, 2]
    allc = list(range(len(FEATURE_NAMES)))
    full = [train(X, y, s) for s in seeds]
    full_s = {t: [score(b, Xt) for b in full] for t, (Xt, _) in targets.items()}
    print(f"full models ({time.time() - t0:.0f}s)", flush=True)

    def ablate(drop: list[int], sd: list[int]) -> dict:
        keep = [j for j in allc if j not in drop]
        ms = [train(X, y, s, keep) for s in sd]
        out = {}
        for t, (Xt, yt) in targets.items():
            s = [score(b, Xt, keep) for b in ms]
            out[t] = paired_bootstrap_diff(yt, s, full_s[t][: len(sd)], a.boot)
        return out

    top = [FEATURE_NAMES.index(f["feature"]) for f in faithful[: a.k]]
    ab = {"dropped": [FEATURE_NAMES[j] for j in top], "seeds": seeds,
          "ablated_minus_full": ablate(top, seeds)}
    print(f"faithful ablation {ab['ablated_minus_full']} ({time.time() - t0:.0f}s)", flush=True)
    # group-matched random draws from the faithful pool (excluding the top-k themselves)
    pool = {}
    for f in faithful[a.k:]:
        pool.setdefault(f["group"], []).append(FEATURE_NAMES.index(f["feature"]))
    need = {}
    for j in top:
        g = feature_group(FEATURE_NAMES[j])
        need[g] = need.get(g, 0) + 1
    rr = np.random.default_rng(11)
    draws = []
    for _ in range(a.draws):
        pick = []
        for g, c in need.items():
            pick += rr.choice(pool[g], min(c, len(pool[g])), replace=False).tolist()
        r = ablate(sorted(pick), [0])
        draws.append({"dropped": [FEATURE_NAMES[j] for j in sorted(pick)],
                      **{t: {m: r[t][m]["mean"] for m in r[t]} for t in r}})
        print(f"draw {len(draws)} ({time.time() - t0:.0f}s)", flush=True)
    summ = {}
    for t in targets:
        for m in ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0.1pct"):
            v = np.array([d[t][m] for d in draws])
            summ[f"{t}:{m}"] = {"mean": float(v.mean()), "p2.5": float(np.percentile(v, 2.5)),
                                "p97.5": float(np.percentile(v, 97.5)),
                                "frac_draws_worse_than_topk": float(
                                    (v < ab["ablated_minus_full"][t][m]["mean"]).mean())}
    ab["group_matched_random"] = {"n_draws": len(draws), "group_counts": need, "summary": summ, "draws": draws}
    res["faithful_ablation"] = ab
    res["training_rows"] = int(sub.size)
    res["threshold_note"] = "ROC-read metrics; no thresholds are calibrated in this script"
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember2024_drift_parity.json", res)


if __name__ == "__main__":
    main()
