#!/usr/bin/env python
"""Parser-feature parity: EMBER v2 (elastic/ember + LIEF 0.9.0) vs EMBER v3 (thrember + pefile) on the
SAME benign PE files.

EMBER 2018 records were extracted with LIEF 0.9.0 and EMBER2024 records with pefile (thrember), so a
2018 -> 2024 shift in a parser-based feature can come from the files or from the extractor. This
script runs both extractors on one benign corpus and measures, per VITRINE named feature, how far the
two extractors disagree on identical files: exact agreement, Spearman rho, and the PSI between the two
extractors' values (bootstrap CI over files). The extractor-only PSI is then set against the
cross-dataset benign PSI in ``ember2024_drift.json``.

Run by ``.github/workflows/extractor-parity.yml`` inside a GitHub Actions runner on benign Windows DLL/PYD
files unpacked from PyPI wheels (open-source builds; parsed, never executed, never committed):

    # Python 3.7 + LIEF 0.9.0 (conda-forge py-lief=0.9.0), elastic/ember checkout
    python scripts/parity_extractors.py v2 --files corpus.txt --ember-src ember_src --out v2.jsonl
    python scripts/parity_extractors.py corpus --wheels wheels --out corpus --list corpus.txt
    # Python >= 3.10, thrember checkout (FutureComputing4AI/EMBER2024)
    python scripts/parity_extractors.py v3 --files corpus.txt --thrember EMBER2024/src --out v3.jsonl
    python scripts/parity_extractors.py compare --v2 v2.jsonl --v3 v3.jsonl --corpus-note "..."

The ``v2`` mode is kept Python 3.7 compatible (it runs in the LIEF 0.9 environment).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path


def _paths(listfile):
    with open(listfile, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]


def _extract(paths, fn, out):
    ok = bad = 0
    with open(out, "w", encoding="utf-8") as w:
        for p in paths:
            b = Path(p).read_bytes()
            rec = {"path": p, "sha256": hashlib.sha256(b).hexdigest()}
            try:
                rec["raw"] = fn(b)
                ok += 1
            except Exception as e:  # a parser failure is data here, not a crash
                rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
                bad += 1
            w.write(json.dumps(rec, default=str) + "\n")
    print(f"extracted {ok}, failed {bad} -> {out}", flush=True)


def cmd_corpus(a):
    """Unpack PE members (.dll/.pyd/.exe, at most ``--max-mb``) of every downloaded wheel; list them."""
    import zipfile

    out, files, wheels = Path(a.out), [], []
    for whl in sorted(Path(a.wheels).rglob("*.whl")):
        wheels.append(whl.name)
        with zipfile.ZipFile(whl) as z:
            for m in z.infolist():
                if m.filename.lower().endswith((".dll", ".pyd", ".exe")) and 0 < m.file_size <= a.max_mb << 20:
                    data = z.read(m)
                    if data[:2] != b"MZ":
                        continue
                    dst = out / whl.stem / Path(m.filename).name
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(data)
                    files.append(str(dst))
    Path(a.list).write_text("\n".join(files) + "\n", encoding="utf-8")
    Path(a.list).with_suffix(".wheels.json").write_text(json.dumps(wheels, indent=1), encoding="utf-8")
    print(f"{len(files)} PE files from {len(wheels)} wheels", flush=True)


def cmd_v2(a):
    spec = importlib.util.spec_from_file_location("ember_features", str(Path(a.ember_src) / "ember" / "features.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import lief

    print("lief", lief.__version__, flush=True)
    ex = mod.PEFeatureExtractor(feature_version=2, print_feature_warning=True)
    _extract(_paths(a.files), ex.raw_features, a.out)


def cmd_v3(a):
    import types

    # thrember imports signify for its Authenticode block, which no VITRINE feature reads; stub it and drop
    # that block (as prepare_ember2024.py does) instead of pinning an old signify/oscrypto stack
    sig, auth = types.ModuleType("signify"), types.ModuleType("signify.authenticode")
    auth.SignedPEFile = object
    sig.authenticode = auth
    sys.modules.setdefault("signify", sig)
    sys.modules.setdefault("signify.authenticode", auth)
    src = str(Path(a.thrember) / "thrember" / "features.py")
    spec = importlib.util.spec_from_file_location("thrember_features", src)
    tf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tf)
    ex = tf.PEFeatureExtractor()
    ex.features = [f for f in ex.features if type(f).__name__ != "AuthenticodeSignature"]
    _extract(_paths(a.files), ex.raw_features, a.out)


def cmd_compare(a):
    import numpy as np
    from _common import RESULTS, dump
    from _drift_defs import FAITHFUL, feature_class
    from _stats import psi, total_variation
    from scipy.stats import spearmanr

    from vitrine.ember3 import to_v2
    from vitrine.features import FEATURE_NAMES, featurize_raw

    def load(p):
        with open(p, encoding="utf-8") as f:
            return {r["sha256"]: r for r in map(json.loads, f)}

    t0 = time.time()
    v2, v3 = load(a.v2), load(a.v3)
    common = sorted(set(v2) & set(v3))
    both = [h for h in common if "raw" in v2[h] and "raw" in v3[h]]
    A, B = [], []
    for h in both:
        A.append([featurize_raw(v2[h]["raw"])[n] for n in FEATURE_NAMES])
        B.append([featurize_raw(to_v2(v3[h]["raw"]))[n] for n in FEATURE_NAMES])
    A, B = np.asarray(A, float), np.asarray(B, float)
    rank = json.loads((RESULTS / "ember2024_drift.json").read_text(encoding="utf-8")).get("drift_ranking", {})
    drift = {f["feature"]: f for f in rank.get("features", [])}
    rng = np.random.default_rng(21)
    idx = rng.integers(0, len(both), (a.boot, len(both)))
    feats = []
    for j, n in enumerate(FEATURE_NAMES):
        x, y = A[:, j], B[:, j]
        rho = spearmanr(x, y).statistic if x.std() and y.std() else None
        bp = [psi(x[i], y[i]) for i in idx]
        d = drift.get(n, {})
        e = {"feature": n, "class": feature_class(n), "faithful": feature_class(n) in FAITHFUL,
             "exact_agreement": float((x == y).mean()),
             "close_agreement_1pct": float((np.abs(x - y) <= 0.01 * np.maximum(np.abs(x), 1e-9)).mean()),
             "mean_v2_lief": float(x.mean()), "mean_v3_pefile": float(y.mean()),
             "spearman_rho": None if rho is None else float(rho),
             "total_variation": total_variation(x, y) if np.unique(np.r_[x, y]).size <= 64 else None,
             "psi_extractor_same_files": psi(x, y),
             "psi_extractor_ci95": [float(v) for v in np.percentile(bp, [2.5, 97.5])],
             "psi_benign_2018_vs_2024": d.get("psi_benign"), "rank_faithful": d.get("rank_faithful")}
        if d.get("psi_benign"):
            e["extractor_psi_over_cross_dataset_benign_psi"] = e["psi_extractor_same_files"] / d["psi_benign"]
        feats.append(e)
    faithful = sorted((f for f in feats if f["faithful"] and f["rank_faithful"]), key=lambda f: f["rank_faithful"])
    top = faithful[: a.k]
    res = {
        "description": __doc__.split("\n\n")[0],
        "corpus": a.corpus_note, "n_files_listed": len(set(v2) | set(v3)), "n_files_both_parsed": len(both),
        "wheels": json.loads(Path(a.wheels_json).read_text(encoding="utf-8")) if a.wheels_json else None,
        "pe32_share": float(np.mean([v2[h]["raw"]["header"]["optional"]["magic"] == "PE32" for h in both]))
        if both else None,
        "n_v2_errors": sum("error" in r for r in v2.values()), "n_v3_errors": sum("error" in r for r in v3.values()),
        "extractors": {"v2": "elastic/ember features.py (feature_version=2) + LIEF 0.9.0",
                       "v3": "thrember features.py (EMBER2024) + pefile, translated by vitrine.ember3.to_v2"},
        "bootstrap_resamples_over_files": a.boot,
        "summary": {
            "faithful_features": sum(f["faithful"] for f in feats),
            "faithful_exact_agreement_median": float(np.median([f["exact_agreement"] for f in feats if f["faithful"]])),
            "faithful_top_k": [f["feature"] for f in top],
            "faithful_top_k_extractor_psi": {f["feature"]: f["psi_extractor_same_files"] for f in top},
            "faithful_top_k_cross_dataset_benign_psi": {f["feature"]: f["psi_benign_2018_vs_2024"] for f in top},
            "top_k_where_extractor_psi_exceeds_half_of_benign_shift": [
                f["feature"] for f in top if (f.get("extractor_psi_over_cross_dataset_benign_psi") or 0) > 0.5]},
        "features": feats,
        "runtime_seconds": round(time.time() - t0),
    }
    dump("extractor_parity.json", res)
    print(json.dumps(res["summary"], indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    s2 = sub.add_parser("v2", help="LIEF 0.9 / elastic/ember raw features")
    s2.add_argument("--files", required=True)
    s2.add_argument("--ember-src", required=True)
    s2.add_argument("--out", required=True)
    s3 = sub.add_parser("v3", help="pefile / thrember raw features")
    s3.add_argument("--files", required=True)
    s3.add_argument("--thrember", required=True)
    s3.add_argument("--out", required=True)
    c = sub.add_parser("compare", help="named-feature parity -> results/extractor_parity.json")
    c.add_argument("--v2", required=True)
    c.add_argument("--v3", required=True)
    c.add_argument("--boot", type=int, default=1000)
    c.add_argument("--k", type=int, default=10)
    c.add_argument("--corpus-note", default="")
    c.add_argument("--wheels-json", help="wheel list written by the corpus step")
    k = sub.add_parser("corpus", help="unpack PE files from downloaded wheels")
    k.add_argument("--wheels", required=True)
    k.add_argument("--out", required=True)
    k.add_argument("--list", required=True)
    k.add_argument("--max-mb", type=int, default=8)
    a = ap.parse_args()
    {"v2": cmd_v2, "v3": cmd_v3, "compare": cmd_compare, "corpus": cmd_corpus}[a.mode](a)


if __name__ == "__main__":
    main()
