#!/usr/bin/env python
"""Score the EMBER authors' published EMBER 2018 LightGBM model on the same test rows as VITRINE.

The EMBER 2018 archive ships ``ember2018/ember_model_2018.txt`` (elastic/ember benchmark model:
1,000 trees, lr 0.05, 2,048 leaves, max_depth 15, min_data_in_leaf 50, feature_fraction 0.5,
trained by the authors on *all* labelled Jan-Oct 2018 rows). ``prepare_ember.py`` skips it, so this
script pulls just that tar member out of the bzip2 archive by decompressing blocks from
``--start-block`` onward (block-parallel, see ``_pbz2.py``) until the member is complete.

It is then scored on VITRINE's 2,381-dim vectors of
  * the EMBER 2018 test set (200k, Nov-Dec 2018) -- with bootstrap CIs and a paired comparison
    against the VITRINE XGBoost test scores (``models/vitrine_xgb_test_scores.npy``);
  * the 2018-10 calibration rows (for a validation-calibrated threshold);
  * the EMBER2024 test subsample translated to v2 (``ember2024/processed/test_X2.f32``), if present.

Caveat recorded in the output: VITRINE's clean-room vectorizer hashes the entry-section name as one
token, elastic/ember hashed it per character under old scikit-learn (50 of 2,381 dims differ).

    python scripts/score_published.py --data D:/cyber-portfolio/datasets/vitrine
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import time

import numpy as np
from _common import binary_metrics, data_dir, dump, load_split, threshold_for_fpr
from _pbz2 import block_ranges, decompress_block
from _stats import bootstrap_roc, paired_bootstrap_diff

MEMBER = b"ember2018/ember_model_2018.txt"
ARCHIVE = "ember_dataset_2018_2.tar.bz2"


def extract(data, start_block: int, workers: int):
    out = data / "models" / "ember_model_2018.txt"
    if out.exists():
        return out
    path = data / ARCHIVE
    header, ranges = block_ranges(path)
    buf, size, body = b"", None, None
    with mp.Pool(workers) as pool:
        k = start_block
        while k < len(ranges):
            chunk = pool.map(decompress_block, [(str(path), header, s, e) for s, e in ranges[k : k + workers]])
            k += workers
            buf += b"".join(chunk)
            if size is None:
                i = buf.find(MEMBER + b"\0")
                if i < 0:
                    buf = buf[-1024:]
                    continue
                hdr = buf[i : i + 512]
                size = int(hdr[124:136].strip(b"\0 ") or b"0", 8)
                buf = buf[i + 512 :]
                print(f"found {MEMBER.decode()} ({size:,} bytes) near block {k}", flush=True)
            if len(buf) >= size:
                body = buf[:size]
                break
    if body is None:
        raise SystemExit("member not found after --start-block; lower it")
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(body)
    return out


def predict(bst, X, chunk=5000):
    return np.concatenate([bst.predict(np.asarray(X[i : i + chunk])) for i in range(0, X.shape[0], chunk)])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--start-block", type=int, default=6000, help="first bz2 block to search for the member")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--boot", type=int, default=1000)
    a = ap.parse_args()
    data = data_dir(a.data)
    t0 = time.time()
    mpath = extract(data, a.start_block, a.workers)
    import lightgbm as lgb

    bst = lgb.Booster(model_file=str(mpath))
    print(f"model: {bst.num_trees()} trees, {bst.num_feature()} features ({time.time() - t0:.0f}s)", flush=True)
    Xtr, _, ytr, mtr = load_split(data, "train")
    Xte, _, yte, _ = load_split(data, "test")
    val = np.flatnonzero(np.asarray(mtr["appeared"]) == "2018-10")
    s_val = predict(bst, Xtr[val])
    s_te = predict(bst, Xte)
    np.save(data / "models" / "ember_published_2018_test_scores.npy", s_te)
    print(f"scored test ({time.time() - t0:.0f}s)", flush=True)
    xgb_te = np.load(data / "models" / "vitrine_xgb_test_scores.npy")
    res = {"model": "elastic/ember ember_model_2018.txt (published by the EMBER authors)",
           "trees": int(bst.num_trees()), "n_features": int(bst.num_feature()),
           "trained_on": "all labelled EMBER 2018 training rows Jan-Oct 2018 (authors); not our subsample",
           "vectorizer_caveat": "scored on VITRINE's clean-room EMBER v2 vectors; the 50 entry-section-name "
                                "hash dims differ from elastic/ember (whole-name vs per-character hashing)",
           "ember2018_test": bootstrap_roc(yte.astype(int), [s_te], b=a.boot)}
    # The authors trained on 2018-10 too, so a threshold calibrated there is leaked and meaningless
    # (it lands near 1e-4 and gives ~18 % test FPR). Report it only as a diagnostic.
    thr = threshold_for_fpr(ytr[val], s_val, 0.01)
    res["diagnostic_leaked_2018_10_threshold"] = {
        "note": "2018-10 is in the published model's training data; do not use as an operating point",
        "threshold": thr, "ember2018_test": binary_metrics(yte, s_te, thr)}
    res["paired_vitrine_xgb_minus_published"] = paired_bootstrap_diff(yte.astype(int), [xgb_te], [s_te], b=a.boot)
    p24 = data / "ember2024" / "processed" / "test_X2.f32"
    if p24.exists():
        import csv

        with open(p24.with_name("test_meta.csv"), newline="") as f:
            y24 = np.array([int(r["label"]) for r in csv.DictReader(f)])
        X24 = np.memmap(p24, dtype=np.float32, mode="r", shape=(y24.size, 2381))
        s24 = predict(bst, X24)
        np.save(data / "models" / "ember_published_2018_on_2024test_scores.npy", s24)
        res["ember2024_test_translated"] = bootstrap_roc(y24, [s24], b=a.boot)
        thr18 = threshold_for_fpr(yte, s_te, 0.01)  # 1 % FPR on the 2018 *test* set (no leakage into 2024)
        res["ember2024_test_translated"]["at_2018_test_1pct_threshold"] = binary_metrics(y24, s24, thr18)
    res["runtime_seconds"] = round(time.time() - t0)
    dump("ember_published.json", res)
    print({k: v for k, v in res["ember2018_test"].items() if k != "val_calibrated_1pct"})


if __name__ == "__main__":
    main()
