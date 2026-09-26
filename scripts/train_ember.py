#!/usr/bin/env python
"""Train and benchmark verdict models on EMBER 2018 (temporal split: train Jan-Oct, test Nov-Dec 2018).

Models
  * ``lgbm_ember_paper``   LightGBM, default params (100 trees, 31 leaves) on the 2381-dim EMBER vector
                           -- the configuration of the original EMBER paper baseline.
  * ``lgbm_ember_2018``    LightGBM with the elastic/ember 2018 benchmark params
                           (num_leaves=2048, lr=0.05, feature_fraction=0.5, ...), reduced tree budget.
  * ``vitrine_xgb``        XGBoost on VITRINE's 91 interpretable features (the triage model).

Operating thresholds are calibrated on a held-out validation month (2018-10, removed from training)
so the reported test FPR/TPR are honest out-of-time numbers; the standard "TPR at FPR<=x read off
the test ROC" is also reported for comparability with the literature.

Also measures SHAP faithfulness (additivity + deletion test) and packed vs. unpacked accuracy.

    python scripts/train_ember.py --data D:/cyber-portfolio/datasets/vitrine [--rounds-2018 400]
"""
from __future__ import annotations

import argparse
import time

import numpy as np
from _common import FIGURES, REPO, binary_metrics, data_dir, dump, load_split, threshold_for_fpr, tpr_at_fpr

from vitrine.features import FEATURE_NAMES
from vitrine.gbdt import GBDTVerdictModel

EMBER_2018_PARAMS = {"boosting": "gbdt", "objective": "binary", "learning_rate": 0.05, "num_leaves": 2048,
                     "max_depth": 15, "min_data_in_leaf": 50, "feature_fraction": 0.5, "verbose": -1}


def evaluate(name, y_val, s_val, y_te, s_te, train_s):
    from sklearn.metrics import average_precision_score, roc_auc_score

    r = {"model": name, "train_seconds": round(train_s, 1),
         "roc_auc": float(roc_auc_score(y_te, s_te)), "pr_auc": float(average_precision_score(y_te, s_te))}
    for tgt, tag in ((0.01, "1pct"), (0.001, "0.1pct")):
        r[f"tpr_at_fpr_{tag}_test_roc"] = tpr_at_fpr(y_te, s_te, tgt)[0]
        thr = threshold_for_fpr(y_val, s_val, tgt)
        r[f"val_calibrated_{tag}"] = binary_metrics(y_te, s_te, thr)
    r["at_0.5"] = binary_metrics(y_te, s_te, 0.5)
    print(f"{name:18s} AUC={r['roc_auc']:.5f} TPR@1%={r['tpr_at_fpr_1pct_test_roc']:.4f} "
          f"TPR@0.1%={r['tpr_at_fpr_0.1pct_test_roc']:.4f} ({train_s:.0f}s)", flush=True)
    return r


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--rounds-2018", type=int, default=400)
    ap.add_argument("--xgb-rounds", type=int, default=600)
    ap.add_argument("--skip-full", action="store_true", help="skip the 2381-dim LightGBM baselines")
    ap.add_argument("--lgbm-limit", type=int, default=0,
                    help="subsample training rows for the 2381-dim LightGBM baselines (0 = all; memory)")
    a = ap.parse_args()
    data = data_dir(a.data)
    models_dir = data / "models"
    models_dir.mkdir(exist_ok=True)

    Xtr, Ftr, ytr, mtr = load_split(data, "train")
    Xte, Fte, yte, mte = load_split(data, "test")
    val = np.asarray([m == "2018-10" for m in mtr["appeared"]])
    fit = ~val
    fit_idx, val_idx = np.flatnonzero(fit), np.flatnonzero(val)
    lgbm_idx = fit_idx
    if a.lgbm_limit and a.lgbm_limit < fit_idx.size:
        lgbm_idx = np.sort(np.random.default_rng(0).choice(fit_idx, size=a.lgbm_limit, replace=False))
    print(f"train={fit_idx.size} val={val_idx.size} test={yte.size} "
          f"(test malicious={int(yte.sum())})", flush=True)
    results = {"dataset": "EMBER 2018 (feature version 2)", "n_train": int(fit_idx.size),
               "n_val": int(val_idx.size), "n_test": int(yte.size), "models": []}
    scores = {}

    if not a.skip_full:
        import lightgbm as lgb

        Xfit = np.asarray(Xtr[lgbm_idx])
        Xval = np.asarray(Xtr[val_idx])
        for name, params, rounds in (("lgbm_ember_paper", {"objective": "binary", "verbose": -1}, 100),
                                     ("lgbm_ember_2018", EMBER_2018_PARAMS, a.rounds_2018)):
            t = time.time()
            bst = lgb.train({**params, "num_threads": 8}, lgb.Dataset(Xfit, ytr[lgbm_idx]), rounds)
            tt = time.time() - t
            s_val = bst.predict(Xval)
            s_te = np.concatenate([bst.predict(np.asarray(Xte[i : i + 50000])) for i in range(0, len(yte), 50000)])
            r = evaluate(name, ytr[val_idx], s_val, yte, s_te, tt)
            r["params"] = {**params, "num_boost_round": rounds}
            r["n_train"] = int(lgbm_idx.size)
            results["models"].append(r)
            scores[name] = s_te
            bst.save_model(str(models_dir / f"{name}.txt"))
            np.save(models_dir / f"{name}_test_scores.npy", s_te)
            np.save(models_dir / f"{name}_val_scores.npy", s_val)
        del Xfit, Xval

    t = time.time()
    fams = [mtr["avclass"][i] for i in fit_idx]
    m = GBDTVerdictModel.fit(Ftr[fit_idx], ytr[fit_idx], families=fams, num_rounds=a.xgb_rounds,
                             params={"max_depth": 10, "eta": 0.08})
    tt = time.time() - t
    s_val = m.score_many(Ftr[val_idx])
    s_te = m.score_many(Fte)
    r = evaluate("vitrine_xgb", ytr[val_idx], s_val, yte, s_te, tt)
    r["n_features"] = len(FEATURE_NAMES)
    r["n_train"] = int(fit_idx.size)
    results["models"].append(r)
    scores["vitrine_xgb"] = s_te
    m.thresholds = {"fpr_1pct": threshold_for_fpr(ytr[val_idx], s_val, 0.01),
                    "fpr_0.1pct": threshold_for_fpr(ytr[val_idx], s_val, 0.001)}
    m.meta = {"trained_on": "EMBER 2018 train (Jan-Sep 2018), calibrated on 2018-10",
              "xgb_rounds": a.xgb_rounds, "test_roc_auc": r["roc_auc"]}
    m.save(models_dir / "vitrine_xgb.json")
    np.save(models_dir / "vitrine_xgb_test_scores.npy", s_te)

    # ---------------- SHAP faithfulness
    rng = np.random.default_rng(0)
    mal = rng.choice(np.flatnonzero(yte == 1), 2000, replace=False)
    C = m.contributions(Fte[mal])
    margin = m.booster.predict(m._dm(Fte[mal]), output_margin=True)
    additivity = float(np.abs(C.sum(axis=1) - margin).max())
    ben_median = np.median(Ftr[fit_idx][ytr[fit_idx] == 0], axis=0)
    base = m.score_many(Fte[mal])
    deletion = {}
    for k in (1, 3, 5, 10):
        Xs, Xr = Fte[mal].copy(), Fte[mal].copy()
        top = np.argsort(-C[:, :-1], axis=1)[:, :k]  # features pushing hardest toward MALICIOUS
        for i in range(len(mal)):
            Xs[i, top[i]] = ben_median[top[i]]
            rnd = rng.choice(len(FEATURE_NAMES), k, replace=False)
            Xr[i, rnd] = ben_median[rnd]
        deletion[k] = {"mean_score_drop_shap_topk": float((base - m.score_many(Xs)).mean()),
                       "mean_score_drop_random_k": float((base - m.score_many(Xr)).mean())}
    results["shap_faithfulness"] = {"n": int(len(mal)), "max_additivity_error_logodds": additivity,
                                    "deletion_test": deletion}
    print("SHAP additivity err", additivity, "deletion", deletion)
    Call = m.contributions(Fte[rng.choice(len(yte), 5000, replace=False)])[:, :-1]
    imp = np.abs(Call).mean(axis=0)
    order = np.argsort(-imp)[:20]
    results["global_shap_top20"] = [{"feature": FEATURE_NAMES[i], "mean_abs_shap": float(imp[i])} for i in order]

    # ---------------- packed vs. unpacked subsets (routing rationale)
    col = {n: Fte[:, FEATURE_NAMES.index(n)] for n in ("packer_section_name", "n_high_entropy_sections",
                                                          "imports_tiny")}
    pk = (col["packer_section_name"] > 0) | ((col["n_high_entropy_sections"] > 0) & (col["imports_tiny"] > 0))
    from sklearn.metrics import roc_auc_score
    sub = {"packed_fraction_test": float(pk.mean()),
           "packed_malicious_fraction": float(yte[pk].mean()) if pk.any() else None}
    for name, s in scores.items():
        sub[name] = {"auc_packed": float(roc_auc_score(yte[pk], s[pk])),
                     "auc_unpacked": float(roc_auc_score(yte[~pk], s[~pk]))}
    results["packing_subsets"] = sub
    print("packing", sub)

    dump("ember_benchmark.json", results)
    _figures(yte, scores, results)


def _figures(yte, scores, results):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve

    FIGURES.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=120)
    for name, s in scores.items():
        f, t, _ = roc_curve(yte, s)
        ax.plot(f, t, label=name, lw=1.4)
    ax.set_xscale("log")
    ax.set_xlim(1e-4, 1)
    ax.set_ylim(0.5, 1.0)
    ax.axvline(0.01, ls=":", c="grey", lw=0.8)
    ax.axvline(0.001, ls=":", c="grey", lw=0.8)
    ax.set_xlabel("false positive rate (log)")
    ax.set_ylabel("true positive rate")
    ax.set_title("EMBER 2018 test set (Nov-Dec 2018, 200k samples)")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES / "roc_ember2018.png")
    fig, ax = plt.subplots(figsize=(6, 5), dpi=110)
    top = results["global_shap_top20"][::-1]
    ax.barh([t["feature"] for t in top], [t["mean_abs_shap"] for t in top], color="#4c72b0")
    ax.set_xlabel("mean |SHAP| (log-odds)")
    ax.set_title("VITRINE XGBoost: global feature attribution")
    fig.tight_layout()
    fig.savefig(FIGURES / "shap_global_top20.png")
    print("figures written to", FIGURES.relative_to(REPO))


if __name__ == "__main__":
    main()
