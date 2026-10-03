#!/usr/bin/env python
"""Draw ``docs/figures/drift_ember2024.png`` from the committed drift result files.

Left: AUC of the 2018-trained model (3-seed ensemble) on each EMBER2024 week, with the per-week
bootstrap band (``ember2024_drift.json``). Right: the drift-weighted ranking restricted to features
defined the same way in both schemas, with bootstrap intervals, coloured by which class shifted;
``n_embedded_mz``, the top raw-PSI feature, is shown greyed out because its rank is a schema-definition
change, not drift (``ember2024_drift_parity.json``).

    python scripts/plot_drift.py
"""
from __future__ import annotations

import json

from _common import FIGURES, RESULTS

INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
PATTERN = {"both_classes": ("#2a78d6", "shifts in both classes"),
           "benign_only": ("#eb6834", "benign files only"),
           "malicious_only": ("#1baf7a", "malware only"),
           "mixed": ("#9b9a95", "mixed / small shift"),
           "stable": ("#9b9a95", "mixed / small shift")}


def main(top: int = 12) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    drift = json.loads((RESULTS / "ember2024_drift.json").read_text(encoding="utf-8"))
    curve = drift["weekly_2018_model_on_2024"]
    feats = drift["drift_ranking"]["features"]
    faithful = [f for f in feats if f["faithful"]][:top]
    mz = next(f for f in feats if f["feature"] == "n_embedded_mz")

    plt.rcParams.update({"font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
                         "ytick.color": MUTED, "axes.titlecolor": INK})
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(11, 4.4), dpi=110, gridspec_kw={"width_ratios": [1, 1.15]})
    w = [c["week"] for c in curve]
    ax.fill_between(w, [c["roc_auc_ci95"][0] for c in curve], [c["roc_auc_ci95"][1] for c in curve],
                    color="#2a78d6", alpha=0.18, lw=0, label="95 % bootstrap band")
    ax.plot(w, [c["roc_auc"] for c in curve], color="#2a78d6", lw=2, label="weekly ROC AUC")
    in18 = drift["matrix"]["ember2018->ember2018_test"]["roc_auc"]["point"]
    ax.axhline(in18, color=MUTED, ls="--", lw=1)
    ax.text(w[0], in18 + 0.001, f"same model on 2018 test: {in18:.3f}", color=MUTED, va="bottom", fontsize=8)
    ax.axvline(51.5, ls=":", c=MUTED, lw=1)
    ax.text(52, ax.get_ylim()[0] + 0.002, "test weeks", color=MUTED, fontsize=8)
    ax.set_xlabel("EMBER2024 week (0 = 2023-09-24)")
    ax.set_ylabel("ROC AUC")
    ax.set_title("2018-trained model on each EMBER2024 week", loc="left")
    ax.grid(color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    ax.legend(loc="lower left", frameon=False, fontsize=8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)

    rows = [mz, *faithful][::-1]
    y = range(len(rows))
    vals = [f["drift_weight"] for f in rows]
    err = [[f["drift_weight"] - f["drift_weight_ci95"][0] for f in rows],
           [f["drift_weight_ci95"][1] - f["drift_weight"] for f in rows]]
    err = [[max(0.0, e) for e in side] for side in err]
    colors = ["#d6d5d0" if f is mz else PATTERN[f["shift_pattern"]][0] for f in rows]
    bars = bx.barh(list(y), vals, color=colors, height=0.68, xerr=err, ecolor=INK,
                   error_kw={"lw": 0.8, "capsize": 2})
    bars[-1].set_hatch("///")
    bars[-1].set_edgecolor("#9b9a95")
    bx.set_yticks(list(y))
    bx.set_yticklabels([f"{f['feature']} (definition change, excluded)" if f is mz else f["feature"] for f in rows],
                       fontsize=8)
    bx.set_xlabel("max(PSI benign, PSI malware) x mean |SHAP| of the 2018 model")
    bx.set_title("Drift-weighted ranking (correlational)", loc="left")
    bx.grid(axis="x", color=GRID, lw=0.8)
    bx.set_axisbelow(True)
    for s in ("top", "right"):
        bx.spines[s].set_visible(False)
    seen, handles = set(), []
    for f in faithful:
        c, lab = PATTERN[f["shift_pattern"]]
        if lab not in seen:
            seen.add(lab)
            handles.append(Patch(color=c, label=lab))
    handles.append(Patch(facecolor="#d6d5d0", edgecolor="#9b9a95", hatch="///", label="not comparable across schemas"))
    bx.legend(handles=handles, loc="lower right", frameon=False, fontsize=8)
    fig.text(0.01, 0.01, "Parser features: LIEF 0.9 (2018) vs pefile (2024); features the two disagree on (benign "
             "parity files) are excluded. Error bars: 95 % bootstrap.", fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    FIGURES.mkdir(parents=True, exist_ok=True)
    out = FIGURES / "drift_ember2024.png"
    fig.savefig(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
