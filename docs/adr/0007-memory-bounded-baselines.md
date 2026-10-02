# ADR 0007: Memory-bounded baselines, and published numbers shown only as context

- Status: accepted
- Date: 2026-09-26

## Context

The EMBER 2018 training data used here (275,732 labelled rows after holding out October 2018) is a
deterministic **50 % sha256-prefix subsample** (`prepare_ember.py --train-frac 0.5`): 319,336 of the
600,000 labelled training rows were kept, and 275,732 remain after removing 2018-10. It takes
about 2.6 GB as a 2381-dim float32 matrix. LightGBM also needs a binned copy of that data. On
the 16 GB development laptop, which other workloads share, the tuned "ember 2018" LightGBM
configuration (`num_leaves=2048`, `lr=0.05`, hundreds of rounds) spent more than 90 minutes
swapping without finishing.

## Decision

- The EMBER-paper LightGBM configuration (default parameters, 100 trees) is trained on a
  150,000-row seeded random subsample (`--lgbm-limit 150000`) and reported as a *reproduced
  baseline*, with its row count shown next to the result.
- VITRINE's XGBoost uses all 275,732 rows of that subsample. The asymmetry is stated in the README
  and never hidden.
- Published EMBER numbers (the 2017 paper) appear only as context and are labeled with their
  dataset, because EMBER 2018 was built to be harder.
- `train_ember.py` saves every model's validation and test scores, so baselines trained
  separately, for example on a bigger machine, can be merged later with
  `merge_baselines.py`, without retraining anything else.

## Consequences

- The headline comparison favors VITRINE partly through training-set size. A full-data,
  tuned LightGBM would probably narrow or reverse the gap, which is listed on the roadmap.

## Update (2026-09-26, later the same day)

The tuned `lgbm_ember_2018` run (`--lgbm-limit 150000 --rounds-2018 300`) eventually finished
in about 2 h once memory freed up: AUC 0.9901, TPR 89.0 % at 1 % FPR and 56.8 % at 0.1 % FPR.
It is now reported next to the paper-config baseline. With 1.8x fewer rows and 300 instead of
1,000 rounds it already matches VITRINE's XGBoost at 1 % FPR (and is slightly more robust in
the feature-space adversarial benchmark), so the "cost of interpretability" claim in the README
was narrowed accordingly: VITRINE's advantage is at low FPR (0.1 %) and in AUC, not everywhere. All reported thresholds stay validation-calibrated.

## Update (2026-10-02)

The 50 % training subsample was not disclosed before this date; it is now stated next to every
EMBER 2018 number. The EMBER authors' published model (`ember_model_2018.txt`, shipped inside the
archive, trained on all labelled rows with 1,000 rounds) is now scored on the same test rows
(`scripts/score_published.py`) and replaces the Kaggle notebook as the EMBER 2018 reference. It is
clearly ahead of every model trained here.
