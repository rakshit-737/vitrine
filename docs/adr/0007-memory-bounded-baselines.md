# ADR 0007: Memory-bounded baselines, and published numbers shown only as context

- Status: accepted
- Date: 2026-09-26

## Context

The EMBER 2018 training split (275,732 labeled rows after holding out October 2018) takes
about 2.6 GB as a 2381-dim float32 matrix. LightGBM also needs a binned copy of that data. On
the 16 GB development laptop, which other workloads share, the tuned "ember 2018" LightGBM
configuration (`num_leaves=2048`, `lr=0.05`, hundreds of rounds) spent more than 90 minutes
swapping without finishing.

## Decision

- The EMBER-paper LightGBM configuration (default parameters, 100 trees) is trained on a
  150,000-row seeded random subsample (`--lgbm-limit 150000`) and reported as a *reproduced
  baseline*, with its row count shown next to the result.
- VITRINE's XGBoost uses the full training split. The asymmetry is stated in the README
  and never hidden.
- Published EMBER numbers (the 2017 paper) appear only as context and are labeled with their
  dataset, because EMBER 2018 was built to be harder.
- `train_ember.py` saves every model's validation and test scores, so baselines trained
  separately, for example on a bigger machine, can be merged later with
  `merge_baselines.py`, without retraining anything else.

## Consequences

- The headline comparison favors VITRINE partly through training-set size. A full-data,
  tuned LightGBM would probably narrow or reverse the gap, which is listed on the roadmap.
- All reported thresholds stay validation-calibrated, so the operating-point comparison is
  fair, whatever the training budget.
