# ADR 0003: An interpretable feature set with XGBoost and TreeSHAP for the triage verdict

- Status: accepted
- Date: 2026-09-26

## Context

The EMBER 2381-dim vector is mostly feature hashing: 1024 import buckets, 50 section-name
buckets, and so on. A SHAP value on "imports bucket 731" cannot be turned into an analyst
sentence, and the spec makes explanation the core deliverable, not decoration.

## Decision

- The triage model is XGBoost over **91 named features** (`vitrine/features.py`): section entropy
  statistics, W+X sections, entry-point placement, import API-group counts, the capability rules,
  string counters, header mitigations, and so on. Each one has a sentence template.
- Attributions come from XGBoost's built-in exact TreeSHAP (`pred_contribs=True`). The
  contributions sum to the model margin (the additivity error is measured in the benchmark), so
  "these five features drove the score" is a faithful statement.
- The full-vector LightGBM models are kept as **baselines** so the cost of interpretability is
  measured and reported, not hidden.
- Family assignment is nearest-centroid over standardized features for the 20 largest AVClass
  families. HDBSCAN is evaluated separately as unsupervised discovery (`bench_cluster.py`).

## Consequences

- Detection at very low FPR is below a full-data, full-budget 2,381-dim LightGBM. The README reports the gap.

## Update (2026-10-02)

Measured outcome: against our memory-limited 150k-row LightGBM reproductions the 91 named features
were ahead at 0.1 % FPR and level at 1 % FPR, and most of the AUC lead came from having more training
rows. Against the EMBER authors' *published* EMBER 2018 model (all labelled rows, 1,000 trees),
scored on the same test rows, VITRINE's XGBoost is clearly behind: -0.0047 AUC, -7.8 pt TPR at
1 % FPR and -12.7 pt at 0.1 % FPR (paired bootstrap CIs in `results/ember_published.json`).
Interpretability does have a measurable cost; the original expectation above was right.
- The linear, dependency-free model stays in the code for CI and demos. There, exact linear SHAP
  is `w_i * z_i`.
