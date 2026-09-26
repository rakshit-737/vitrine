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

- Detection at very low FPR is somewhat below the full-vector LightGBM. The README reports the gap.
- The linear, dependency-free model stays in the code for CI and demos. There, exact linear SHAP
  is `w_i * z_i`.
