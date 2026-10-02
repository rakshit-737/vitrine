# Limitations and roadmap

- **No live samples by design.** Real-file scoring is validated only on benign binaries. Malware performance comes from EMBER's LIEF-extracted features, and VITRINE's own extractor differs from LIEF in small ways ([ADR 0002](adr/0002-own-extractor-emits-ember-schema.md)).
- **Temporal drift.** Measured: a 2018 model loses 0.018 AUC and 29 pt of recall at its threshold on EMBER2024 ([Evaluation §2](evaluation.md#2-cross-time-ember-2018-ember2024)). Retrain on recent data for real use. EMBER2024 is used as a ~7 % per-week subsample.
- Detection is below the authors' published full-data EMBER 2018 model (−0.0047 AUC); EMBER 2018 training here is a 50 % subsample.
- The LightGBM baselines are memory-limited reproductions (150k rows; 100 trees for the paper config, 300 for the tuned 2018 config). The published 2017-set numbers are shown only for context.
- The adversarial evaluation works in feature space. It bounds what naive edits can do, and it is not a problem-space attack on real binaries.
- YARA structural rules abstain on about half the families. String and byte-sequence atoms from code sections (capstone) are not implemented.
- The capability floor is not discriminative on its own (sections 3 and 5).


## Roadmap

- [x] Evaluate across EMBER 2018 / EMBER2024 (done). SOREL-20M is out of scope (size).
- [ ] Full-data EMBER 2018 retrain (no subsample) in a GitHub Actions job, to separate data from representation in the gap to the published model.
- [ ] Attribution-guided (SHAP-ranked) YARA atoms, the spec's open research question.
- [ ] Reproduce the EMBER 2017 (feature v1) paper setup.
- [ ] Problem-space adversarial evaluation on benign binaries (secml-malware style section and overlay injection).
- Capstone byte-sequence atoms are out of scope: they need binaries, which the safety rules exclude.
- [ ] Per-cluster (HDBSCAN) rule generation instead of per-AVClass-family.
- [ ] EMBER2024 challenge set evaluation and a representation-only ablation (deferred for time; not run).
- [ ] Drift parity on more than string counters: the parser-based features are still computed by LIEF (2018) and pefile (2024); a both-extractor run on benign files would need the 2018 LIEF 0.9 toolchain.
- [ ] Release v1.1.0 with the current `main` (the v1.0.0 assets predate the latest fixes).
- [x] Full-budget EMBER 2018 reference: the authors' published model is now scored on our test rows.
