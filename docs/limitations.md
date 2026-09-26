# Limitations and roadmap

- **No live samples by design.** Real-file scoring is validated only on benign binaries. Malware performance comes from EMBER's LIEF-extracted features, and VITRINE's own extractor differs from LIEF in small ways ([ADR 0002](adr/0002-own-extractor-emits-ember-schema.md)).
- **Temporal drift.** EMBER stops in 2018. The model is a 2018 detector and needs retraining on modern features (for example EMBER2024) for real use.
- The LightGBM baselines are memory-limited reproductions (150k rows; 100 trees for the paper config, 300 for the tuned 2018 config). The published 2017-set numbers are shown only for context.
- The adversarial evaluation works in feature space. It bounds what naive edits can do, and it is not a problem-space attack on real binaries.
- YARA structural rules abstain on about half the families. String and byte-sequence atoms from code sections (capstone) are not implemented.
- The capability floor is not discriminative on its own (sections 3 and 5).


## Roadmap

- [ ] Train and evaluate on EMBER2024 / SOREL-20M features (temporal generalisation to 2024).
- [ ] Problem-space adversarial evaluation on benign binaries (secml-malware style section and overlay injection).
- [ ] Capstone byte-sequence atoms for YARA, plus a yarGen-style goodware string DB.
- [ ] Per-cluster (HDBSCAN) rule generation instead of per-AVClass-family.
- [ ] A full-data, full-budget (1,000-round) tuned LightGBM 2018 baseline on a bigger machine.
