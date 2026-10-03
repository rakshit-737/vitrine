# Limitations and roadmap

- **No live samples by design.** Real-file scoring is validated only on benign binaries. Malware performance comes from EMBER's LIEF-extracted features, and VITRINE's own extractor differs from LIEF in small ways ([ADR 0002](adr/0002-own-extractor-emits-ember-schema.md)).
- **Temporal drift.** A 2018 model loses AUC and, at its own threshold, most of its recall on EMBER2024 ([Evaluation §2](evaluation.md#2-cross-time-ember-2018-ember2024)). Retrain on recent data for real use. EMBER2024 is used as a ~7 % per-week subsample (43.5 % malicious in test, 50 % in the paper).
- **The drift ranking is correlational.** It ranks features by max(PSI benign, PSI malware) × mean |SHAP|. It does not establish a cause:
    - 2018 → 2024 mixes time with collection (EMBER 2018 was selected to be harder), extractor and schema-translation changes;
    - parser-based features were extracted by **LIEF 0.9 (EMBER 2018) and pefile/thrember (EMBER2024)**; the both-extractor parity run is described on the Evaluation page, and it covers benign open-source DLLs, not the EMBER files themselves;
    - the ranking depends on the PSI binning and on family composition (one family, xtrat, is 19 % of the 2018 test malware and absent from the 2024 test);
    - removing the top-ranked features does not recover robustness, and an oracle alignment of their 2018 marginals lowers 2024 AUC further instead of restoring it, so the shift is not marginal-only;
    - the alignment test runs on 2018 models retrained in GitHub Actions (AUC within 0.0005 of the committed `bench_drift.py` models), and the System32 definition parity on a Windows Server 2022 runner, not the Windows 11 host used for the other System32 benchmarks.
- Detection is below the authors' published full-data EMBER 2018 model; EMBER 2018 training here is a 50 % subsample, so the gap mixes data and representation.
- The LightGBM baselines are memory-limited reproductions (150k rows; 100 trees for the paper config, 300 for the tuned 2018 config). The EMBER 2017 paper setup itself is reproduced exactly (Actions run [37005292317](https://github.com/rakshit-737/vitrine-malware-triage/actions/runs/37005292317)).
- The adversarial evaluation works in feature space. It bounds what naive edits can do, and it is not a problem-space attack on real binaries.
- YARA structural rules abstain on about half the families, and their lead over a benign-filtered imphash baseline is not significant. String and byte-sequence atoms from code sections (capstone) are not implemented.
- The capability floor is not discriminative on its own (sections 5 and 7).

## Roadmap

- [x] Evaluate across EMBER 2018 / EMBER2024 (done). SOREL-20M is out of scope (size).
- [ ] Full-data EMBER 2018 retrain (no subsample) in a GitHub Actions job, to separate data from representation in the gap to the published model.
- [ ] EMBER2024 paper-config retrain on all training rows, scored on the full test split (Actions job).
- [ ] Attribution-guided (SHAP-ranked) YARA atoms, the spec's open research question.
- [x] Reproduce the EMBER 2017 (feature v1) paper setup (`results/ember2017_repro.json`, Actions run 37005292317).
- [ ] Problem-space adversarial evaluation on benign binaries (secml-malware style section and overlay injection).
- Capstone byte-sequence atoms are out of scope: they need binaries, which the safety rules exclude.
- [ ] Per-cluster (HDBSCAN) rule generation instead of per-AVClass-family.
- [ ] EMBER2024 challenge set evaluation and a representation-only ablation (deferred for time; not run).
- [x] Parser parity LIEF 0.9 vs pefile on the same benign files (Actions job `extractor-parity.yml`, `results/extractor_parity.json`).
- [ ] The same parity on files closer to EMBER's benign population (signed third-party installers), which the PyPI corpus does not represent.
- [x] Release v1.1.2 with the current `main`.
- [x] Full-budget EMBER 2018 reference: the authors' published model is now scored on our test rows.
