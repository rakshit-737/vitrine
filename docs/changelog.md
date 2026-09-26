# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [0.2.2] - 2026-09-26

### Added
- Tuned EMBER-2018 LightGBM baseline (150k rows, 300 rounds) in `results/ember_benchmark.json`,
  the ROC figure and the adversarial benchmark.

### Fixed
- The dissector truncated import/export names at 256 bytes; long C++-mangled exports now match
  pefile (was 499/500 System32 DLLs, now 500/500).
- `train_ember.py` records `n_features` for the LightGBM baselines.

### Changed
- README: the "no cost of interpretability" claim is narrowed. The tuned LightGBM matches XGBoost
  at 1 % FPR and is slightly more robust to feature-space evasion; XGBoost leads at 0.1 % FPR and AUC.

## [0.2.1] - 2026-09-26

### Added
- `scripts/merge_baselines.py`: folds saved LightGBM baseline scores into
  `results/ember_benchmark.json` without retraining.
- Real results committed: EMBER 2018 verdict benchmark with ROC and SHAP figures,
  adversarial robustness (`results/adversarial.json`), System32 benign specificity
  (`results/benign_system32.json`).
- ADR 0007: memory-bounded baselines and how published numbers are reported.

### Changed
- `train_ember.py --lgbm-limit` subsamples only the 2381-dim LightGBM baselines. The XGBoost
  model still uses all 275,732 training rows.
- README rewritten around real results, with an honest treatment of limitations.

## [0.2.0] - 2026-09-26

### Added
- **Real data:** EMBER 2018 (feature version 2) pipeline. A resumable, checksum-verified
  download (`scripts/download_ember.py`). A streaming prep step (`scripts/prepare_ember.py`) with
  a parallel bzip2 block decompressor (`scripts/_pbz2.py`).
- EMBER-schema layer (`vitrine/ember.py`): raw features from bytes via VITRINE's own dissector,
  and a batch port of the 2381-dim v2 vectorizer.
- 91 interpretable features (`vitrine/features.py`), computed from EMBER raw dicts, each with an
  analyst-language template.
- XGBoost verdict model with exact TreeSHAP attributions and validation-calibrated thresholds
  (`vitrine/gbdt.py`).
- Structural (`pe`-module) YARA synthesis and native validation from imports, section names and
  imphash (`vitrine/yara_synth.py`).
- 22 ATT&CK-mapped capability rules with A/W-agnostic API matching.
- FastAPI service and a single-file triage UI (`vitrine serve`), Dockerfile and docker-compose.
- CLI `scan` command for directory triage.
- Benchmarks: EMBER verdict models against LightGBM baselines, SHAP faithfulness, packed-subset
  AUC, auto-YARA on real families, real-benign specificity on a Windows install, feature-space
  adversarial robustness, and HDBSCAN family clustering. Results are in `results/`.
- Docs: ADRs 0001-0006, MIT licence, CONTRIBUTING.

### Changed
- The dissector now handles PE32+ (8-byte thunks), ordinal and delay-load imports, exports,
  resources, data directories and overlay. Import and export tables agree with pefile on real
  System32 binaries.
- Triage emits both a string rule and a structural rule, and supports either model type.

## [0.1.0] - 2026-09-20

### Added
- Initial MVP: stdlib PE dissector, capa-style tagger, linear model with exact linear SHAP,
  string-based YARA synthesis with specificity and coverage validation, and synthetic inert PE
  families.
