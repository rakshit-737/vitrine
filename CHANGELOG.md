# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

## [1.1.0] - 2026-10-02

### Added
- EMBER 2017 (feature v1) paper setup reproduced exactly in a GitHub Actions job: AUC 0.99911
  (0.99905-0.99917) vs 0.99911 published (`ember2017_repro.json`).
- v2/v3 feature-definition parity check on System32 files; drift attribution restricted to faithful
  features, with per-class patterns and 20 group-matched random-removal draws.
- Docs redirect for the old `/benchmarks/` URL, mermaid parse check in CI, deferred audit items listed.
- EMBER2024 (Win32, features only): resumable sha256-range subsample fetcher with per-range SHA-256
  manifest, pinned thrember vectorization, v3 -> v2 adapter (`vitrine/ember3.py`) with tests.
- Cross-time evaluation EMBER 2018 <-> EMBER2024 with seed-pooled bootstrap CIs, a same-size 2018
  control, a weekly drift curve, and named-feature drift attribution plus ablation (`bench_drift.py`).
- The EMBER authors' published 2018 model scored on our test rows (`score_published.py`), and the
  EMBER2024 released Win32 model plus paper-config retrains on native and translated vectors
  (`bench_ember2024.py`).
- Capability tagger and packing heuristic validated against EMBER2024 capa/packer labels.
- Like-for-like benign-filtered YARA baselines and a no-abstention ablation; Wilson/McNemar/rule-of-three
  intervals (`add_intervals.py`); adversarial benchmark with clean donors, 3 draws and matched-FPR
  comparison; clustering scored on all points.
- Docs: How it works, Evaluation, Reproduce pages; demo screenshot; preprint in `paper/`.
- Repo: CITATION.cff, CODEOWNERS, dependabot, issue/PR templates; CI on 3.10-3.14, Windows, Docker
  smoke test, pip-audit; release gated on tests.

### Changed (numbers that got worse are listed first)
- **Disclosed** that EMBER 2018 training used a 50 % sha256-prefix subsample (`--train-frac 0.5`).
- **Withdrawn:** "cost of interpretability is small" / "clearly ahead at 0.1 % FPR". The published
  EMBER 2018 model is ahead by 0.0047 AUC, 7.8 pt at 1 % FPR and 12.7 pt at 0.1 % FPR.
- **Withdrawn:** the capability floor's robustness claim; 13 of its 18.8 pt combined-attack gain came
  from benign donors' imports, and it costs 11.7 % benign FPR.
- YARA: VITRINE's lead over benign-filtered baselines is small (16.8 % vs 13.9 % coverage); the naive
  frequency baseline's FP count moved 55,112 -> 50,355 on re-run.
- Clustering: HDBSCAN on all points (ARI 0.341) is below k-means (0.478).
- Headline uses the 3-seed mean; rounding of three CI bounds fixed; SHAP ratio 28-37x (was 18-37x).

### Security
- API: upload cap enforced while streaming, octet-stream required, 64 KiB rule text, Host allow-list,
  `/docs` off by default, CSP; parser per-file import budget; download scripts require HTTP 206 and
  bounded reads, zip-slip guard; Docker base pinned by digest, HEALTHCHECK.

### Fixed
- Drift attribution is described as a correlational ranking (hypothesis), not an established cause;
  the paper states the random-draw comparison holds in AUC only (14 of 20 draws are worse at 0.1 % FPR).
- Third-party actions in release/paper workflows pinned to commit SHAs; Starlette TestClient
  deprecation warning filtered; `benchmarks.md` marked `not_in_nav`.
- Release notes were never taken from CHANGELOG (awk escape); the step now fails on empty notes.
- XML-namespace URLs no longer trigger T1071.001; sdist ships test fixtures; CLI errors are one line.

## [1.0.0] - 2026-09-26

### Added
- `scripts/bench_ci.py` and `results/ember_ci.json`: stratified-bootstrap 95 % CIs, paired
  differences, and XGBoost seed variance on full data and on the LightGBM baselines' exact 150k rows.
- MkDocs Material documentation site on GitHub Pages (architecture, datasets, benchmarks, API
  reference via mkdocstrings, ADRs) with a static, server-less triage demo (`scripts/build_demo.py`).
- Release workflow: wheel/sdist and a GHCR image (`ghcr.io/rakshit-737/vitrine`) on `v*` tags.

### Changed
- README: like-for-like rows remove XGBoost's AUC lead and put the tuned LightGBM ahead at 1 % FPR;
  the 0.1 % FPR lead holds. The 1 % FPR XGB-vs-LGBM difference is not significant.

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

[Unreleased]: https://github.com/rakshit-737/vitrine/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/rakshit-737/vitrine/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rakshit-737/vitrine/releases/tag/v1.0.0
