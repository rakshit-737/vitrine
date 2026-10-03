# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

## [1.1.3] - 2026-10-03

## [1.1.3] - 2026-10-03

### Added
- Oracle marginal-alignment test of the drift ranking (`bench_drift_align.py`,
  `results/ember2024_drift_align.json`) and the removal ablation with 100 seed- and group-matched
  random draws (`results/ember2024_drift_parity.json`), both run on the full data in GitHub Actions
  (`drift-heavy.yml`, run 37117414731); the System32 definition parity runs on the Windows runner.
- `scripts/render_results.py`: README, `docs/index.md`, `docs/evaluation.md` and `paper/main.tex` are
  rendered from `templates/` and the committed result files; CI fails on a stale rendered file or a
  leftover `@@` token.
- Bootstrap intervals for the System32 definition parity (Wilson agreement, total variation, PSI by
  share floor).

### Changed (numbers that got worse are listed first)
- **Oracle alignment is a negative result**: giving the faithful top-10 features their 2018
  class-conditional marginals lowers the frozen 2018 models' 2024 AUC by 0.0166 (0.0130-0.0204)
  instead of recovering the 0.018 drop, and all 20 group-matched random sets end at least as high;
  the shift is not marginal-only. Evaluation §2, the abstract and the README say so.
- **Removal ablation, 100 draws**: dropping the faithful top 10 changes 2024 AUC by −0.0018
  (−0.0033 to −0.0003), no worse than chance (46 of 100 random removals hurt more, p = 0.47), and
  hurts 2018 AUC and 2024 TPR @ 1 % FPR more than every draw (p = 0.01). Was 20 draws on a ranking
  that still contained an extractor-sensitive feature.
- **Paper retitled**: "Attributable Temporal Drift" became "a Correlational Account of Temporal
  Drift"; abstract, introduction and limitations no longer claim attribution.
- **Drift ranking recomputed** on point-mass-aware PSI bins and restricted to definition- and
  extractor-consistent features, with bootstrap rank intervals and binning / family (xtrat)
  controls: the top 10 is now `cert_kb`, `max_vsize_ratio`, `is_dll`, `n_imports`, `os_major`,
  `size_kb`, `linker_major`, `n_wx_sections`, `code_ratio`, `avg_string_len`; 6 survive every control.
- `n_embedded_mz` parity re-measured on 600 System32 files of a Windows Server 2022 runner: exact
  agreement 13.7 % (11.1-16.6), total variation 0.86 (was 12.7 % on the Windows 11 host, no interval).
- VITRINE vs the published EMBER 2018 model is reported seed-pooled with plug-in points: AUC −0.0050
  (−0.0056 to −0.0043), was −0.0047 for seed 0 alone (also still reported).
- The drift figure shows the comparable-feature ranking with bootstrap error bars and the weekly AUC
  band; `n_embedded_mz` is greyed out as a definition change.
- Docs, README, citation and package metadata point to the renamed repository
  (`rakshit-737/vitrine-malware-triage`, pages at `/vitrine-malware-triage/`); the old pages URL
  returns 404. The GHCR image is now `ghcr.io/rakshit-737/vitrine-malware-triage`; older entries
  below keep the old names (`rakshit-737/vitrine`, `ghcr.io/rakshit-737/vitrine`) as they were.

### Fixed
- `prepare_ember2024.py` pinned thrember's `features.py` by the bytes of a CRLF (Windows autocrlf)
  checkout, so on Linux the check failed in every pool initializer and the pool respawned workers
  forever; the pin is now on LF-normalised bytes and is checked once before the pool starts.
- `bench_drift_parity.py` had the two Monte Carlo p-value labels of the random-removal control
  swapped (`mc_p_topk_more_damaging` / `_less_damaging`); fixed, and the committed result's two
  fields recomputed from its draws (noted in the file).
- `bench_drift_parity.py` no longer says the parser parity was "not run"; it points to
  `extractor_parity.json`.
- README: the EMBER2024 retrain is ~7 % of the paper's training rows (was "~4 %").

## [1.1.2] - 2026-10-03

### Fixed
- The sdist test run no longer fails on the committed-demo check: it skips when `docs/demo` is absent
  from the sdist. The v1.1.1 tag has no release artefacts (no GitHub Release, wheel, sdist or GHCR
  image) because its release workflow failed on that test; 1.1.2 is the same code plus this fix.

## [1.1.1] - 2026-10-03

### Added
- LIEF 0.9 vs pefile parity of the parser features on 1,069 benign PE files, run in GitHub Actions
  (`extractor-parity.yml`, run 37092793271, `results/extractor_parity.json`); the drift ranking
  excludes parser features the two extractors disagree on.
- A `provenance` block (commit, command, UTC time, library versions, Actions run id) in every result
  file; older files are backfilled.
- Intervals for the YARA coverage (family bootstrap and paired family-level test), clustering
  (20 re-drawn samples), secondary EMBER 2018 statistics (`ember_secondary.json`) and the clean-donor
  adversarial pool; parity intervals and a seed-matched 100-draw random ablation in the drift tooling.
- The preprint PDF is built with the docs and published at `/paper/vitrine-preprint.pdf`.
- README / datasets: related work on drift detection (Transcend, CADE, drift forensics, Kalný et al.)
  and the EMBER2024 subsample's fraction of the paper split and class shares.

### Changed
- Point-mass-aware PSI, exact Wilson edges, threshold and two-sample bootstraps in `_stats.py`;
  `bench_drift.py` keeps models and scores and bootstraps every reported drift statistic.
- CI takes Dependabot's action bumps and exercises the pinned Docker actions.

### Fixed
- Authenticode CRL/AIA/CPS URLs no longer tag T1071.001; the static demo is rebuilt with the current tagger.
- `analyze`/`scan` refuse files over the 128 MiB parser cap before reading; one default per help line.
- The API runs analyses in a worker thread with two bounded slots; its test uses httpx's ASGI transport.
- Docs: current CLI help and `/openapi.json` in the reference; private advisory link in SECURITY.

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

[Unreleased]: https://github.com/rakshit-737/vitrine-malware-triage/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/rakshit-737/vitrine-malware-triage/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/rakshit-737/vitrine-malware-triage/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/rakshit-737/vitrine-malware-triage/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rakshit-737/vitrine-malware-triage/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rakshit-737/vitrine-malware-triage/releases/tag/v1.0.0
