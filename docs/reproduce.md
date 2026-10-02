# Reproduce

Every number on the [Evaluation](evaluation.md) page comes from a committed JSON file in
[`results/`](https://github.com/rakshit-737/vitrine/tree/main/results) written by one of the commands
below. Datasets live outside the repo (`--data`); no binaries are ever downloaded.

**Prerequisites:** Python 3.10-3.14, about 25 GB free disk, 16 GB RAM (every step below stays under
about 3 GB per process except the tuned LightGBM baseline), and `pip install -e ".[dev,bench]"`.
Runtimes are wall-clock on a shared 16 GB / 16-thread Windows laptop and vary a lot with contention.

## EMBER 2018

| # | Command | Writes | Expect | Runtime |
| --- | --- | --- | --- | --- |
| 1 | `python scripts/download_ember.py --out D:/data/vitrine` | `ember_dataset_2018_2.tar.bz2` (1.7 GB, MD5 + SHA-256 checked) | `sha256 OK` | 10 min - hours (link) |
| 2 | `python scripts/prepare_ember.py --data D:/data/vitrine --train-frac 0.5` | `processed/*` (~5.5 GB) | `train=319336, test=200000` | ~40 min |
| 3 | `python scripts/train_ember.py --data D:/data/vitrine --lgbm-limit 150000 --rounds-2018 300` | `results/ember_benchmark.json`, ROC/SHAP figures | XGB AUC 0.9917, TPR 88.7 % @1 %, 74.5 % @0.1 % | XGB 2-12 min, tuned LGBM ~2 h |
| 4 | `python scripts/merge_baselines.py --data D:/data/vitrine` | merges saved baseline scores, redraws figures | - | 1 min |
| 5 | `python scripts/bench_ci.py --data D:/data/vitrine` | `results/ember_ci.json` | XGB AUC CI 0.9915-0.9920 | ~40 min |
| 6 | `python scripts/score_published.py --data D:/data/vitrine` | `results/ember_published.json` | published model AUC 0.9964, 96.5 % @1 %, 87.0 % @0.1 % | ~10 min |
| 7 | `python scripts/bench_yara.py --data D:/data/vitrine --benign-dir C:/Windows/System32 --benign-limit 3000` | `results/yara_structural.json`, `results/rules/*.yar` | VITRINE 8 rules, 5 benign FPs / 100k | 20-40 min |
| 8 | `python scripts/bench_adversarial.py --data D:/data/vitrine` | `results/adversarial.json` | triage benign FPR 0.1165 | ~30 min |
| 9 | `python scripts/bench_cluster.py --data D:/data/vitrine` | `results/clustering.json` | 40 HDBSCAN clusters, 33.6 % noise | ~5 min |
| 10 | `python scripts/bench_benign.py --data D:/data/vitrine --dir C:/Windows/System32 --limit 3000` | `results/benign_system32.json` | 0 / 2,999 score false positives | 18-36 min |
| 11 | `python scripts/add_intervals.py` | `results/intervals.json` | rule-set specificity 0.99995 | seconds |

Step 2 keeps a deterministic **50 % sha256-prefix subsample** of the 600k labelled training rows
(memory); 275,732 rows remain after holding out 2018-10 for calibration. Without `--train-frac 0.5`
you get about twice the rows and different numbers.

## EMBER2024 (cross-time and baselines)

| # | Command | Writes | Expect | Runtime |
| --- | --- | --- | --- | --- |
| 12 | `python scripts/download_ember2024.py --out D:/data/vitrine/ember2024 --mb 8` | 64 weekly `*.prefix.jsonl.gz`, `results/ember2024_manifest.json` | 135,423 records | ~15 min (512 MB of range requests) |
| 13 | `git clone https://github.com/FutureComputing4AI/EMBER2024 && git -C EMBER2024 checkout 0ef753e8` | thrember reference code (pinned, hash-checked) | - | 1 min |
| 14 | `python scripts/prepare_ember2024.py --data D:/data/vitrine --thrember EMBER2024/src` | `ember2024/processed/*` (2.6 GB) | `train 107708, test 27715` | ~10 min |
| 15 | `python scripts/bench_drift.py --data D:/data/vitrine` | `results/ember2024_drift.json`, `docs/figures/drift_ember2024.png` | see Evaluation | 1-3 h (15 XGBoost fits) |
| 15b | `python scripts/bench_drift_parity.py --data D:/data/vitrine` (also reads local `C:/Windows/System32`) | `results/ember2024_drift_parity.json` | see Evaluation §2 | 19 min, ~1.5 GB |
| 16 | `python scripts/bench_ember2024.py --data D:/data/vitrine --released <EMBER2024_Win32.model> --config EMBER2024/examples/lgbm_config.json` | `results/ember2024_baselines.json` | released model AUC 0.9983 | ~1 h |
| 17 | `python scripts/bench_capabilities.py --data D:/data/vitrine` | `results/capabilities_ember2024.json` | 46,275 records with capa output | ~15 min |

`make data data2024 bench bench2024` runs the same commands. Tests: `python -m pytest -q`
(real-data tests skip without the datasets; `VITRINE_DATA=D:/data/vitrine python -m pytest -m realdata`).

## EMBER 2017 paper setup (GitHub Actions)

`gh workflow run ember2017-repro` downloads the 1.67 GB feature archive inside the runner (sha256
checked), vectorizes it with elastic/ember@d97a0b5 (`feature_version=1`), trains LightGBM defaults and
uploads `ember2017_repro.json` (committed to `results/`). About 19 minutes; needs ~10 GB RAM, so it is
not run on a laptop.
