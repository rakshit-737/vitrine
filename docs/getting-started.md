# Getting started

```bash
python -m pip install -e ".[dev]"      # numpy core; dev pulls sklearn, xgboost, fastapi, pytest, ruff
python -m pytest -q                     # 40 tests; realdata tests skip when the dataset is absent
python -m vitrine demo                  # end-to-end on synthetic inert samples
```

Triage real files (read-only) with a trained model:

```bash
python -m vitrine analyze C:/Windows/System32/notepad.exe --model <data>/models/vitrine_xgb.json
python -m vitrine scan C:/Windows/System32 --model <data>/models/vitrine_xgb.json > verdicts.jsonl
python -m vitrine serve --model <data>/models/vitrine_xgb.json   # http://127.0.0.1:8000
docker compose up                                                # same API, hardened container
```

Real output on this machine's `notepad.exe` (EMBER-trained model, excerpt):

```
verdict  BENIGN  score=0.001  family=None
packed   False   route_to_dynamic=False
top drivers (SHAP, log-odds; + pushes toward malicious):
  -1.358  minimum OS major version 10
  -1.130  64-bit (PE32+) image: 1
  -1.062  4 exploit mitigations flagged in the header
  -0.807  Control Flow Guard enabled: 1
  -0.717  debug directory present: 1
capabilities:
  [T1106] create process: import CreateProcessW, import ShellExecuteW
  [T1622] anti-debugging checks: import IsDebuggerPresent, import OutputDebugStringW
  [T1112] registry modification: import RegCreateKeyW, import RegCreateKeyExW, import RegSetValueExW
```


## Reproducing the benchmarks

`make` targets exist, but every step is a plain command (this project was built on Windows without `make`):

```bash
pip install -e ".[dev,bench]"
python scripts/download_ember.py  --out D:/data/vitrine          # 1.7 GB, MD5 + SHA-256 verified, resumable
python scripts/prepare_ember.py   --data D:/data/vitrine         # stream -> 2381-dim f32 memmap + 91 features (~5.5 GB)
python scripts/train_ember.py     --data D:/data/vitrine --lgbm-limit 150000 --rounds-2018 300   # -> results/ember_benchmark.json
python scripts/merge_baselines.py --data D:/data/vitrine         # fold saved baseline scores in, redraw figures
python scripts/bench_yara.py      --data D:/data/vitrine --benign-dir C:/Windows/System32 --benign-limit 3000
python scripts/bench_adversarial.py --data D:/data/vitrine
python scripts/bench_cluster.py   --data D:/data/vitrine
python scripts/bench_benign.py    --data D:/data/vitrine --dir C:/Windows/System32 --limit 3000
VITRINE_DATA=D:/data/vitrine python -m pytest -q -m realdata   # real-data tests
```

Wall-clock on a contended 16 GB / 16-thread laptop: prep about 40 min, XGBoost 2–12 min depending on contention, the LightGBM paper-config baseline about 7 min, the tuned LightGBM 2018 baseline about 2 h, and the System32 scan 18–36 min.
