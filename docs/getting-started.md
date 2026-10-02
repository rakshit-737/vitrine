# Getting started

```bash
python -m pip install -e ".[dev]"      # numpy core; dev pulls sklearn, xgboost, fastapi, pytest, ruff
python -m pytest -q                     # 43 tests; realdata tests skip when the dataset is absent
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

See [Reproduce](reproduce.md) for every command (including `--train-frac 0.5`), its output file, expected numbers and runtime.
