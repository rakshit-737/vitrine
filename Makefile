# `make` targets; each line is also runnable directly (e.g. on Windows without make).
# The commands match docs/reproduce.md exactly.
PY ?= python
DATA ?= data
SYSTEM32 ?= C:/Windows/System32

.PHONY: install test lint demo data data2024 bench bench2024 serve

install:
	$(PY) -m pip install -e ".[dev,bench]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

demo:
	$(PY) -m vitrine demo

data:
	$(PY) scripts/download_ember.py --out $(DATA)
	$(PY) scripts/prepare_ember.py --data $(DATA) --train-frac 0.5

data2024:
	$(PY) scripts/download_ember2024.py --out $(DATA)/ember2024 --mb 8
	$(PY) scripts/prepare_ember2024.py --data $(DATA) --thrember $(DATA)/ref/EMBER2024/src

bench:
	$(PY) scripts/train_ember.py --data $(DATA) --lgbm-limit 150000 --rounds-2018 300
	$(PY) scripts/merge_baselines.py --data $(DATA)
	$(PY) scripts/bench_ci.py --data $(DATA)
	$(PY) scripts/score_published.py --data $(DATA)
	$(PY) scripts/bench_yara.py --data $(DATA) --benign-dir $(SYSTEM32) --benign-limit 3000
	$(PY) scripts/bench_adversarial.py --data $(DATA)
	$(PY) scripts/bench_cluster.py --data $(DATA)
	$(PY) scripts/bench_benign.py --data $(DATA) --dir $(SYSTEM32) --limit 3000
	$(PY) scripts/add_intervals.py

bench2024:
	$(PY) scripts/bench_drift.py --data $(DATA)
	$(PY) scripts/bench_ember2024.py --data $(DATA) --released $(DATA)/ref/models2024/EMBER2024_Win32.model --config $(DATA)/ref/EMBER2024/examples/lgbm_config.json
	$(PY) scripts/bench_capabilities.py --data $(DATA)

serve:
	$(PY) -m vitrine serve --model $(DATA)/models/vitrine_xgb.json
