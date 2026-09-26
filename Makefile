# `make` targets; each line is also runnable directly (e.g. on Windows without make).
PY ?= python
DATA ?= data

.PHONY: install test lint demo data bench serve

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
	$(PY) scripts/prepare_ember.py --data $(DATA)

bench:
	$(PY) scripts/train_ember.py --data $(DATA)
	$(PY) scripts/bench_yara.py --data $(DATA)
	$(PY) scripts/bench_adversarial.py --data $(DATA)
	$(PY) scripts/bench_cluster.py --data $(DATA)

serve:
	$(PY) -m vitrine serve --model $(DATA)/models/vitrine_xgb.json
