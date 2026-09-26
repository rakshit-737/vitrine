PY ?= python

.PHONY: test demo install

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m vitrine demo
