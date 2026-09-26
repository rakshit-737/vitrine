# Contributing to VITRINE

Thanks for helping. VITRINE is a defensive, static-only tool. Please keep it that way.

## Ground rules

- **No malware in the repository, issues or PRs.** Do not attach samples. Use the synthetic
  builder (`vitrine/synth.py`) or EMBER *feature records* for reproducers.
- **Never execute analysed files.** New code must only read bytes. Parsers must bounds-check
  every read and raise `PEParseError` on malformed input, never crash or hang.
- **No large files.** Datasets go under `$VITRINE_DATA` (outside git) and are fetched by
  `scripts/download_*.py` with checksums. Committed artefacts must stay under ~500 KB.
- Models are serialized as JSON, never pickle.

## Dev setup

```bash
python -m pip install -e ".[dev,bench]"
python -m pytest -q -m "not realdata"   # what CI runs
python -m pytest -q                     # also real-data tests if EMBER / System32 are present
python -m ruff check .
```

## Adding a capability rule

Add a `_r(...)` entry in `vitrine/capabilities.py`, including the ATT&CK technique ID. Mark it
`high=True` only if it should floor the verdict to SUSPICIOUS (this costs benign flags, so check
`results/adversarial.json -> capability_floor_benign_flag_rate` after re-running the benchmark).
Then add a test.

## Adding a feature

Add the name and its sentence template to `FEATURES` in `vitrine/features.py` and compute it in
`featurize_raw`. It must be computable from an EMBER raw-feature dict. Adding a feature changes
the model schema, so re-run `scripts/prepare_ember.py` and `scripts/train_ember.py`.

## Commits and PRs

Use conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `refactor:`,
`ci:`). Keep them small and logical. If a PR changes benchmark numbers, include the updated
`results/*.json` and explain the change in `CHANGELOG.md`.
