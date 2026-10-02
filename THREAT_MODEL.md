# VITRINE Threat Model

## Scope
A static analyzer that reads PE bytes and produces a verdict, attributions, capability tags and a candidate YARA rule. It makes no outbound network connections and never executes, maps, or loads a sample. The optional HTTP API (`vitrine serve`) listens on localhost by default.

## Assets
- The sample corpus: real samples, if an operator uses any, must stay in an offline lab. The repo ships only synthetic inert fixtures.
- The trained models (`vitrine_xgb.json`, EMBER-trained; `vitrine_model.json`, synthetic demo) and the benign corpus used for rule validation.
- Generated YARA rules, which feed downstream detection.

## Adversaries and threats

| Threat | Vector | Mitigation (implemented / planned) |
| --- | --- | --- |
| Parser exploitation | Malformed PE targets the analyzer (huge counts, bad offsets, truncation) | Implemented: pure-Python parser with bounds-checked `struct` reads, `PEParseError` on malformed input, caps on file size (128 MiB), sections (96), import descriptors (512), thunks per DLL (8,192), total import entries per file (20,000, shared by import and delay-import tables, each thunk table read once), exports (16,384) and name length (4,096 bytes). Fuzz-style tests cover truncated and malformed input. Planned: an AFL/atheris fuzzing harness |
| Accidental execution | Analyst double-clicks a sample | Implemented: VITRINE never executes anything; the synthetic corpus uses a `.exe.vitrine` extension. Operational: use an offline VM |
| Feature-space evasion | Appending benign sections, padding imports | Implemented: capability-based verdict floor and a feature-space perturbation suite with robustness metrics (`scripts/bench_adversarial.py`, see Evaluation). Note: the floor raises benign review volume and can itself be switched on by benign donor imports |
| Anti-static packing | Packers hide imports and strings | Implemented: packing heuristics set `route_to_dynamic=true` |
| Model poisoning | Mislabelled or poisoned training samples | Planned: dataset provenance, hashes, and label audit. Operational: use only curated datasets (EMBER) |
| Over-broad YARA rules | A generated rule fires on benign software | Implemented: benign-corpus specificity check, header-artifact filter, and API names demoted. Rules are labelled "analyst review required". Planned: a larger benign corpus |
| HTTP API abuse | Oversized uploads, slow/huge YARA text, DNS rebinding from a browser | Implemented: 32 MiB upload cap enforced while streaming (Content-Length checked first), `application/octet-stream` required (415 otherwise), 64 KiB rule-text cap and a line-based rule parser, Host-header allow-list (localhost), uvicorn concurrency limit, `/docs` off by default (it loads a CDN), CSP and nosniff on the UI. Container publishes on 127.0.0.1 only in docker-compose |
| Rule-string leakage | Rules embed sample strings (URLs, paths) | Rules are artifacts for internal detection. Review them before sharing externally |

## Trust boundaries
Sample bytes are untrusted. The model file is trusted input: JSON only, no pickle. The benign corpus is trusted for validation.

## Out of scope
Dynamic analysis (handled by a sandbox such as SentinelCore), network intelligence, and real malware handling procedures.
