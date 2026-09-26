# VITRINE Threat Model

## Scope
A static analyzer that reads PE bytes and produces a verdict, attributions, capability tags and a candidate YARA rule. It has no network access and never executes, maps, or loads a sample.

## Assets
- The sample corpus: real samples, if an operator uses any, must stay in an offline lab. The repo ships only synthetic inert fixtures.
- The trained model (`vitrine_model.json`) and the benign corpus used for rule validation.
- Generated YARA rules, which feed downstream detection.

## Adversaries and threats

| Threat | Vector | Mitigation (implemented / planned) |
| --- | --- | --- |
| Parser exploitation | Malformed PE targets the analyzer (huge counts, bad offsets, truncation) | Implemented: pure-Python parser with bounds-checked `struct` reads, `PEParseError` on malformed input, caps on file size (64 MB), sections (96), descriptors (256) and thunks (4096). Fuzz-style tests cover truncated and malformed input. Planned: an AFL/atheris fuzzing harness |
| Accidental execution | Analyst double-clicks a sample | Implemented: VITRINE never executes anything; the synthetic corpus uses a `.exe.vitrine` extension. Operational: use an offline VM |
| Feature-space evasion | Appending benign sections, padding imports | Implemented: capability-based verdict floor, and the demo shows the evasion. Planned: a perturbation suite and robustness metrics |
| Anti-static packing | Packers hide imports and strings | Implemented: packing heuristics set `route_to_dynamic=true` |
| Model poisoning | Mislabelled or poisoned training samples | Planned: dataset provenance, hashes, and label audit. Operational: use only curated datasets (EMBER) |
| Over-broad YARA rules | A generated rule fires on benign software | Implemented: benign-corpus specificity check, header-artifact filter, and API names demoted. Rules are labelled "analyst review required". Planned: a larger benign corpus |
| Rule-string leakage | Rules embed sample strings (URLs, paths) | Rules are artifacts for internal detection. Review them before sharing externally |

## Trust boundaries
Sample bytes are untrusted. The model file is trusted input: JSON only, no pickle. The benign corpus is trusted for validation.

## Out of scope
Dynamic analysis (handled by a sandbox such as SentinelCore), network intelligence, and real malware handling procedures.
