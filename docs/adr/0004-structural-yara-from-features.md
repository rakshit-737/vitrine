# ADR 0004: Structural YARA rules (pe module) that can be validated on real data

- Status: accepted
- Date: 2026-09-26

## Context

String-based auto-YARA (in the style of yarGen) needs the bytes of many family samples. Under
ADR 0001 we have no real malware bytes. EMBER does give per-sample imports, section names and
(derivable) imphash.

## Decision

- `synthesize_structural` builds rules from **atoms**: `pe.imports(dll, fn)`, section names,
  and `pe.imphash()`. It keeps only atoms that are present in at least 20% of the family group (`min_support=0.2`, the committed run)
  and in at most 0.2% of a benign tuning pool. It never uses ubiquitous APIs. It then picks the
  smallest `N of (...)` threshold with zero benign hits on the tuning pool.
- It is validated **out of time**: family rules come from EMBER 2018 training samples (Jan-Oct 2018, including the 2018-10 calibration month). Coverage
  is measured on Nov-Dec 2018 test samples of the same AVClass family. Specificity is measured on
  all 100k test benign samples and on a local Windows install.
- There are two baselines: exact-imphash rules, and naive frequency rules (no benign filter).
  Neither is benign-filtered, so they are weaker than real yarGen (whose goodware filter is its
  defining step); see the Evaluation page for the like-for-like reading.
- The emitted `N of (<boolean>, ...)` syntax requires YARA 4.3 or later. VITRINE evaluates the
  same atoms natively, so validation does not need yara-python, which has no wheel for Python
  3.14 yet.

## Consequences

Structural rules survive string encryption but are defeated by import obfuscation, which is the
reason the packing detector and dynamic routing exist. The string synthesizer is still used when
the analyst supplies sibling binaries.
