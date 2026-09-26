# ADR 0002: The stdlib dissector emits the EMBER v2 raw-feature schema

- Status: accepted
- Date: 2026-09-26

## Context

The public EMBER corpus was extracted with LIEF 0.9. We want a model trained on that corpus to
score a file on disk. The options were:

| Option | Pro | Con |
| --- | --- | --- |
| Depend on LIEF + `elastic/ember` | exact feature parity | the old LIEF pin does not build on Python 3.14; a heavy native dependency |
| pefile | mature | slow; still needs a port of the EMBER feature code |
| **Own stdlib dissector, then EMBER schema** | no native deps; fully auditable bounds checks | small extraction differences from LIEF (domain shift) |

## Decision

`vitrine.dissect` parses PE32 and PE32+ (imports with 8-byte thunks, ordinals, delay imports,
exports, resources and data directories). `vitrine.ember.raw_from_report` renders that as an
EMBER-v2 dict, using the same enum spellings as LIEF (`I386`, `PE32_PLUS`, `MEM_EXECUTE`, and
so on). `vectorize_many` is a clean-room batch port of EMBER's feature hashing (2381 dims).

## Verification

- Import and export tables agree with pefile on 500/500 System32 files (plus a `realdata` test).
- A schema test checks key-for-key compatibility against real EMBER records.
- The remaining LIEF-vs-VITRINE differences are measured, not assumed. `bench_benign.py` reports
  false-positive rates on real Windows binaries, which include this extraction shift together
  with the 2018 to 2026 temporal drift.
