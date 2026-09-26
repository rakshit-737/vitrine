# ADR 0005: Adversarial evaluation as feature-space simulation of functionality-preserving edits

- Status: accepted
- Date: 2026-09-26

## Context

The spec asks how robust the model is to appending benign sections and padding imports.
Editing real malware binaries would break ADR 0001.

## Decision

`bench_adversarial.py` applies the edits to EMBER *raw-feature dicts*: appending a benign donor's
bytes as overlay (all byte and string statistics updated), adding a new data section, merging a
donor's imports, copying a donor's header fields, and all of these combined. It then recomputes
both feature sets and reports detection and evasion rates at validation-calibrated 1%-FPR
thresholds for each model. It also measures the **capability floor**, and the floor's price: the
share of benign software it sends to review.

## Consequences

The benchmark is an optimistic model of a *naive* attacker. It does not do gradient- or
query-based optimization, and it does not check that the edited binary still runs. Real
binary-level attacks (e.g. MalConv/EMBER attacks from the literature) are out of scope and listed
on the roadmap.
