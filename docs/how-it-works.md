# How it works

This page follows two files through the pipeline: an inert **synthetic injector** (built in code by
`vitrine/synth.py`, scored by the linear demo model) and the real **`notepad.exe`** from Windows
System32 (scored by the XGBoost model trained on EMBER 2018). Both outputs are the ones embedded in
the [static demo](demo/index.html). Nothing is ever executed; every stage only reads bytes.

![Triage UI on the synthetic injector](figures/demo_triage.png)

## 1. Parse (`dissect.py`)

A bounds-checked, pure-Python PE parser reads the DOS/COFF/optional headers, sections, import,
delay-import and export tables, resources, data directories, overlay, strings and entropy. Every read
is checked; malformed input raises `PEParseError`. Hard caps (128 MiB file, 96 sections, 512 import
descriptors, 8,192 thunks per DLL, 20,000 import entries per file) bound the work an adversarial file
can cause. The report is converted to the EMBER v2 raw-feature schema (`ember.py`), so files on disk
and EMBER's pre-extracted JSON go through the same code from here on.

## 2. Capabilities (`capabilities.py`)

22 declarative, capa-style rules match imported APIs (A/W-agnostic) and strings, each mapped to an
ATT&CK technique with its evidence. For the injector:

```text
[T1055.002] process injection (remote thread): import CreateRemoteThread, import WriteProcessMemory, import VirtualAllocEx
[T1027.007] dynamic API resolution: import GetProcAddress, import LoadLibraryA
```

For `notepad.exe` the same rules fire on legitimate imports (`CreateProcessW`, `IsDebuggerPresent`,
`RegSetValueExW`). That is why capabilities are *features* and a *floor*, never a verdict on their
own. How often each rule agrees with Mandiant capa on 46,275 EMBER2024 records is measured on the
[Evaluation](evaluation.md#capability-tagger-vs-capa-ember2024) page.

## 3. Features and score (`features.py`, `gbdt.py`)

91 named features (header flags, mitigations, section entropy, import groups, string counters,
capability indicators) feed an XGBoost model (600 trees, depth 10). Operating thresholds are
calibrated on a held-out month (2018-10): **MALICIOUS** at the 0.1 % FPR point, **SUSPICIOUS** at the
1 % FPR point. The linear demo model uses fixed 0.7 / 0.3 thresholds.

## 4. Explanation (exact SHAP)

XGBoost's `pred_contribs` gives exact TreeSHAP values in log-odds; they sum to the margin (max error
1.7e-5 on 2,000 test malware). Each feature has a sentence template:

```text
notepad.exe  verdict BENIGN  score 0.0006  (TreeSHAP)
  -1.358  minimum OS major version 10
  -1.130  64-bit (PE32+) image: 1
  -1.062  4 exploit mitigations flagged in the header
  -0.807  Control Flow Guard enabled: 1
  -0.717  debug directory present: 1
```

Replacing a malware sample's top-k SHAP features with the benign median drops its score 28-37x
more than replacing k random features ([Evaluation](evaluation.md#shap-faithfulness)).

## 5. Rule synthesis and validation (`yara_synth.py`)

For non-benign verdicts VITRINE writes two candidate rules: a string rule (strings shared by the
sample and its siblings and absent from every benign file) and a structural `pe`-module rule from
**atoms** (imports, section names, imphash) kept only if rare in a benign tuning pool. The smallest
`N of (...)` threshold with zero benign hits is chosen; if none exists, VITRINE **abstains**.

```yara
rule vitrine_injector_c58a0c65_pe
{
    condition:
        uint16(0) == 0x5A4D and 1 of (
            pe.imphash() == "5060bb34101245cba70dd00a60a7d3ce",
            pe.imports("kernel32.dll", "CreateRemoteThread"),
            ...
```

Each rule is then validated: specificity on a benign corpus, coverage on held-out family siblings.

## 6. Triage policy (`triage.py`)

| Condition | Result |
| --- | --- |
| score ≥ 0.1 % FPR threshold | MALICIOUS |
| score ≥ 1 % FPR threshold | SUSPICIOUS |
| score below both, but a high-risk capability (T1055.002/.004/.012, T1056.001, T1105) fires | SUSPICIOUS ("capability floor") |
| packed (packer-like section name, or high-entropy section with a tiny import table) | `route_to_dynamic = true` |

The floor costs benign review volume: with it, the triage rule flags 11.7 % of EMBER 2018 test
benign files, and a score-only threshold at the same 11.7 % FPR detects more malware, even under the
feature-space attacks ([Evaluation](evaluation.md#adversarial-robustness)). Treat the floor as a
"don't auto-clear" queue for an analyst, not as a detector.
