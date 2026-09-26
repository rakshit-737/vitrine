# VITRINE

**Static-first PE triage that explains every verdict and writes a candidate YARA rule, without ever running the sample.**

A bare `predict() -> 0.87` doesn't help an analyst decide anything. VITRINE parses a PE file (headers, sections, imports, exports, resources, entropy, strings, overlay), tags capabilities with 22 capa-style rules mapped to ATT&CK, and scores the file with an XGBoost model trained on **EMBER 2018**. Exact TreeSHAP ties the score to named artifacts, which VITRINE reports in plain language. It then synthesizes a `pe`-module YARA rule and validates it against a benign corpus for specificity and against held-out family siblings for coverage. Packed samples starve static features, so VITRINE routes them to dynamic analysis instead of guessing.

> **Lab-only, no malware in this repo.** VITRINE only reads bytes and never loads, maps or executes a file. All training and evaluation uses EMBER's **pre-extracted features** (JSON, no binaries). Test fixtures are synthetic inert PEs built in code (`vitrine/synth.py`) plus a 75 KB sample of EMBER feature records. The real-benign benchmark reads `C:\Windows\System32` in place, read-only. See [SECURITY.md](security.md), [THREAT_MODEL.md](threat-model.md) and [ADR 0001](adr/0001-static-only-no-live-malware.md).



[Try the static demo](demo/index.html){ .md-button } [Benchmarks](benchmarks.md){ .md-button }

## Prior art and how this differs

| Existing | What it does | VITRINE's angle |
| --- | --- | --- |
| EMBER / PE-malware ML [1,2] | Feature set and GBDT score | Named features and exact TreeSHAP sentences, calibrated out-of-time thresholds, triage policy |
| yarGen / YARA-Signator | Frequency-based rule generation | Benign-filtered, structural `pe` rules. Measured specificity and coverage on 100k benign, and abstention when no rule is safe |
| capa (Mandiant), PEframe | Capability detection | Capabilities used as model features *and* as an evasion-resistant "don't auto-clear" floor |
| VirusTotal | Cloud multi-AV | Local, offline, explainable |

VITRINE's contribution is **chaining these into one static-only pipeline and measuring each link on real data**. It complements dynamic sandboxes: VITRINE decides *what deserves* detonation.


## References

1. H. S. Anderson, P. Roth. *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models.* arXiv:1804.04637, 2018. EMBER 2017 LightGBM: AUC 0.99911, 92.99 % TPR at 0.1 % FPR, 98.2 % at 1 % FPR.
2. EMBER 2018 feature-version-2 release, <https://github.com/elastic/ember>. P. Roth, *EMBER Improvements*, CAMLIS 2019.
3. Public EMBER 2018 v2 LightGBM notebook reporting about 0.985 AUROC, <https://www.kaggle.com/code/dhoogla/ember-2018-v2f-lgbm-0-985-auroc>.
4. Mandiant capa, <https://github.com/mandiant/capa>. Neo23x0 yarGen, <https://github.com/Neo23x0/yarGen>.
