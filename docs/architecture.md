# Architecture

```mermaid
flowchart LR
  F["PE bytes - never executed"] --> D["dissect.py headers, sections, imports/exports, resources, entropy, strings, overlay"]
  D --> P["packing heuristics"]
  D --> CAP["capabilities.py 22 capa-style rules -> ATT&CK"]
  D --> E["ember.py EMBER v2 raw dict"]
  E --> FE["features.py 91 interpretable features"]
  CAP --> FE
  FE --> ML["gbdt.py XGBoost + calibrated thresholds"]
  ML --> SH["exact TreeSHAP -> analyst sentences"]
  D --> YG["yara_synth.py string + structural pe-module rules"]
  YG --> VAL["validator: benign specificity, sibling coverage"]
  P --> T["triage.py verdict, capability floor, route-to-dynamic"]
  SH --> T
  CAP --> T
  VAL --> T
  T --> CLI["CLI: analyze / scan"]
  T --> API["FastAPI + triage UI"]
```

| Module | Role |
| --- | --- |
| `dissect.py` | Pure-stdlib, bounds-checked PE32/PE32+ parser: 8-byte thunks, ordinal and delay imports, exports, resources, data directories, overlay, imphash, anomalies. Agrees with `pefile` on 500/500 System32 import/export tables |
| `capabilities.py` | 22 declarative capability rules (injection, hooking, credential access, anti-debug, persistence, ...) with ATT&CK IDs, A/W-agnostic API matching and evidence |
| `ember.py` | Bytes → EMBER v2 raw-feature dict (no LIEF), plus a clean-room batch implementation of the 2,381-dim v2 vectorizer (~30× faster than the per-sample loop) |
| `features.py` | 91 named features computed from EMBER raw dicts, each with a sentence template |
| `gbdt.py` | XGBoost verdict model, exact TreeSHAP (`pred_contribs`), validation-calibrated 1 % / 0.1 % FPR thresholds, nearest-centroid family |
| `model.py` | Dependency-free logistic regression with exact linear SHAP, used for CI and the synthetic demo |
| `yara_synth.py` | String rules (family-shared, benign-absent strings) and structural `pe`-module rules (imports, section names, imphash) with native validation and an optional `yara-python` compile check |
| `triage.py` | Pipeline and verdict policy: MALICIOUS / SUSPICIOUS / BENIGN, capability floor, route-to-dynamic |
| `api.py` + `static/index.html` | FastAPI (`/api/analyze`, `/api/yara/validate`, `/api/model`, `/health`) and a single-file analyst UI |
| `synth.py` | Inert synthetic PE32/PE32+ builder used by tests and the demo |
