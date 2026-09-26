# Benchmarks and results

All numbers come from committed JSON in [`results/`](https://github.com/rakshit-737/vitrine/blob/main/results/) and were produced by the scripts in [`scripts/`](https://github.com/rakshit-737/vitrine/blob/main/scripts/). EMBER 2018 uses a **temporal split**: training on Jan–Sep 2018, calibration on Oct 2018 (held out), and testing on **200,000 samples first seen Nov–Dec 2018**. Thresholds are chosen on the validation month, so the test FPR/TPR are honest out-of-time numbers.

### 1. Verdict model vs. EMBER LightGBM baselines

| Model | Features | Train rows | ROC AUC | TPR @ 1 % FPR | TPR @ 0.1 % FPR | Test FPR / recall at the val-calibrated 1 % threshold |
| --- | --- | --- | --- | --- | --- | --- |
| **VITRINE XGBoost** (600 trees, depth 10) | **91 named** | 275,732 | **0.9917** | **88.7 %** | **74.5 %** | 0.89 % / 87.8 % (precision 99.0 %) |
| LightGBM, EMBER-2018 tuned config (300 trees, 2048 leaves, lr 0.05) | 2,381 hashed | 150,000* | 0.9901 | **89.0 %** | 56.8 % | 0.79 % / 87.0 % |
| LightGBM, EMBER-paper config (100 trees, 31 leaves) | 2,381 hashed | 150,000* | 0.9797 | 75.4 % | 38.9 % | 0.90 % / 74.3 % |
| *Published:* EMBER paper LightGBM on **EMBER 2017** [1] | 2,351 | 600k labeled | 0.9991 | 98.2 % | 93.0 % | n/a (different, easier dataset) |

![ROC on EMBER 2018 test set](figures/roc_ember2018.png)

\* Both LightGBM baselines were trained on the same seeded 150k-row random subsample because the full 275k × 2381 float32 matrix did not fit in memory next to everything else on a 16 GB laptop ([ADR 0007](adr/0007-memory-bounded-baselines.md)). The tuned run also uses 300 rounds instead of the 1,000 of the EMBER 2018 reference config, and took about 2 h. Treat both as *reproduced reference points*, not as the best LightGBM result possible: a full-data, full-budget tuned model would very likely beat the row above. EMBER 2018 was deliberately built to be harder than 2017, and public default-parameter LightGBM runs on EMBER 2018 report about 0.985 AUC [3].

**Cost of interpretability:** small, and it depends on the operating point. Against the tuned 2,381-dim LightGBM, the 91 named features are level at 1 % FPR (88.7 % vs 89.0 % read off the test ROC; 87.8 % vs 87.0 % recall at the validation-calibrated thresholds, where LightGBM's test FPR came out lower, 0.79 % vs 0.89 %). They are clearly ahead at 0.1 % FPR (74.5 % vs 56.8 %) and on AUC (0.9917 vs 0.9901), with 1.8× the training rows. They beat the EMBER-paper config everywhere. In return every verdict comes with SHAP attributions that turn into analyst sentences ([ADR 0003](adr/0003-interpretable-features-plus-treeshap.md)).

**SHAP faithfulness** (2,000 test malware):

| Check | Result |
| --- | --- |
| Additivity: max \|Σ SHAP − margin\| | 1.7e-5 log-odds, so the contributions are exact |
| Deletion test: replace the top-k SHAP features with the benign median | score drop 0.087 / 0.224 / 0.335 / 0.532 for k = 1 / 3 / 5 / 10 |
| Same, but k *random* features | 0.003 / 0.008 / 0.009 / 0.019. SHAP picks the features that actually drive the score, 18–37× better than random |

![global SHAP](figures/shap_global_top20.png)

**Packing routing rationale:** 20.8 % of the test set trips the packing heuristics, and 75 % of those samples are malicious. AUC on the packed subset is 0.9965 (XGB) / 0.9953 (tuned LGBM) / 0.9905 (paper-config LGBM). The packed flag is therefore a strong *prior*, but packed benign files (installers, protected software) are exactly where static evidence runs out, which is why VITRINE routes them to dynamic analysis.

### 2. Auto-YARA on real families (15 most frequent AVClass families)

Structural rules (imports, section names, imphash through YARA's `pe` module) are synthesized from 400 training samples per family and tuned against the training benign pool. Every rule is then scored on out-of-time test siblings, **all 100,000 test benign** samples and **2,999 real System32 binaries**.

| Rule generator | Rules emitted | Mean coverage (families with a rule) | Coverage (all 15 families) | Benign FPs (100k EMBER test) | FPs on System32 | Cross-family hit rate |
| --- | --- | --- | --- | --- | --- | --- |
| **VITRINE structural** | 8 / 15 (abstains on 7) | **31.5 %** | 16.8 % | **5** (specificity 99.9994 %) | **0** | 0.005 % |
| Exact-imphash baseline | 15 | 21.0 % | 21.0 % | 11,596 | 0 | 0.18 % |
| Frequency baseline (yarGen-like, no benign filter) | 15 | 20.4 % | 20.4 % | 55,112 | 297 | 2.9 % |

When a family has distinctive structure, the rule works: xtrat **97.7 %** and sivis **98.9 %** sibling coverage with 0 benign hits. When a family doesn't (zbot, sality, emotet, upatre and others), VITRINE **abstains** instead of shipping a noisy rule. The baselines emit rules that either miss or light up thousands of benign files. Rules are in [`results/rules/ember2018_families.yar`](https://github.com/rakshit-737/vitrine/blob/main/results/rules/ember2018_families.yar).

### 3. Adversarial robustness (feature-space, 3,000 test malware)

Functionality-preserving edits are simulated on the EMBER raw features, with donor content taken from real benign samples ([ADR 0005](adr/0005-adversarial-eval-in-feature-space.md)). The table shows detection rate at the validation-calibrated 1 % FPR threshold.

| Perturbation | VITRINE XGB | LightGBM tuned 2018 | LightGBM paper config | VITRINE triage (score **or** high-risk capability floor) |
| --- | --- | --- | --- | --- |
| none | 87.1 % | 86.5 % | 74.1 % | 89.4 % |
| append benign PE as overlay | 78.6 % | 74.2 % | 63.8 % | 82.3 % |
| add benign data section | 75.1 % | 70.3 % | 63.0 % | 78.6 % |
| import padding (benign donor) | 77.1 % | 78.2 % | 60.2 % | 85.5 % |
| copy benign header fields | 79.2 % | 83.5 % | 70.2 % | 82.3 % |
| **all combined** | **40.2 %** | **44.7 %** | **37.1 %** | **58.9 %** |

Honest reading: every model is badly hurt by a combined attack, and the interpretable features are *not* more robust than the hashed EMBER vector: the tuned LightGBM holds up better against import padding, header copying and the combined attack. The capability floor retains more detections because capability rules need the *malicious* imports to disappear, and padding can't remove them. The floor has a price, though. On EMBER's raw features it flags **10.9 % of benign** test files for review, more than its 8.6 % hit rate on malware. As a *standalone* signal it isn't discriminative, and it is only useful as a "don't auto-clear" floor in front of an analyst queue.

### 4. Family clustering (5,000 malware, 10 AVClass families)

| Embedding | Algorithm | Clusters | Noise | ARI | NMI | Homogeneity | Purity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 91 interpretable feats → PCA20 | HDBSCAN | 40 | 33.6 % | 0.578 | 0.772 | 0.968 | 0.977 |
| 91 interpretable feats → PCA20 | k-means (k = true 10) | 10 | 0 | 0.478 | 0.624 | 0.601 | 0.674 |
| EMBER 2381 → SVD20 | HDBSCAN | 31 | 32.7 % | 0.660 | 0.800 | 0.961 | 0.977 |
| EMBER 2381 → SVD20 | k-means (k = true 10) | 10 | 0 | 0.246 | 0.505 | 0.448 | 0.516 |

HDBSCAN finds **very pure** clusters (about 97 % single-family) by over-splitting families into variants and refusing to label a third of the samples. That is the right behavior for a per-cluster rule generator. AVClass labels are noisy consensus labels, so these are agreement scores rather than accuracy.

### 5. Real benign binaries (domain-shift check)

This benchmark takes 3,000 random PE files from this machine's `C:\Windows\System32` (2026-era Windows 11) and parses them **with VITRINE's own dissector, not LIEF**. It then scores them with models trained on 2018 LIEF features. Every flag is a false positive.

| | Result |
| --- | --- |
| Parsed | 2,999 / 3,000 (1 over the size cap), median 168 KB |
| VITRINE XGB false positives at the 1 % / 0.1 % thresholds | **0 / 0** (mean score 0.0005) |
| LightGBM baseline false positives (tuned 2018 / paper config) | 0 / 0 (mean score 0.0013) and 0 / 0 (mean score 0.012) |
| Triage verdicts | 0 MALICIOUS, 0 SUSPICIOUS by score, **102 (3.4 %) SUSPICIOUS by capability floor**, 2,897 BENIGN |
| Most frequent capability hits | anti-debug API (T1622) 70 %, registry modification (T1112) 41 %, memory-protection changes (T1055) 11 % |

The extractor swap and 8 years of drift do not produce false positives on signed Microsoft binaries. This is an easy benign set, though: every file is signed and well-formed. The capability floor is the component that pays the price here, since OS binaries legitimately import debugging and memory APIs.
