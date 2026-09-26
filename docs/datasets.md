# Datasets

| Dataset | What | Size | Licence | Used for |
| --- | --- | --- | --- | --- |
| **EMBER 2018** (feature version 2) [2] | LIEF-extracted raw features of 1M PE files (800k train incl. 200k unlabeled, 200k test), AVClass family labels | 1.7 GB `.tar.bz2` (about 10 GB JSONL) | Data: MIT. `elastic/ember` code: AGPL-3.0 (not vendored; VITRINE's vectorizer is an independent implementation) | Training, calibration, test, auto-YARA, clustering, adversarial |
| Local Windows install (`C:\Windows\System32`) | Real, current benign PEs | read in place, nothing copied | Microsoft, not redistributed | Parser verification, benign specificity, domain shift |

No binaries, malicious or benign, are stored in the repo or the dataset folder.


## Citations

1. H. S. Anderson, P. Roth. *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models.* arXiv:1804.04637, 2018. EMBER 2017 LightGBM: AUC 0.99911, 92.99 % TPR at 0.1 % FPR, 98.2 % at 1 % FPR.
2. EMBER 2018 feature-version-2 release, <https://github.com/elastic/ember>. P. Roth, *EMBER Improvements*, CAMLIS 2019.
3. Public EMBER 2018 v2 LightGBM notebook reporting about 0.985 AUROC, <https://www.kaggle.com/code/dhoogla/ember-2018-v2f-lgbm-0-985-auroc>.
4. Mandiant capa, <https://github.com/mandiant/capa>. Neo23x0 yarGen, <https://github.com/Neo23x0/yarGen>.
