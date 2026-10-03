# Datasets

| Dataset | What | Size | Licence | Used for |
| --- | --- | --- | --- | --- |
| **EMBER 2018** (feature version 2) [2] | LIEF-extracted raw features of 1M PE files (800k train incl. 200k unlabeled, 200k test). We train on a deterministic 50 % sha256-prefix subsample of the 600k labelled training rows (`--train-frac 0.5`), AVClass family labels | 1.7 GB `.tar.bz2` (about 10 GB JSONL) | Data: MIT. `elastic/ember` code: AGPL-3.0 (not vendored; VITRINE's vectorizer is an independent implementation) | Training, calibration, test, auto-YARA, clustering, adversarial |
| **EMBER2024** Win32 (feature version 3) | pefile/thrember features with capa and packer labels, weekly 2023-09 .. 2024-12; we use a sha256-range subsample (first 8 MiB of each weekly file, 135,423 records, about 7 % of the paper's Win32 split; 43.5 % of the test subsample and 46.4 % of the training subsample are malicious, vs 50 % in the paper; manifest with per-range SHA-256 in `results/ember2024_manifest.json`, HF revision 3d23efef, thrember commit 0ef753e8) | 15 GB full; 512 MB fetched | Apache-2.0 | Cross-time drift, baseline scoring (released model; ~7 % retrain), capability validation |
| Local Windows install (`C:\Windows\System32`) | Real, current benign PEs | read in place, nothing copied | Microsoft, not redistributed | Parser verification, benign specificity, domain shift |

No binaries, malicious or benign, are stored in the repo or the dataset folder.


## Citations

1. H. S. Anderson, P. Roth. *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models.* arXiv:1804.04637, 2018. EMBER 2017 LightGBM: AUC 0.99911, 92.99 % TPR at 0.1 % FPR, 98.2 % at 1 % FPR.
2. EMBER 2018 feature-version-2 release and benchmark model, <https://github.com/elastic/ember>; the original paper [1] describes only EMBER 2017, and the elastic/ember README points to P. Roth's CAMLIS 2019 talk (slides and video) for EMBER 2018.
3. R. J. Joyce et al. *EMBER2024 - A Benchmark Dataset for Holistic Evaluation of Malware Classifiers.* KDD 2025, arXiv:2506.05074.
4. F. Pendlebury et al. *TESSERACT.* USENIX Security 2019, arXiv:1807.07838. R. Jordaney et al. *Transcend.* USENIX Security 2017. F. Barbero et al. *Transcending TRANSCEND.* IEEE S&P 2022. L. Yang et al. *CADE.* USENIX Security 2021. T. Chow et al. *Drift Forensics of Malware Classifiers.* AISec 2023. T. Kalný, M. Jureček, M. Stamp. *Detecting Concept Drift in Evolving Malware Families Using Rule-Based Classifier Representations.* arXiv:2604.22629, 2026. E. Raff et al. *Automatic Yara Rule Generation Using Biclustering.* AISec 2020, arXiv:2009.03779.
5. Mandiant capa, <https://github.com/mandiant/capa>. Neo23x0 yarGen, <https://github.com/Neo23x0/yarGen>.
