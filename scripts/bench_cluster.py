#!/usr/bin/env python
"""Family clustering benchmark: HDBSCAN over static-feature embeddings vs. AVClass labels.

Samples up to ``--per-family`` training malware from each of the ``--families`` most common
AVClass families of EMBER 2018, embeds them two ways and clusters with HDBSCAN (unsupervised,
no family count given). Scored against AVClass labels with ARI / NMI / homogeneity /
completeness, plus the noise fraction HDBSCAN refuses to cluster. AVClass labels are themselves
noisy consensus labels, so these are agreement scores, not accuracy.

  interpretable  VITRINE's 91 features, log1p on counts, standardized, PCA(20)
  ember_svd      EMBER 2381-dim vector, log1p|x|*sign, standardized, TruncatedSVD(20)

    python scripts/bench_cluster.py --data D:/.../vitrine
"""
from __future__ import annotations

import argparse
from collections import Counter

import numpy as np
from _common import data_dir, dump, load_split


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data")
    ap.add_argument("--families", type=int, default=10)
    ap.add_argument("--per-family", type=int, default=500)
    ap.add_argument("--min-cluster-size", type=int, default=25)
    a = ap.parse_args()
    from sklearn.cluster import HDBSCAN, KMeans
    from sklearn.decomposition import PCA, TruncatedSVD
    from sklearn.metrics import adjusted_rand_score, completeness_score, homogeneity_score, normalized_mutual_info_score
    from sklearn.preprocessing import StandardScaler

    data = data_dir(a.data)
    X, F, y, meta = load_split(data, "train")
    fam = np.asarray(meta["avclass"], dtype=object)
    top = [f for f, _ in Counter(f for f, lab in zip(fam, y) if lab == 1 and f).most_common(a.families)]
    rng = np.random.default_rng(0)
    idx = np.concatenate([rng.choice(np.flatnonzero((fam == f) & (y == 1)),
                                     min(a.per_family, int(((fam == f) & (y == 1)).sum())), replace=False)
                          for f in top])
    idx.sort()
    labels = fam[idx]
    print(f"{len(idx)} samples from families {top}")

    emb = {}
    Fi = np.sign(F[idx]) * np.log1p(np.abs(F[idx]))
    emb["interpretable"] = PCA(20, random_state=0).fit_transform(StandardScaler().fit_transform(Fi))
    Xi = np.asarray(X[idx], dtype=np.float64)
    Xi = np.sign(Xi) * np.log1p(np.abs(Xi))
    emb["ember_svd"] = TruncatedSVD(20, random_state=0).fit_transform(StandardScaler().fit_transform(Xi))

    rows = []
    for name, E in emb.items():
        for algo in ("hdbscan", "kmeans_k=true"):
            if algo == "hdbscan":
                pred = HDBSCAN(min_cluster_size=a.min_cluster_size).fit_predict(E)
            else:
                pred = KMeans(len(top), n_init=10, random_state=0).fit_predict(E)
            m = pred >= 0
            purity = 0.0
            for c in set(pred[m]):
                purity += Counter(labels[pred == c]).most_common(1)[0][1]
            row = {"embedding": name, "algorithm": algo, "n_clusters": int(len(set(pred[m]))),
                   "noise_fraction": float(1 - m.mean()),
                   "ari": float(adjusted_rand_score(labels[m], pred[m])),
                   "nmi": float(normalized_mutual_info_score(labels[m], pred[m])),
                   "homogeneity": float(homogeneity_score(labels[m], pred[m])),
                   "completeness": float(completeness_score(labels[m], pred[m])),
                   "purity": float(purity / max(m.sum(), 1))}
            print(row, flush=True)
            rows.append(row)
    dump("clustering.json", {"families": top, "n_samples": int(len(idx)), "rows": rows})


if __name__ == "__main__":
    main()
