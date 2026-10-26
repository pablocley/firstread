"""Informational probe, outside the harness: head-only quality per text representation.

Usage: python3 -I lab/analysis/head_probe.py potion-ml-128m e5-small mmbert-small   (FIRSTREAD_LAB_DATA set)

Same splits and rendered texts as the lab. Each representation gets a logistic head trained on
train, a temperature fitted on calib, and is scored on dev at the cost threshold (100/101), head
alone (no tier-0 facts, no combiner). Adds a stateless hashed word+char n-gram baseline, the
classic bag-of-words approach, to check that the embedders beat it.
"""
import json
import math
import os
import sys

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from scipy.sparse import hstack

LAB = os.environ.get("FIRSTREAD_LAB_DATA", "lab-data")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ml", "sidecar"))
from providers import Cache, resolve, space_id  # noqa: E402

PRIMARY = {"sa", "sa_hard_ham"}
T = 100 / 101


def load(split):
    items = [json.loads(l) for l in open(f"{LAB}/splits/{split}.jsonl")]
    rend = {r["id"]: r for r in map(json.loads, open(f"{LAB}/rendered/{split}.r1.jsonl"))}
    return items, rend


def temp(z, y):
    best_t, best = 1.0, float("inf")
    for t in np.exp(np.linspace(math.log(0.05), math.log(20), 400)):
        p = np.clip(1 / (1 + np.exp(-z / t)), 1e-9, 1 - 1e-9)
        nll = -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))
        if nll < best:
            best, best_t = nll, t
    return best_t


def report(name, ztr_fit, splits):
    (Xtr, ytr), (Xc, yc), (Xd, yd, sl) = splits
    clf = LogisticRegression(C=1.0, max_iter=4000)
    clf.fit(Xtr, ytr)
    t = temp(clf.decision_function(Xc), yc)
    p = 1 / (1 + np.exp(-clf.decision_function(Xd) / t))
    prim = np.array([s in PRIMARY for s in sl])
    yp, pp = yd[prim], p[prim]
    fp = int(((pp >= T) & (yp == 0)).sum())
    fn = int(((pp < T) & (yp == 1)).sum())
    cost = 1000 * (100 * fp + fn) / len(yp)
    print(json.dumps({"repr": name, "auc_sa": round(roc_auc_score(yp, pp), 4), "fp_sa": fp, "fn_sa": fn,
                      "spam_caught_sa": f"{int((yp == 1).sum()) - fn}/{int((yp == 1).sum())}",
                      "cost_per_1k_head_only": round(cost, 1)}), flush=True)


data = {s: load(s) for s in ["train", "calib", "dev"]}


def labels(split):
    return np.array([1 if it["label"] == "junk" else 0 for it in data[split][0]])


def texts(split):
    items, rend = data[split]
    return [rend[it["id"]]["text"] for it in items]


sl = [it["slice"] for it in data["dev"][0]]
y = {s: labels(s) for s in data}

hv_w = HashingVectorizer(n_features=2**20, ngram_range=(1, 2), alternate_sign=False, norm="l2")
hv_c = HashingVectorizer(n_features=2**20, analyzer="char_wb", ngram_range=(3, 5), alternate_sign=False, norm="l2")
Xh = {s: hstack([hv_w.transform(texts(s)), hv_c.transform(texts(s))]).tocsr() for s in data}
report("hashed-ngrams (word 1-2 + char 3-5)", None, ((Xh["train"], y["train"]), (Xh["calib"], y["calib"]), (Xh["dev"], y["dev"], sl)))

for name in sys.argv[1:]:
    cache = Cache(f"{LAB}/cache", space_id(resolve(name), "r1"))
    X = {}
    for s in data:
        items, rend = data[s]
        X[s] = np.vstack([cache.get(rend[it["id"]]["text_sha256"]) for it in items])
    report(name, None, ((X["train"], y["train"]), (X["calib"], y["calib"]), (X["dev"], y["dev"], sl)))
