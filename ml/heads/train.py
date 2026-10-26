"""Heads, calibration and combiner training. The research agent may edit this file (lab/program.md).

Usage:
  python3 -I train.py heads <run_dir> <experiment.toml> <lab_data> <cache_dir>
  python3 -I train.py combiner <run_dir> <experiment.toml> <lab_data> <calib_records.jsonl>

`heads` trains one logistic head per question on cached embeddings of the train split, then fits
a temperature per question on the calib split. `combiner` trains the linear combiner over the
tier-0 features and head logits that the real pipeline recorded for the calib split.
Outputs (in <run_dir>): heads.json, calibration.json, combiner.json.
"""
import hashlib
import json
import math
import os
import sys
import tomllib

import numpy as np
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sidecar"))
from providers import Cache, resolve, space_id  # noqa: E402

QUESTION = "is_spam"


def manifest(lab, split):
    return [json.loads(l) for l in open(os.path.join(lab, "splits", f"{split}.jsonl"))]


def rendered(lab, split, rv):
    return {r["id"]: r for r in map(json.loads, open(os.path.join(lab, "rendered", f"{split}.{rv}.jsonl")))}


def idem_key(path, recipient):
    h = hashlib.sha256(open(path, "rb").read())
    h.update(b"\0")
    h.update(recipient.lower().encode())
    return h.hexdigest()


def xy(lab, split, rv, cache):
    items = manifest(lab, split)
    rend = rendered(lab, split, rv)
    X, y = [], []
    for it in items:
        v = cache.get(rend[it["id"]]["text_sha256"])
        if v is None:
            raise SystemExit(f"missing embedding for {it['id']}")
        X.append(v)
        y.append(1 if it["label"] == "junk" else 0)
    return np.vstack(X), np.asarray(y)


def fit_temperature(z, y):
    best_t, best = 1.0, float("inf")
    for t in np.exp(np.linspace(math.log(0.05), math.log(20), 400)):
        p = 1.0 / (1.0 + np.exp(-z / t))
        p = np.clip(p, 1e-9, 1 - 1e-9)
        nll = -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))
        if nll < best:
            best, best_t = nll, float(t)
    return best_t


def provider_cfg(exp):
    p = exp["providers"]
    return resolve(p["embedder"], p.get("runtime"), p.get("precision"), p.get("max_tokens") or None,
                   p.get("threads") or None)


def heads(run_dir, exp, lab, cache_dir):
    name = exp["providers"]["embedder"]
    rv = exp["render"]["version"]
    space = space_id(provider_cfg(exp), rv)
    cache = Cache(cache_dir, space)
    Xtr, ytr = xy(lab, "train", rv, cache)
    clf = LogisticRegression(C=float(exp["heads"]["C"]), max_iter=4000)
    clf.fit(Xtr, ytr)
    w, b = clf.coef_[0].astype(float), float(clf.intercept_[0])
    digest = hashlib.sha256(np.asarray(w, dtype=np.float32).tobytes() + str(b).encode()).hexdigest()[:10]
    release = f"heads:{name}:{digest}"
    json.dump({"release": release, "space": space, "questions": {QUESTION: {"w": w.tolist(), "b": b}}},
              open(os.path.join(run_dir, "heads.json"), "w"))
    Xc, yc = xy(lab, "calib", rv, cache)
    t = fit_temperature(Xc @ w + b, yc)
    json.dump({"release": release, "temperatures": {QUESTION: t}}, open(os.path.join(run_dir, "calibration.json"), "w"))
    print(json.dumps({"release": release, "temperature": t, "train_n": int(len(ytr))}))


def combiner(run_dir, exp, lab, records_path):
    items = manifest(lab, "calib")
    label = {idem_key(it["path"], it["recipient"]): (1 if it["label"] == "junk" else 0) for it in items}
    recs = [json.loads(l) for l in open(records_path)]
    disabled = exp.get("combiner", {}).get("disabled", [])
    names = sorted({k for r in recs for k in r["features"]})
    # A disabled entry removes a feature by exact name or by prefix ("links." removes all link facts).
    names = [n for n in names if not any(n.startswith(d) for d in disabled)]
    X, y = [], []
    for r in recs:
        if r["idempotency_key"] in label and not r["input"]["parse_failed"]:
            X.append([r["features"].get(n, 0.0) for n in names])
            y.append(label[r["idempotency_key"]])
    X, y = np.asarray(X, dtype=float), np.asarray(y)
    mu, sd = X.mean(0), X.std(0)
    keep = sd > 1e-9
    names = [n for n, k in zip(names, keep) if k]
    X, mu, sd = X[:, keep], mu[keep], sd[keep]
    clf = LogisticRegression(C=float(exp["combiner"]["C"]), max_iter=4000)
    clf.fit((X - mu) / sd, y)
    w = clf.coef_[0] / sd
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mu / sd))
    weights = {n: float(v) for n, v in zip(names, w)}
    digest = hashlib.sha256(json.dumps(weights, sort_keys=True).encode() + str(b).encode()).hexdigest()[:10]
    json.dump({"release": f"combiner:{digest}", "bias": b, "weights": weights},
              open(os.path.join(run_dir, "combiner.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps({"release": f"combiner:{digest}", "inputs": len(names), "calib_n": int(len(y))}))


if __name__ == "__main__":
    stage, run_dir, exp_path, lab = sys.argv[1:5]
    exp = tomllib.load(open(exp_path, "rb"))
    if stage == "heads":
        heads(run_dir, exp, lab, sys.argv[5])
    else:
        combiner(run_dir, exp, lab, sys.argv[5])
