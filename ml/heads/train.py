"""Heads, calibration and combiner training. The research agent may edit this file (lab/program.md).

Usage:
  python3 -I train.py heads <run_dir> <experiment.toml> <lab_data> <cache_dir>
  python3 -I train.py combiner <run_dir> <experiment.toml> <lab_data> <calib_records.jsonl>
  python3 -I train.py verdict <kind> <run_dir> <experiment.toml> <lab_data> <calib_records.jsonl>

`heads` trains one logistic head per question in `[heads] questions` (default `["is_spam"]`) on
cached embeddings of the train split, then fits a temperature per question on the calib split. A
question is trained where the lab's items say its answer (labels.py); with `[heads] teacher = "<dir>"`
(a run of ml/distill/teach.py under <lab_data>/teacher/) the other questions are distilled from the
teacher's answers: a noul question from P(true) >= 0.5, weighted by the teacher's confidence; a choice
or score question from its most likely outcome, as a matrix head. A distilled head is calibrated
against the teacher, so it can be no better than the teacher's agreement.json says. Too few of each
answer, and a question gets no head and no calibration, so the daemon never asks it.
`combiner` trains junk's linear combiner over the tier-0 features and head logits that the real
pipeline recorded for the calib split. `verdict` trains the combiner of another verdict the same
way, from VERDICT_LABELS, without mailbox facts for the safety verdicts (the safety floor).
Outputs (in <run_dir>): heads.json, calibration.json, combiner.json, combiner-<kind>.json.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labels import LABELS, VERDICT_LABELS  # noqa: E402

SAFETY = {"phishing", "fraud"}
# Fewest examples of each answer a head or combiner needs in a split.
MIN_EACH = {"train": 20, "calib": 5}


def manifest(lab, split):
    return [json.loads(l) for l in open(os.path.join(lab, "splits", f"{split}.jsonl"))]


def rendered(lab, split, rv):
    return {r["id"]: r for r in map(json.loads, open(os.path.join(lab, "rendered", f"{split}.{rv}.jsonl")))}


def idem_key(path, recipient):
    h = hashlib.sha256(open(path, "rb").read())
    h.update(b"\0")
    h.update(recipient.lower().encode())
    return h.hexdigest()


def xy(lab, split, rv, cache, label=LABELS["is_spam"]):
    items = manifest(lab, split)
    rend = rendered(lab, split, rv)
    X, y = [], []
    for it in items:
        lab_ = label(it)
        if lab_ is None:
            continue
        v = cache.get(rend[it["id"]]["text_sha256"])
        if v is None:
            raise SystemExit(f"missing embedding for {it['id']}")
        X.append(v)
        y.append(lab_)
    return np.vstack(X), np.asarray(y)


def enough(y, split):
    return int(y.sum()) >= MIN_EACH[split] and int(len(y) - y.sum()) >= MIN_EACH[split]


def teacher_xy(lab, split, rv, cache, teacher, q):
    """Embeddings and the teacher's answer for question q, for the messages the teacher read."""
    path = os.path.join(lab, "teacher", teacher, f"{split}.jsonl")
    answers = {t["id"]: t["p"][q] for t in map(json.loads, open(path)) if q in t["p"]}
    rend = rendered(lab, split, rv)
    X, P = [], []
    for it in manifest(lab, split):
        if it["id"] in answers:
            v = cache.get(rend[it["id"]]["text_sha256"])
            if v is None:
                raise SystemExit(f"missing embedding for {it['id']}")
            X.append(v)
            P.append(answers[it["id"]])
    if not X:
        return np.zeros((0, 0)), np.zeros((0, 0))
    return np.vstack(X), np.asarray(P, dtype=float)


def fit_temperature_multi(Z, y):
    best_t, best = 1.0, float("inf")
    for t in np.exp(np.linspace(math.log(0.05), math.log(20), 400)):
        z = Z / t
        z = z - z.max(1, keepdims=True)
        logp = z - np.log(np.exp(z).sum(1, keepdims=True))
        nll = -np.mean(logp[np.arange(len(y)), y])
        if nll < best:
            best, best_t = nll, float(t)
    return best_t


def distil(Xtr, Ptr, Xc, Pc, C):
    """A head from teacher answers. Returns (head, temperature) or a reason it could not be trained."""
    k = Ptr.shape[1]
    if k == 2:
        ytr, yc = (Ptr[:, 1] >= 0.5).astype(int), (Pc[:, 1] >= 0.5).astype(int)
        if not (enough(ytr, "train") and enough(yc, "calib")):
            return f"too few teacher answers of each kind (train {int(ytr.sum())}/{len(ytr)})"
        clf = LogisticRegression(C=C, max_iter=4000)
        clf.fit(Xtr, ytr, sample_weight=np.abs(2 * Ptr[:, 1] - 1) + 1e-3)
        w, b = clf.coef_[0].astype(float), float(clf.intercept_[0])
        return {"w": w.tolist(), "b": b}, fit_temperature(Xc @ w + b, yc)
    ytr, yc = Ptr.argmax(1), Pc.argmax(1)
    common = [c for c in range(k) if int((ytr == c).sum()) >= MIN_EACH["train"]]
    if len(common) < 2:
        return f"the teacher gives fewer than two outcomes {MIN_EACH['train']} times"
    clf = LogisticRegression(C=C, max_iter=4000)
    clf.fit(Xtr, ytr)
    # One row per outcome, in outcome order; an outcome the teacher never chose can never win.
    W, b = np.zeros((k, Xtr.shape[1])), np.full(k, -20.0)
    rows = clf.coef_ if len(clf.classes_) > 2 else np.vstack([-clf.coef_[0] / 2, clf.coef_[0] / 2])
    bias = clf.intercept_ if len(clf.classes_) > 2 else np.array([-clf.intercept_[0] / 2, clf.intercept_[0] / 2])
    for row, c in enumerate(clf.classes_):
        W[c], b[c] = rows[row], bias[row]
    return {"W": W.tolist(), "b": b.tolist()}, fit_temperature_multi(Xc @ W.T + b, yc)


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
                   p.get("threads") or None, p.get("ort_arena"), p.get("tokenizer") or None)


def heads(run_dir, exp, lab, cache_dir):
    name = exp["providers"]["embedder"]
    rv = exp["render"]["version"]
    space = space_id(provider_cfg(exp), rv)
    cache = Cache(cache_dir, space)
    trained, temps, report = {}, {}, {}
    teacher = exp["heads"].get("teacher")
    for q in exp["heads"].get("questions", ["is_spam"]):
        if q not in LABELS and teacher:
            Xtr, Ptr = teacher_xy(lab, "train", rv, cache, teacher, q)
            Xc, Pc = teacher_xy(lab, "calib", rv, cache, teacher, q)
            if len(Xtr) == 0 or len(Xc) == 0:
                report[q] = "the teacher did not answer it"
                continue
            r = distil(Xtr, Ptr, Xc, Pc, float(exp["heads"]["C"]))
            if isinstance(r, str):
                report[q] = r
                continue
            trained[q], temps[q] = r
            report[q] = {"labels": f"teacher {teacher}", "temperature": temps[q], "train_n": int(len(Xtr))}
            continue
        if q not in LABELS:
            report[q] = "no labels in the lab"
            continue
        Xtr, ytr = xy(lab, "train", rv, cache, LABELS[q])
        Xc, yc = xy(lab, "calib", rv, cache, LABELS[q])
        if not (enough(ytr, "train") and enough(yc, "calib")):
            report[q] = f"too few labels (train {int(ytr.sum())}/{len(ytr)}, calib {int(yc.sum())}/{len(yc)})"
            continue
        clf = LogisticRegression(C=float(exp["heads"]["C"]), max_iter=4000)
        clf.fit(Xtr, ytr)
        w, b = clf.coef_[0].astype(float), float(clf.intercept_[0])
        trained[q] = {"w": w.tolist(), "b": b}
        temps[q] = fit_temperature(Xc @ w + b, yc)
        report[q] = {"labels": "lab", "temperature": temps[q], "train_n": int(len(ytr)), "train_pos": int(ytr.sum())}
    if not trained:
        sys.exit(f"no head could be trained: {report}")
    blob = b"".join(np.asarray(h.get("w", h.get("W")), dtype=np.float32).tobytes() + str(h["b"]).encode()
                    for _, h in sorted(trained.items()))
    # One head keeps the release id it always had; more heads hash their names too.
    if list(trained) != ["is_spam"]:
        blob += json.dumps(sorted(trained)).encode()
    release = f"heads:{name}:{hashlib.sha256(blob).hexdigest()[:10]}"
    json.dump({"release": release, "space": space, "questions": trained},
              open(os.path.join(run_dir, "heads.json"), "w"))
    json.dump({"release": release, "temperatures": temps}, open(os.path.join(run_dir, "calibration.json"), "w"))
    print(json.dumps({"release": release, "questions": report}))


MEMORY = "mailbox."
# Facts that are 1 when the mailbox knows nothing about the sender or the thread. In residual mode
# they are left out, so that mail from a stranger is decided exactly as without memory.
ABSENCE = {"mailbox.first_contact", "mailbox.unknown_thread"}
# Which way each mailbox fact may push P(junk). firstreadd refuses a combiner that breaks these,
# so the bounds below are not a tuning choice.
DIRECTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crates", "firstread-graph",
                          "data", "fact-directions.txt")


def directions():
    out = {}
    for line in open(DIRECTIONS):
        line = line.strip()
        if line and not line.startswith("#"):
            name, d = line.split()
            out[name] = d
    return out


def bound(name, dirs):
    d = dirs.get(name)
    if d == "raises":
        return (0.0, None)
    if d == "lowers":
        return (None, 0.0)
    sys.exit(f"{name}: no direction in {DIRECTIONS}")


def fit_logistic(X, y, exp):
    mu, sd = X.mean(0), X.std(0)
    keep = sd > 1e-9
    X, mu, sd = X[:, keep], mu[keep], sd[keep]
    l1 = float(exp["combiner"].get("l1_ratio", 0.0))
    # saga shuffles the data; a fixed seed makes the combiner, and so every decision, reproducible.
    clf = LogisticRegression(C=float(exp["combiner"]["C"]), max_iter=4000, l1_ratio=l1,
                             solver="saga" if l1 > 0 else "lbfgs", random_state=0)
    clf.fit((X - mu) / sd, y)
    w = clf.coef_[0] / sd
    b = float(clf.intercept_[0] - np.sum(clf.coef_[0] * mu / sd))
    return keep, w, b


def fit_residual(M, y, offset, C, bounds):
    """Memory weights on top of a fixed base logit: no intercept and no centring, so a message whose
    memory facts are all 0 keeps the base logit exactly. L2 penalty, scaled like sklearn's. Each
    weight stays within its fact's direction (`bounds`)."""
    from scipy.optimize import minimize
    sd = M.std(0)
    keep = sd > 1e-9
    Ms = M[:, keep] / sd[keep]

    def loss(w):
        z = offset + Ms @ w
        p = 1.0 / (1.0 + np.exp(-z))
        return C * np.sum(np.logaddexp(0.0, z) - y * z) + 0.5 * w @ w, C * Ms.T @ (p - y) + w

    w = np.zeros(M.shape[1])
    if Ms.shape[1] == 0:
        return w
    b = [bd for bd, k in zip(bounds, keep) if k]
    r = minimize(loss, np.zeros(Ms.shape[1]), jac=True, method="L-BFGS-B", bounds=b)
    w[keep] = r.x / sd[keep]
    return w


def combiner(run_dir, exp, lab, records_path):
    items = manifest(lab, "calib")
    label = {idem_key(it["path"], it["recipient"]): (1 if it["label"] == "junk" else 0) for it in items}
    order = {idem_key(it["path"], it["recipient"]): i for i, it in enumerate(items)}
    recs = [json.loads(l) for l in open(records_path)]
    recs = [r for r in recs if r["idempotency_key"] in label and not r["input"]["parse_failed"]]
    disabled = exp.get("combiner", {}).get("disabled", [])
    mode = exp.get("combiner", {}).get("memory", "joint")
    if mode == "residual":
        # Calib order, whatever order the records were written in (the learning test writes them
        # in date order): the base then gets exactly the rows, and so the fit, of a run without memory.
        recs.sort(key=lambda r: order[r["idempotency_key"]])
    names = sorted({k for r in recs for k in r["features"]})
    # A disabled entry removes a feature by exact name or by prefix ("links." removes all link facts).
    names = [n for n in names if not any(n.startswith(d) for d in disabled)]
    y = np.asarray([label[r["idempotency_key"]] for r in recs])
    if mode == "joint":
        X = np.asarray([[r["features"].get(n, 0.0) for n in names] for r in recs], dtype=float)
        keep, w, b = fit_logistic(X, y, exp)
        weights = {n: float(v) for n, v in zip([n for n, k in zip(names, keep) if k], w)}
        dirs = directions()
        wrong = [f"{n} = {v:+.3f}" for n, v in weights.items() if n.startswith(MEMORY)
                 and (bound(n, dirs)[0] is not None and v < 0 or bound(n, dirs)[1] is not None and v > 0)]
        if wrong:
            sys.exit("joint fit breaks fact directions (firstreadd would refuse it): " + ", ".join(wrong))
    elif mode == "residual":
        # The base is fitted without memory, exactly as a combiner without memory would be; memory
        # then only moves a decision where the mailbox knows the sender, its domain or the thread.
        base = [n for n in names if not n.startswith(MEMORY)]
        mem = [n for n in names if n.startswith(MEMORY) and n not in ABSENCE]
        X = np.asarray([[r["features"].get(n, 0.0) for n in base] for r in recs], dtype=float)
        keep, w, b = fit_logistic(X, y, exp)
        weights = {n: float(v) for n, v in zip([n for n, k in zip(base, keep) if k], w)}
        offset = b + X[:, keep] @ w
        M = np.asarray([[r["features"].get(n, 0.0) for n in mem] for r in recs], dtype=float)
        dirs = directions()
        bounds = [bound(n, dirs) for n in mem]
        for n, v in zip(mem, fit_residual(M, y, offset, float(exp["combiner"]["C"]), bounds)):
            if v != 0.0:
                weights[n] = float(v)
    else:
        sys.exit(f"combiner.memory: unknown mode {mode!r}")
    digest = hashlib.sha256(json.dumps(weights, sort_keys=True).encode() + str(b).encode()).hexdigest()[:10]
    json.dump({"release": f"combiner:{digest}", "bias": b, "weights": weights},
              open(os.path.join(run_dir, "combiner.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps({"release": f"combiner:{digest}", "inputs": len(weights), "calib_n": int(len(y))}))


def verdict(kind, run_dir, exp, lab, records_path):
    """The combiner of one more verdict over what the pipeline recorded for the calib split. For
    phishing and fraud mailbox facts are left out entirely, so nothing a mailbox owner taught can
    lower them (firstreadd refuses such a combiner)."""
    if kind not in VERDICT_LABELS:
        sys.exit(f"{kind}: no labels in the lab for this verdict")
    items = {idem_key(it["path"], it["recipient"]): it for it in manifest(lab, "calib")}
    recs = [json.loads(l) for l in open(records_path)]
    recs = [r for r in recs if r["idempotency_key"] in items and not r["input"]["parse_failed"]
            and VERDICT_LABELS[kind](items[r["idempotency_key"]]) is not None]
    y = np.asarray([VERDICT_LABELS[kind](items[r["idempotency_key"]]) for r in recs])
    if not enough(y, "calib"):
        sys.exit(f"{kind}: too few labels in calib ({int(y.sum())} of {len(y)})")
    disabled = exp.get("combiner", {}).get("disabled", [])
    names = sorted({k for r in recs for k in r["features"]})
    names = [n for n in names if not any(n.startswith(d) for d in disabled)
             and not (kind in SAFETY and n.startswith(MEMORY))]
    X = np.asarray([[r["features"].get(n, 0.0) for n in names] for r in recs], dtype=float)
    keep, w, b = fit_logistic(X, y, exp)
    weights = {n: float(v) for n, v in zip([n for n, k in zip(names, keep) if k], w)}
    digest = hashlib.sha256(json.dumps(weights, sort_keys=True).encode() + str(b).encode()).hexdigest()[:10]
    release = f"combiner-{kind}:{digest}"
    json.dump({"release": release, "bias": b, "weights": weights},
              open(os.path.join(run_dir, f"combiner-{kind}.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps({"release": release, "inputs": len(weights), "calib_n": int(len(y)), "calib_pos": int(y.sum())}))


if __name__ == "__main__":
    if sys.argv[1] == "verdict":
        kind, run_dir, exp_path, lab, records = sys.argv[2:7]
        verdict(kind, run_dir, tomllib.load(open(exp_path, "rb")), lab, records)
        sys.exit(0)
    stage, run_dir, exp_path, lab = sys.argv[1:5]
    exp = tomllib.load(open(exp_path, "rb"))
    if stage == "heads":
        heads(run_dir, exp, lab, sys.argv[5])
    else:
        combiner(run_dir, exp, lab, sys.argv[5])
