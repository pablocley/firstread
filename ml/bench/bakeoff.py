"""Quick decision-model bake-off (Jev-Style 0.8B, the other candidate, was removed after it lost; its
run is in git at 2c029ae) on lab mail: separation (AUC) and time per mail, nothing more.

Usage: python3 -I bakeoff.py sample <lab_data> <out_dir> [--n-per-group 10]
       python3 -I bakeoff.py sidecar <decision_socket> <out_dir> --name NAME
       python3 -I bakeoff.py report <lab_data> <out_dir>

`sample` picks a fixed, seeded sample of the dev split (synthetic Dutch phishing, CEO and IBAN fraud,
legitimate invoices and reminders, other synthetic mail; SpamAssassin ham, hard ham and spam) with the
rendered text the daemon sends to providers. Mica then answers the four questions the lab has labels
for (ml/heads/labels.py), worded as in crates/firstread-stamp/data/questions.json, and writes its raw
score per question (log-odds of true, before any calibration) and the wall time per mail. `report` gives
per question the AUC against the labels and the accuracy at score 0, plus the e5 tier-1 head of
the lab run for is_spam. A cheap ranking signal, not an evaluation (docs/07-evaluation.md): the Dutch
phishing and fraud labels are synthetic.

sidecar: through ml/sidecar/decision_server.py in front of Mica's own server (llama.cpp on CPU), the path
firstreadd takes; score = log P(true) - log P(false). (The first run used transformers in BF16 instead;
that path is in git at 2c029ae.)
"""
import argparse
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
QS = ["is_spam", "risk_phishing", "risk_fraud", "asks_payment_or_bank_change"]
GROUPS = {
    "phishing": lambda it: it["slice"] == "synthetic_nl" and it["subclass"] == "phishing",
    "fraud": lambda it: it["slice"] == "synthetic_nl" and it["subclass"] in ("fraud_ceo", "fraud_iban"),
    "invoice": lambda it: it["slice"] == "synthetic_nl" and it["subclass"] in ("invoice", "reminder"),
    "synth_other_legit": lambda it: it["slice"] == "synthetic_nl" and it["label"] == "legit"
                                    and it["subclass"] not in ("invoice", "reminder"),
    "synth_spam": lambda it: it["slice"] == "synthetic_nl" and it["subclass"] == "spam",
    "sa_ham": lambda it: it["slice"] == "sa" and it["label"] == "legit",
    "sa_hard_ham": lambda it: it["slice"] == "sa_hard_ham",
    "sa_spam": lambda it: it["slice"] == "sa" and it["label"] == "junk",
}


def questions():
    qs = {q["id"]: q for q in json.load(open(os.path.join(REPO, "crates", "firstread-stamp", "data", "questions.json")))["questions"]}
    return [qs[q] for q in QS]


def sample(a):
    items = [json.loads(l) for l in open(os.path.join(a.lab, "splits", "dev.jsonl"))]
    rend = {r["id"]: r for r in map(json.loads, open(os.path.join(a.lab, "rendered", "dev.r1.jsonl")))}
    rng = random.Random(20261027)
    out = []
    for g, f in GROUPS.items():
        pick = sorted((it for it in items if f(it) and "text" in rend.get(it["id"], {})), key=lambda it: it["id"])
        rng.shuffle(pick)
        out += [{"id": it["id"], "group": g, "text": rend[it["id"]]["text"]} for it in pick[:a.n_per_group]]
    os.makedirs(a.out, exist_ok=True)
    json.dump(out, open(os.path.join(a.out, "sample.json"), "w"))
    print(f"{len(out)} messages: " + ", ".join(f"{g} {sum(o['group'] == g for o in out)}" for g in GROUPS))


def run(a, name, score_one, release):
    msgs = json.load(open(os.path.join(a.out, "sample.json")))
    rows = []
    for i, m in enumerate(msgs):
        t = time.perf_counter()
        scores = score_one(m["text"])
        rows.append({"id": m["id"], "ms": round((time.perf_counter() - t) * 1000), "scores": dict(zip(QS, scores))})
        print(f"{name} {i + 1}/{len(msgs)} {rows[-1]['ms']} ms", file=sys.stderr, flush=True)
    json.dump({"model": release, "threads": a.threads, "rows": rows}, open(os.path.join(a.out, f"{name}.json"), "w"))


def sidecar(a):
    """Through a decision sidecar (ml/sidecar/decision_server.py), the path firstreadd takes."""
    import socket
    import struct

    def call(req):
        c = socket.socket(socket.AF_UNIX); c.connect(a.socket)
        b = json.dumps(req).encode(); c.sendall(struct.pack(">I", len(b)) + b)
        n = struct.unpack(">I", c.recv(4))[0]; d = b""
        while len(d) < n:
            d += c.recv(n - len(d))
        return json.loads(d)
    release = call({"op": "manifest"})["release"]
    specs = [{"id": q["id"], "text": q["text"], "kind": "noul", "outcomes": []} for q in questions()]

    def one(text):
        z = call({"op": "logits", "text": text, "questions": QS, "specs": specs})["logits"]
        return [t - f for f, t in z]
    run(a, a.name, one, release)


def auc(pos, neg):
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return round(wins / (len(pos) * len(neg)), 3)


def report(a):
    sys.path.insert(0, os.path.join(REPO, "ml", "heads"))
    from labels import LABELS
    items = {it["id"]: it for it in map(json.loads, open(os.path.join(a.lab, "splits", "dev.jsonl")))}
    msgs = json.load(open(os.path.join(a.out, "sample.json")))
    ids = {m["id"] for m in msgs}
    results = {}
    for f in sorted(os.listdir(a.out)):
        if f in ("sample.json", "report.json") or not f.endswith(".json"):
            continue
        r = json.load(open(os.path.join(a.out, f)))
        r["rows"] = [x for x in r["rows"] if x["id"] in ids]
        res = {"model": r["model"], "ms_per_mail_median": sorted(x["ms"] for x in r["rows"])[len(r["rows"]) // 2]}
        for q in QS:
            pairs = [(x["scores"][q], LABELS[q](items[x["id"]])) for x in r["rows"]]
            pairs = [(s, y) for s, y in pairs if y is not None]
            res[q] = {"auc": auc([s for s, y in pairs if y], [s for s, y in pairs if not y]),
                      "acc_at_0": round(sum((s > 0) == bool(y) for s, y in pairs) / len(pairs), 3), "n": len(pairs)}
        results[f[:-5]] = res
    # The e5 tier-1 head of the lab run, for is_spam only (no other heads exist).
    import hashlib
    key = {}
    for i in ids:
        it = items[i]
        h = hashlib.sha256(open(it["path"], "rb").read()); h.update(b"\0"); h.update(it["recipient"].lower().encode())
        key[h.hexdigest()] = i
    recs = os.path.join(a.lab, "runs", "reproduce", "dev.records.jsonl")
    if os.path.exists(recs):
        pairs = [(r["features"].get("head.is_spam.logit"), LABELS["is_spam"](items[key[r["idempotency_key"]]]))
                 for r in map(json.loads, open(recs)) if r["idempotency_key"] in key]
        pairs = [(s, y) for s, y in pairs if s is not None]
        results["e5_head_tier1"] = {"model": "e5-small int8 + logistic head (lab champion)",
                                    "is_spam": {"auc": auc([s for s, y in pairs if y], [s for s, y in pairs if not y]),
                                                "n": len(pairs)}}
    json.dump(results, open(os.path.join(a.out, "report.json"), "w"), indent=1)
    print(json.dumps(results, indent=1))


ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
s = sub.add_parser("sample"); s.add_argument("lab"); s.add_argument("out"); s.add_argument("--n-per-group", type=int, default=10)
m = sub.add_parser("sidecar"); m.add_argument("socket"); m.add_argument("out"); m.add_argument("--name", required=True); m.add_argument("--threads", type=int, default=0)
r = sub.add_parser("report"); r.add_argument("lab"); r.add_argument("out")
a = ap.parse_args()
{"sample": sample, "sidecar": sidecar, "report": report}[a.cmd](a)
