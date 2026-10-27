"""Teacher labels for distillation (docs/04-models.md, Distillation).

Usage: python3 -I teach.py <lab_data> <decision_socket> [--splits train,calib,dev] [--every N]
                           [--questions FILE] [--render r1]

A decision model behind the sidecar protocol (ml/sidecar/decision_server.py) answers the whole
question catalogue (crates/firstread-stamp/data/questions.json) for lab messages, reading the same
rendered text the daemon sends to providers (<lab_data>/rendered/<split>.<render>.jsonl). Answers go
to <lab_data>/teacher/<release>/<split>.jsonl, one line per message: {"id", "text_sha256", "p": {question:
[probabilities in outcome order]}, "ms": wall time of the call}. A run that stops resumes where it stopped. --every N takes every
N-th message (the teacher costs seconds per message on a CPU).

Then the teacher is checked where the lab has human labels (ml/heads/train.py LABELS), as the design
asks before trusting it: per question the number of messages, accuracy at 0.5, and mean P(true) on
positives and negatives, written to agreement.json. Heads trained on its answers (train.py heads with
[heads] teacher) learn the teacher, mistakes included: agreement.json is how far that goes.

Only lab data, only a local model: the sidecar is reached over a Unix socket on this machine.
"""
import argparse
import json
import math
import os
import re
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
QUESTIONS = os.path.join(REPO, "crates", "firstread-stamp", "data", "questions.json")

ap = argparse.ArgumentParser()
ap.add_argument("lab")
ap.add_argument("socket")
ap.add_argument("--splits", default="train,calib,dev")
ap.add_argument("--every", type=int, default=1)
ap.add_argument("--questions", default=QUESTIONS)
ap.add_argument("--render", default="r1")
a = ap.parse_args()


def call(req):
    c = socket.socket(socket.AF_UNIX)
    c.connect(a.socket)
    b = json.dumps(req).encode()
    c.sendall(struct.pack(">I", len(b)) + b)
    n = struct.unpack(">I", c.recv(4))[0]
    d = b""
    while len(d) < n:
        chunk = c.recv(n - len(d))
        if not chunk:
            raise ConnectionError("short read")
        d += chunk
    return json.loads(d)


def softmax(z):
    m = max(z)
    e = [math.exp(x - m) for x in z]
    return [x / sum(e) for x in e]


def spec(q):
    outcomes = q.get("options") or q.get("levels") or []
    return {"id": q["id"], "text": q["text"], "kind": q["kind"], "outcomes": outcomes}


def main():
    m = call({"op": "manifest"})
    if "*" not in m.get("supported", []):
        sys.exit(f"{m.get('release')}: not a decision model (it does not read question texts)")
    specs = [spec(q) for q in json.load(open(a.questions))["questions"]]
    out_dir = os.path.join(a.lab, "teacher", re.sub(r"[^A-Za-z0-9._@-]", "_", m["release"]))
    os.makedirs(out_dir, exist_ok=True)
    json.dump({"release": m["release"], "questions": specs}, open(os.path.join(out_dir, "questions.json"), "w"))
    for split in a.splits.split(","):
        rows = [json.loads(l) for l in open(os.path.join(a.lab, "rendered", f"{split}.{a.render}.jsonl"))]
        rows = [r for r in rows if "text" in r][::a.every]
        path = os.path.join(out_dir, f"{split}.jsonl")
        done = {json.loads(l)["id"] for l in open(path)} if os.path.exists(path) else set()
        with open(path, "a") as f:
            for i, r in enumerate(rows):
                if r["id"] in done:
                    continue
                t0 = time.perf_counter()
                res = call({"op": "logits", "text": r["text"], "questions": [s["id"] for s in specs], "specs": specs})
                if "logits" not in res:
                    sys.exit(f"{r['id']}: {res}")
                p = {s["id"]: [round(x, 6) for x in softmax(z)] for s, z in zip(specs, res["logits"])}
                ms = round((time.perf_counter() - t0) * 1000)
                f.write(json.dumps({"id": r["id"], "text_sha256": r["text_sha256"], "ms": ms, "p": p}) + "\n")
                f.flush()
                print(f"{split} {i + 1}/{len(rows)}", file=sys.stderr, flush=True)
    agreement(out_dir)


def agreement(out_dir):
    sys.path.insert(0, os.path.join(REPO, "ml", "heads"))
    from labels import LABELS
    report = {}
    for split in a.splits.split(","):
        items = {it["id"]: it for it in map(json.loads, open(os.path.join(a.lab, "splits", f"{split}.jsonl")))}
        answers = [json.loads(l) for l in open(os.path.join(out_dir, f"{split}.jsonl"))]
        for q, label in LABELS.items():
            pairs = [(t["p"][q][1], label(items[t["id"]])) for t in answers if q in t["p"] and t["id"] in items]
            pairs = [(p, y) for p, y in pairs if y is not None]
            pos = [p for p, y in pairs if y == 1]
            neg = [p for p, y in pairs if y == 0]
            if not pairs:
                continue
            report.setdefault(split, {})[q] = {
                "n": len(pairs), "positives": len(pos),
                "accuracy_at_0.5": round(sum((p >= 0.5) == (y == 1) for p, y in pairs) / len(pairs), 4),
                "mean_p_true_positives": round(sum(pos) / len(pos), 4) if pos else None,
                "mean_p_true_negatives": round(sum(neg) / len(neg), 4) if neg else None,
            }
    json.dump(report, open(os.path.join(out_dir, "agreement.json"), "w"), indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
