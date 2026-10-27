"""Run: python3 -I ml/tests/test_train.py (the lab's Python, lab/requirements.txt).

Fake lab: checks train.py heads (multi-question, label gating, unchanged single-head release id)
and verdict combiners (safety verdicts never see mailbox facts)."""
import hashlib, json, os, subprocess, sys, tempfile
import numpy as np
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "ml", "sidecar"))
from providers import Cache, resolve, space_id

rng = np.random.default_rng(0)
lab = tempfile.mkdtemp(); run = tempfile.mkdtemp()
os.makedirs(f"{lab}/splits"); os.makedirs(f"{lab}/rendered"); os.makedirs(f"{lab}/msgs")
cfg = resolve("e5-small", "onnx", "int8", 192, None, True, "sentencepiece")
space = space_id(cfg, "r1")
cache = Cache(f"{lab}/cache", space)
kinds = [("legit", "sa", None)] * 60 + [("junk", "sa", None)] * 40 + \
        [("junk", "synthetic_nl", "phishing")] * 30 + [("junk", "synthetic_nl", "spam")] * 30 + \
        [("legit", "synthetic_nl", "invoice")] * 25 + [("junk", "synthetic_nl", "fraud_iban")] * 3
records = []
for split in ["train", "calib"]:
    items, rend = [], []
    for i, (label, sl, sub) in enumerate(kinds):
        iid = f"{split}-{i}"
        v = rng.normal(size=8).astype(np.float32)
        v[0] += 3 if label == "junk" else -3
        v[1] += 3 if sub == "phishing" else -3
        key = hashlib.sha256(iid.encode()).hexdigest()
        cache.put_many([(key, v)])
        path = f"{lab}/msgs/{iid}.eml"; open(path, "w").write(iid)
        items.append({"id": iid, "path": path, "recipient": "u@x", "label": label, "slice": sl, "subclass": sub})
        rend.append({"id": iid, "text_sha256": key})
        if split == "calib":
            h = hashlib.sha256(open(path, "rb").read()); h.update(b"\0"); h.update(b"u@x")
            records.append({"idempotency_key": h.hexdigest(), "input": {"parse_failed": False},
                            "features": {"links.ip_literal": float(sub == "phishing") + rng.random() * 0.1,
                                         "subject.caps_ratio": float(label == "junk") + rng.random() * 0.1,
                                         "mailbox.sender_ok_log": rng.random()}})
    open(f"{lab}/splits/{split}.jsonl", "w").write("\n".join(map(json.dumps, items)) + "\n")
    open(f"{lab}/rendered/{split}.r1.jsonl", "w").write("\n".join(map(json.dumps, rend)) + "\n")
cache.db.commit()
open(f"{lab}/calib.jsonl", "w").write("\n".join(map(json.dumps, records)) + "\n")

def exp(questions):
    q = "" if questions is None else f"questions = {json.dumps(questions)}\n"
    p = f"{run}/exp.toml"
    open(p, "w").write(f"""[providers]\nembedder = "e5-small"\nruntime = "onnx"\nprecision = "int8"\nmax_tokens = 192\nthreads = 0\nort_arena = true\ntokenizer = "sentencepiece"\n[render]\nversion = "r1"\n[heads]\nC = 1.0\n{q}[combiner]\nC = 4.0\nl1_ratio = 0.0\ndisabled = []\n""")
    return p

def train(*args):
    r = subprocess.run([sys.executable, "-I", f"{REPO}/ml/heads/train.py", *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])

one = train("heads", run, exp(None), lab, f"{lab}/cache")
h = json.load(open(f"{run}/heads.json"))
assert list(h["questions"]) == ["is_spam"], h["questions"].keys()
w = np.asarray(h["questions"]["is_spam"]["w"], dtype=np.float32); b = h["questions"]["is_spam"]["b"]
assert one["release"] == "heads:e5-small:" + hashlib.sha256(w.tobytes() + str(b).encode()).hexdigest()[:10], "single-head release id as before"
many = train("heads", run, exp(["is_spam", "risk_phishing", "risk_fraud", "intent"]), lab, f"{lab}/cache")
h = json.load(open(f"{run}/heads.json")); cal = json.load(open(f"{run}/calibration.json"))
assert sorted(h["questions"]) == ["is_spam", "risk_phishing"], h["questions"].keys()
assert sorted(cal["temperatures"]) == ["is_spam", "risk_phishing"]
assert "too few" in many["questions"]["risk_fraud"] and many["questions"]["intent"] == "no labels in the lab"
assert many["questions"]["risk_phishing"]["train_n"] == 60 + 30 + 30 + 25 + 3, "sa junk left out of phishing"
v = train("verdict", "phishing", run, exp(None), lab, f"{lab}/calib.jsonl")
c = json.load(open(f"{run}/combiner-phishing.json"))
assert not any(k.startswith("mailbox.") for k in c["weights"]), c["weights"]
assert c["weights"]["links.ip_literal"] > 0
j = train("verdict", "junk", run, exp(None), lab, f"{lab}/calib.jsonl")
assert "mailbox.sender_ok_log" in json.load(open(f"{run}/combiner-junk.json"))["weights"]
r = subprocess.run([sys.executable, "-I", f"{REPO}/ml/heads/train.py", "verdict", "important", run, exp(None), lab, f"{lab}/calib.jsonl"], capture_output=True, text=True)
assert r.returncode != 0 and "no labels" in r.stderr
print("train.py ok:", one["release"], many["release"], v["release"])
