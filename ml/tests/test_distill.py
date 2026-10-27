"""Run: python3 -I ml/tests/test_distill.py (the lab's Python, lab/requirements.txt).

Distillation end to end on a fake lab: a stand-in Mica server (fake_mica.py, answering from the text)
behind the real decision_server.py labels the messages with ml/distill/teach.py; train.py distils a noul head and a
choice head (a matrix) from its answers next to the human-labelled is_spam head; server.py serves
them. Also checks the agreement report against the human labels.
"""
import hashlib, json, os, socket, struct, subprocess, sys, tempfile, time
import numpy as np
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, f"{REPO}/ml/sidecar")
from providers import Cache, resolve, space_id
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_mica

def teacher(text, q):
    """A stand-in teacher that answers from the text."""
    if q["type"] == "noul":
        yes = ("factuur" in text) if "money" in q["instructions"] else ("junk" in text)
        return fake_mica.typed(q, p_true=0.9 if yes else 0.1)
    if q["type"] == "choice":
        return fake_mica.typed(q, pick="request_action" if "betaal" in text else "inform")
    return {"type": "score", "probabilities": {str(i): 1.0 / len(q["criteria"]) for i in range(len(q["criteria"]))}}


def wait(path):
    for _ in range(200):
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise SystemExit(f"{path} never appeared")


def call(sock, req):
    c = socket.socket(socket.AF_UNIX); c.connect(sock)
    b = json.dumps(req).encode(); c.sendall(struct.pack(">I", len(b)) + b)
    n = struct.unpack(">I", c.recv(4))[0]; d = b""
    while len(d) < n:
        d += c.recv(n - len(d))
    return json.loads(d)


rng = np.random.default_rng(1)
lab, run = tempfile.mkdtemp(), tempfile.mkdtemp()
for d in ["splits", "rendered", "msgs"]:
    os.makedirs(f"{lab}/{d}")
cfg = resolve("e5-small", "onnx", "int8", 192, None, True, "sentencepiece")
space = space_id(cfg, "r1")
cache = Cache(f"{lab}/cache", space)
for split in ["train", "calib"]:
    items, rend = [], []
    for i in range(120):
        junk, money, pay = i % 2 == 0, i % 3 == 0, i % 4 == 0
        text = " ".join(w for w, on in [("junk", junk), ("factuur", money), ("betaal", pay), (f"m{i}", True)] if on)
        key = hashlib.sha256(text.encode()).hexdigest()
        v = rng.normal(size=8).astype(np.float32)
        v[0] += 3 if junk else -3
        v[1] += 3 if money else -3
        v[2] += 3 if pay else -3
        cache.put_many([(key, v)])
        iid = f"{split}-{i}"
        path = f"{lab}/msgs/{iid}.eml"; open(path, "w").write(text)
        items.append({"id": iid, "path": path, "recipient": "u@x", "label": "junk" if junk else "legit",
                      "slice": "sa", "subclass": None})
        rend.append({"id": iid, "text_sha256": key, "text": text})
    open(f"{lab}/splits/{split}.jsonl", "w").write("\n".join(map(json.dumps, items)) + "\n")
    open(f"{lab}/rendered/{split}.r1.jsonl", "w").write("\n".join(map(json.dumps, rend)) + "\n")
cache.db.commit()

url, _ = fake_mica.serve(teacher)
t2 = f"{run}/t2.sock"
p = subprocess.Popen([sys.executable, "-I", f"{REPO}/ml/sidecar/decision_server.py", "--socket", t2,
                      "--mica", url, "--release", "teacher@test"], stdout=subprocess.DEVNULL)
try:
    wait(t2)
    r = subprocess.run([sys.executable, "-I", f"{REPO}/ml/distill/teach.py", lab, t2, "--splits", "train,calib"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    again = subprocess.run([sys.executable, "-I", f"{REPO}/ml/distill/teach.py", lab, t2, "--splits", "train,calib"],
                           capture_output=True, text=True)
    assert "train 1/" not in again.stderr, "a finished run resumes without asking again"
finally:
    p.kill()
tdir = f"{lab}/teacher/teacher@test"
rows = [json.loads(l) for l in open(f"{tdir}/train.jsonl")]
assert len(rows) == 120 and len(rows[0]["p"]) == len(json.load(open(f"{REPO}/crates/firstread-stamp/data/questions.json"))["questions"])
agree = json.load(open(f"{tdir}/agreement.json"))
assert agree["train"]["is_spam"]["accuracy_at_0.5"] == 1.0, agree

open(f"{run}/exp.toml", "w").write('[providers]\nembedder = "e5-small"\nruntime = "onnx"\nprecision = "int8"\nmax_tokens = 192\n'
                                   'threads = 0\nort_arena = true\ntokenizer = "sentencepiece"\n[render]\nversion = "r1"\n'
                                   '[heads]\nC = 1.0\nquestions = ["is_spam", "topic_money", "intent", "urgency"]\n'
                                   'teacher = "teacher@test"\n')
r = subprocess.run([sys.executable, "-I", f"{REPO}/ml/heads/train.py", "heads", run, f"{run}/exp.toml", lab, f"{lab}/cache"],
                   capture_output=True, text=True)
assert r.returncode == 0, r.stderr
report = json.loads(r.stdout.strip().splitlines()[-1])["questions"]
assert report["is_spam"]["labels"] == "lab" and report["topic_money"]["labels"] == "teacher teacher@test", report
assert "fewer than two" in report["urgency"], "a flat teacher answer trains nothing"
heads = json.load(open(f"{run}/heads.json"))
assert len(heads["questions"]["intent"]["W"]) == 5 and "w" in heads["questions"]["topic_money"]

sock = f"{run}/s.sock"
srv = subprocess.Popen([sys.executable, "-I", f"{REPO}/ml/sidecar/server.py", "--socket", sock, "--embedder", "e5-small",
                        "--runtime", "onnx", "--precision", "int8", "--max-tokens", "192", "--tokenizer", "sentencepiece",
                        "--render-version", "r1", "--cache", f"{lab}/cache", "--heads", f"{run}/heads.json"],
                       stdout=subprocess.DEVNULL)
try:
    wait(sock)
    text = "factuur betaal m4"
    v = rng.normal(size=8).astype(np.float32); v[0] -= 3; v[1] += 3; v[2] += 3
    cache.put_many([(hashlib.sha256(text.encode()).hexdigest(), v)]); cache.db.commit()
    out = call(sock, {"op": "logits", "text": text, "questions": ["topic_money", "intent"]})["logits"]
    assert out[0][1] > 0, out
    assert int(np.argmax(out[1])) == 1, f"request_action wins: {out[1]}"
finally:
    srv.kill()
print("distillation ok")
