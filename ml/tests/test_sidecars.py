"""Run: python3 -I ml/tests/test_sidecars.py (the lab's Python, lab/requirements.txt).

Both sidecars over their real socket protocol: server.py with a noul head and a choice head
(matrix), answering from the embedding cache; decision_server.py with a stand-in for the model's
own JevStyleDecision, checking that its probabilities come back as logits in outcome order.
"""
import hashlib, json, math, os, socket, struct, subprocess, sys, tempfile, time
import numpy as np
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, f"{REPO}/ml/sidecar")
from providers import Cache, resolve, space_id

FAKE_JEV = """class JevStyleDecision:
    def __init__(self, d, device, dtype): pass
    def decide_many(self, state, qs):
        assert "email" in state
        out = []
        for q in qs:
            if q["t"] == "noul": p = {"true": 0.9, "false": 0.1}
            elif q["t"] == "choice": p = {k: (0.7 if i == 1 else 0.3 / (len(q["crit"]) - 1)) for i, k in enumerate(q["crit"])}
            else: p = {str(i): (1.0 if i == 4 else 0.0) for i in range(len(q["crit"]))}
            out.append({"probabilities": p})
        return out
"""


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


def heads_server():
    d = tempfile.mkdtemp(); sock = f"{d}/s.sock"
    cfg = resolve("e5-small", "onnx", "int8", 192, None, True, "sentencepiece"); space = space_id(cfg, "r1")
    c = Cache(f"{d}/cache", space); text = "Subject: hi"
    c.put_many([(hashlib.sha256(text.encode()).hexdigest(), np.array([1.0, 2.0], dtype=np.float32))]); c.db.commit()
    json.dump({"release": "h@1", "space": space, "questions": {
        "is_spam": {"w": [1.0, 1.0], "b": 0.5},
        "intent": {"W": [[1, 0], [0, 1], [1, 1]], "b": [0.0, 0.0, -1.0]}}}, open(f"{d}/heads.json", "w"))
    p = subprocess.Popen([sys.executable, "-I", f"{REPO}/ml/sidecar/server.py", "--socket", sock, "--embedder", "e5-small",
                          "--runtime", "onnx", "--precision", "int8", "--max-tokens", "192", "--tokenizer", "sentencepiece",
                          "--render-version", "r1", "--cache", f"{d}/cache", "--heads", f"{d}/heads.json"],
                         stdout=subprocess.DEVNULL)
    try:
        wait(sock)
        r = call(sock, {"op": "logits", "text": text, "questions": ["is_spam", "intent"]})
        assert r["logits"] == [[0.0, 3.5], [1.0, 2.0, 2.0]], r
    finally:
        p.kill()


def decision_server():
    d = tempfile.mkdtemp(); sock = f"{d}/t2.sock"; model = f"{d}/model"
    os.makedirs(model)
    open(f"{model}/jev_style_decision.py", "w").write(FAKE_JEV)
    open(f"{model}/torch.py", "w").write("def set_num_threads(n):\n    pass\n")
    p = subprocess.Popen([sys.executable, "-I", f"{REPO}/ml/sidecar/decision_server.py", "--socket", sock,
                          "--model-dir", model, "--release", "fake@1"], stdout=subprocess.DEVNULL)
    try:
        wait(sock)
        m = call(sock, {"op": "manifest"})
        assert m["supported"] == ["*"] and m["release"] == "fake@1" and m["commercial_use"] is True
        specs = [{"id": "rule:bank", "text": "Mail from my bank", "kind": "noul", "outcomes": []},
                 {"id": "intent", "text": "What?", "kind": "choice", "outcomes": ["inform", "request_action", "sell"]},
                 {"id": "urgency", "text": "How urgent?", "kind": "score", "outcomes": ["a", "b", "c", "d", "e", "f"]}]
        r = call(sock, {"op": "logits", "text": "Subject: x", "questions": [s["id"] for s in specs], "specs": specs})
        sm = lambda z: [math.exp(x) / sum(math.exp(y) for y in z) for x in z]
        assert abs(sm(r["logits"][0])[1] - 0.9) < 1e-6, r
        assert abs(sm(r["logits"][1])[1] - 0.7) < 1e-6, r
        assert sm(r["logits"][2])[4] > 0.999, r
        assert "error" in call(sock, {"op": "logits", "text": "x", "questions": ["a"], "specs": []})
    finally:
        p.kill()


heads_server()
decision_server()
print("sidecars ok")
