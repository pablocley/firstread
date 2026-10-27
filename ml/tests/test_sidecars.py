"""Run: python3 -I ml/tests/test_sidecars.py (the lab's Python, lab/requirements.txt).

Both sidecars over their real socket protocol: server.py with a noul head and a choice head
(matrix), answering from the embedding cache; decision_server.py in front of a stand-in
Mica server (fake_mica.py), checking requests in Mica's format, at most 16 questions per read, and
answers back as logits in outcome order; a non-loopback Mica URL is refused.
"""
import hashlib, json, math, os, socket, struct, subprocess, sys, tempfile, time
import numpy as np
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, f"{REPO}/ml/sidecar")
from providers import Cache, resolve, space_id
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_mica

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
    def answer(text, q):
        if q["type"] == "noul":
            return fake_mica.typed(q, p_true=0.9)
        return fake_mica.typed(q, pick="request_action", level=4)
    url, seen = fake_mica.serve(answer)
    d = tempfile.mkdtemp(); sock = f"{d}/t2.sock"
    bad = subprocess.run([sys.executable, "-I", f"{REPO}/ml/sidecar/decision_server.py", "--socket", sock,
                          "--mica", "http://example.org:8010", "--release", "x"], capture_output=True, text=True)
    assert bad.returncode != 0 and "only a server on this machine" in bad.stderr
    p = subprocess.Popen([sys.executable, "-I", f"{REPO}/ml/sidecar/decision_server.py", "--socket", sock,
                          "--mica", url, "--release", "mica@test"], stdout=subprocess.DEVNULL)
    try:
        wait(sock)
        m = call(sock, {"op": "manifest"})
        assert m["supported"] == ["*"] and m["release"] == "mica@test" and m["commercial_use"] is True
        specs = [{"id": "rule:bank", "text": "Mail from my bank", "kind": "noul", "outcomes": []},
                 {"id": "intent", "text": "What?", "kind": "choice", "outcomes": ["inform", "request_action", "sell"]},
                 {"id": "urgency", "text": "How urgent?", "kind": "score", "outcomes": ["a", "b", "c", "d", "e", "f"]}]
        specs += [{"id": f"topic_{i}", "text": f"About {i}?", "kind": "noul", "outcomes": []} for i in range(20)]
        r = call(sock, {"op": "logits", "text": "Subject: x", "questions": [s["id"] for s in specs], "specs": specs})
        sm = lambda z: [math.exp(x) / sum(math.exp(y) for y in z) for x in z]
        assert len(r["logits"]) == 23
        assert abs(sm(r["logits"][0])[1] - 0.9) < 1e-6, r
        assert abs(sm(r["logits"][1])[1] - 0.8) < 1e-6, r
        assert sm(r["logits"][2])[4] > 0.999, r
        assert [len(x["questions"]) for x in seen] == [16, 7], "at most 16 questions per read"
        assert seen[0]["questions"]["intent"]["criteria"]["request_action"] == "request action"
        assert "error" in call(sock, {"op": "logits", "text": "x", "questions": ["a"], "specs": []})
    finally:
        p.kill()


heads_server()
decision_server()
print("sidecars ok")
