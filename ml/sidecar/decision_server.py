"""The tier-2 sidecar: Mica (sky7350/Mica-v0.5-4B) behind the provider contract (docs/14-providers.md).

Usage: python3 -I decision_server.py --socket PATH --mica URL --release ID [--timeout S]

Mica runs in its own server (akivet/Mica: llama.cpp with the Q8_0 GGUF on a CPU, its INT8 runtime on
an NVIDIA GPU), which renders the prompt and reads the answer labels exactly as the model was trained.
This sidecar only translates: our sidecar protocol in, Mica's `/v1/systemone` out. --mica must be a
loopback URL (http://127.0.0.1:8010): customer mail never leaves the machine. --release names the model,
its revision and runtime (e.g. mica-v0.5-4b@5ea7aafe-q8_0); calibrations are fitted for it.

Speaks the frames of `firstread-core::wire` like server.py, and declares "*": Mica reads each question's
text, so it can be asked any question, including rules people write in words:
  {"op": "manifest"} -> release, licence, commercial_use, supported ["*"], max_input_tokens
  {"op": "logits", "text": ..., "questions": [ids], "specs": [{"id", "text", "kind", "outcomes"}]}
      -> {"logits": [[...], ...]} in each question's outcome order
Mica returns probabilities (with its own temperature); their logarithms go back as logits, and the
daemon's calibration, fitted in the lab, decides (no calibration, no decision). At most 16 questions go
in one request, as many as Mica answers from one read of the mail.
"""
import argparse
import json
import math
import os
import socket
import struct
import sys
import urllib.parse
import urllib.request

MAX_QUESTIONS = 16
FLOOR = 1e-12


def mica_question(spec):
    """Our question as Mica's request format (its model card, "Request format")."""
    if spec["kind"] == "noul":
        return {"type": "noul", "instructions": spec["text"]}
    if spec["kind"] == "choice":
        return {"type": "choice", "instructions": spec["text"],
                "criteria": {o: o.replace("_", " ") for o in spec["outcomes"]}}
    return {"type": "score", "instructions": spec["text"], "criteria": list(spec["outcomes"])}


def logits_of(spec, answer):
    """Log-probabilities in our outcome order: noul (false, true); choice by option; score by level."""
    if spec["kind"] == "noul":
        p = [1.0 - answer["noul"], answer["noul"]]
    elif spec["kind"] == "choice":
        p = [answer["probabilities"][o] for o in spec["outcomes"]]
    else:
        p = [answer["probabilities"][str(i)] for i in range(len(spec["outcomes"]))]
    return [math.log(max(float(x), FLOOR)) for x in p]


def ask(url, timeout, text, specs):
    out = []
    for i in range(0, len(specs), MAX_QUESTIONS):
        chunk = specs[i:i + MAX_QUESTIONS]
        body = json.dumps({"state": text, "questions": {s["id"]: mica_question(s) for s in chunk}}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            answers = json.loads(r.read())["answers"]
        out += [logits_of(s, answers[s["id"]]) for s in chunk]
    return out


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--mica", required=True)
    ap.add_argument("--release", required=True)
    ap.add_argument("--timeout", type=float, default=120)
    a = ap.parse_args()
    host = urllib.parse.urlparse(a.mica).hostname
    if host not in ("127.0.0.1", "::1", "localhost"):
        sys.exit(f"--mica {a.mica}: only a server on this machine (customer mail never leaves it)")
    url = a.mica.rstrip("/") + "/v1/systemone"

    def handle(req):
        if req["op"] == "manifest":
            return {"release": a.release, "licence": "Apache-2.0", "commercial_use": True,
                    "languages": [], "max_input_tokens": 32768, "supported": ["*"]}
        if req["op"] == "logits":
            specs = req.get("specs") or []
            if [s["id"] for s in specs] != list(req["questions"]):
                return {"error": "specs must name the questions, in order"}
            return {"logits": ask(url, a.timeout, req["text"], specs)}
        return {"error": "unknown op"}

    if os.path.exists(a.socket):
        os.unlink(a.socket)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(a.socket)
    srv.listen(4)
    print(f"decision sidecar: {a.release} via {url} on {a.socket}", flush=True)
    while True:
        c, _ = srv.accept()
        try:
            n = struct.unpack(">I", recv_exact(c, 4))[0]
            body = json.dumps(handle(json.loads(recv_exact(c, n)))).encode()
            c.sendall(struct.pack(">I", len(body)) + body)
        except Exception as e:  # one bad request never takes the sidecar down
            print(f"decision sidecar: {e}", file=sys.stderr, flush=True)
        finally:
            c.close()


if __name__ == "__main__":
    main()
