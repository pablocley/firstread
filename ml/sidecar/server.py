"""The tier-1 sidecar: a local provider the daemon reaches over a Unix socket.

Usage: python3 -I server.py --socket PATH --embedder NAME [--runtime R] [--precision P]
                            [--max-tokens N] [--threads N] --render-version V --cache DIR
                            --heads FILE [--no-cache] [--preload] [--stats FILE]

Speaks the frames of `firstread-core::wire` (4-byte big-endian length, then JSON):
  {"op": "manifest"} -> release, licence, commercial_use, supported questions, max_input_tokens
  {"op": "logits", "text": ..., "questions": [...]} -> {"logits": [[...], ...]}
Raw logits only; calibration happens in the daemon (no calibration, no decision).

--no-cache computes every vector (the lab's latency pass); --preload loads the model before the
socket opens, as a production sidecar would; --stats appends one JSON line per logits request with
the process CPU time and wall time it took.
"""
import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from providers import Cache, Embedder, add_config_args, from_args, space_id  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--socket", required=True)
add_config_args(ap)
ap.add_argument("--render-version", required=True)
ap.add_argument("--cache", required=True)
ap.add_argument("--heads", required=True)
ap.add_argument("--no-cache", action="store_true")
ap.add_argument("--preload", action="store_true")
ap.add_argument("--stats")
a = ap.parse_args()

cfg = from_args(a)
space = space_id(cfg, a.render_version)
heads = json.load(open(a.heads))
if heads["space"] != space:
    sys.exit(f"heads were trained in space {heads['space']}, not {space}")
# A noul head is a vector ("w", "b": one logit for true); a choice or score head is a matrix ("W", "b": one
# logit per outcome, in outcome order).
W = {q: ((np.asarray(h["W"], dtype=np.float32), np.asarray(h["b"], dtype=np.float32)) if "W" in h
         else (np.asarray(h["w"], dtype=np.float32), float(h["b"])))
     for q, h in heads["questions"].items()}
cache = None if a.no_cache else Cache(a.cache, space)
embedder = Embedder(cfg) if a.preload else None
stats = open(a.stats, "a") if a.stats else None


def vector(text):
    global embedder
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    v = cache.get(key) if cache else None
    if v is None:
        if embedder is None:
            embedder = Embedder(cfg)
        v = embedder.embed([text])[0]
        if cache:
            cache.put_many([(key, v)])
    return v


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def handle(req):
    if req["op"] == "manifest":
        return {"release": heads["release"], "licence": cfg["licence"], "commercial_use": cfg["commercial_use"],
                "languages": [], "max_input_tokens": cfg["max_tokens"] or 100000, "supported": sorted(W)}
    if req["op"] == "logits":
        c0, w0 = time.process_time(), time.perf_counter()
        v = vector(req["text"])
        out = []
        for q in req["questions"]:
            w, b = W[q]
            out.append((w @ v + b).tolist() if w.ndim == 2 else [0.0, float(v @ w + b)])
        if stats:
            stats.write(json.dumps({"key": hashlib.sha256(req["text"].encode("utf-8")).hexdigest(),
                                    "cpu_ms": (time.process_time() - c0) * 1000,
                                    "wall_ms": (time.perf_counter() - w0) * 1000}) + "\n")
            stats.flush()
        return {"logits": out}
    return {"error": "unknown op"}


if os.path.exists(a.socket):
    os.unlink(a.socket)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(a.socket)
srv.listen(16)
print(f"sidecar: {heads['release']} in {space} on {a.socket}", flush=True)
while True:
    c, _ = srv.accept()
    try:
        n = struct.unpack(">I", recv_exact(c, 4))[0]
        req = json.loads(recv_exact(c, n))
        body = json.dumps(handle(req)).encode()
        c.sendall(struct.pack(">I", len(body)) + body)
    except Exception as e:  # one bad request never takes the sidecar down
        print(f"sidecar: {e}", file=sys.stderr, flush=True)
    finally:
        c.close()
