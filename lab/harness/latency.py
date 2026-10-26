"""Cold embedding latency for one embedder configuration, one message at a time.

Usage: python3 -I latency.py <lab_data> --embedder NAME [--runtime R] [--precision P]
                             [--max-tokens N] [--threads N] [--n N]

Takes the first n dev texts by id (default 200), loads the embedder, warms it up on 5 texts,
then embeds each text alone (batch of one, no cache) and prints p50 / p90 / p99 in ms, the CPU
time per text and the peak resident memory of this process. run.py measures the same thing
through the real filter and daemon; this script isolates the model.
"""
import argparse
import json
import os
import resource
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ml", "sidecar"))
from providers import Embedder, add_config_args, from_args  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("lab")
add_config_args(ap)
ap.add_argument("--n", type=int, default=200)
a = ap.parse_args()
os.environ.setdefault("HF_HOME", os.path.join(a.lab, "hf"))
os.environ.setdefault("FIRSTREAD_ONNX_DIR", os.path.join(a.lab, "onnx"))
cfg = from_args(a)
rows = sorted((json.loads(l) for l in open(os.path.join(a.lab, "rendered", "dev.r1.jsonl"))), key=lambda r: r["id"])
texts = [r["text"] for r in rows if "text" in r][:a.n]
t_load = time.perf_counter()
emb = Embedder(cfg)
load_s = time.perf_counter() - t_load
for t in texts[:5]:
    emb.embed([t])
ms, cpu = [], []
for t in texts:
    c, s = time.process_time(), time.perf_counter()
    emb.embed([t])
    ms.append((time.perf_counter() - s) * 1000)
    cpu.append((time.process_time() - c) * 1000)
ms.sort()


def q(p):
    return ms[min(len(ms) - 1, max(0, int(round(p * len(ms))) - 1))]


peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
print(json.dumps({"config": {k: cfg[k] for k in ["name", "runtime", "precision", "max_tokens", "threads"]},
                  "n": len(ms), "load_s": round(load_s, 2), "p50_ms": round(q(0.5), 1), "p90_ms": round(q(0.9), 1),
                  "p99_ms": round(q(0.99), 1), "cpu_ms_per_text": round(sum(cpu) / len(cpu), 1),
                  "peak_rss_mb": round(peak, 1)}))
