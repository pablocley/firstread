"""Fill the embedding cache for one space from rendered texts (`firstread render-batch` output).

Usage: python3 -I embed_batch.py --embedder NAME [--runtime R] [--precision P] [--max-tokens N]
                                 [--threads N] [--batch N] --render-version V --cache DIR
                                 <rendered.jsonl>...

One message per call by default, as delivery computes it: with int8 dynamic quantisation and
padding, a vector depends on what else is in the batch.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from providers import Cache, Embedder, add_config_args, from_args, space_id  # noqa: E402

ap = argparse.ArgumentParser()
add_config_args(ap)
ap.add_argument("--render-version", required=True)
ap.add_argument("--cache", required=True)
ap.add_argument("--batch", type=int, default=1)
ap.add_argument("rendered", nargs="+")
a = ap.parse_args()
cfg = from_args(a)
space = space_id(cfg, a.render_version)
cache = Cache(a.cache, space)
have = cache.keys()
todo = {}
for path in a.rendered:
    for line in open(path):
        r = json.loads(line)
        if "text" in r and r["text_sha256"] not in have:
            todo[r["text_sha256"]] = r["text"]
print(f"{space}: {len(todo)} to embed, {len(have)} cached", flush=True)
if not todo:
    sys.exit(0)
emb = Embedder(cfg)
items = list(todo.items())
t0 = time.time()
for i in range(0, len(items), a.batch):
    chunk = items[i:i + a.batch]
    vecs = emb.embed([t for _, t in chunk])
    cache.put_many(zip([k for k, _ in chunk], vecs))
    if (i // a.batch) % max(1, 400 // a.batch) == 0:
        print(f"  {i + len(chunk)}/{len(items)} in {time.time() - t0:.0f}s", flush=True)
print(f"done {len(items)} in {time.time() - t0:.0f}s", flush=True)
