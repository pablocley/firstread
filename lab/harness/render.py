"""Render the provider text of every train, calib and dev message with the real pipeline renderer.

Usage: python3 -I render.py <lab_data> [--render-max-chars N]

Runs `firstread render-batch` (the daemon's own renderer) on each split manifest and writes
<lab_data>/rendered/<split>.r1.jsonl, the input the embedding caches are filled from. r1 is the
renderer at its default of 2,000 characters; another limit needs another render version.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
lab = os.path.abspath(sys.argv[1])
extra = sys.argv[2:]
version = "r1" if not extra else "r1-" + "-".join(extra).replace("--render-max-chars-", "c")
os.makedirs(os.path.join(lab, "rendered"), exist_ok=True)
for split in ["train", "calib", "dev"]:
    out = os.path.join(lab, "rendered", f"{split}.{version}.jsonl")
    with open(out, "w") as f:
        subprocess.run([os.path.join(REPO, "target", "release", "firstread"), "render-batch",
                        os.path.join(lab, "splits", f"{split}.jsonl")] + extra, stdout=f, check=True)
    print(f"{out}: {sum(1 for _ in open(out))} texts")
