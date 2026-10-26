"""Run a queue of one-change experiments through lab/loop/exp.sh, in order, each on the champion of the moment.

Usage: python3 -I lab/loop/queue.py <queue.json>

Each entry: {"desc": "...", "set": [[section, key, value-literal], ...], "patch": optional path,
from the repository root, of a script that edits ml/heads/train.py in place (lab/loop/patches/)}.
A run whose latency or footprint came out `unmeasured` (machine noise) is repeated once.
"""
import json
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EXP = os.path.join(REPO, "lab", "experiment.toml")
SCRATCH = os.path.join(REPO, "lab", "loop")


def set_key(section, key, value):
    lines = open(EXP).read().split("\n")
    out, cur, done = [], None, False
    for i, line in enumerate(lines):
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            if cur == section and not done:
                out.append(f"{key} = {value}")
                done = True
            cur = m.group(1)
        if cur == section and re.match(rf"^{re.escape(key)}\s*=", line):
            out.append(f"{key} = {value}")
            done = True
            continue
        out.append(line)
    if not done:
        if cur != section:
            out.append(f"[{section}]")
        out.append(f"{key} = {value}")
    open(EXP, "w").write("\n".join(out))


def run(entry):
    for section, key, value in entry.get("set", []):
        set_key(section, key, value)
    if entry.get("patch"):
        subprocess.run([sys.executable, os.path.join(REPO, entry["patch"]), os.path.join(REPO, "ml", "heads", "train.py")],
                       check=True)
    p = subprocess.run(["bash", os.path.join(SCRATCH, "exp.sh"), entry["desc"]], capture_output=True, text=True)
    print(p.stdout[-3000:], p.stderr[-1000:], flush=True)
    last = open(os.path.join(REPO, "lab", "results.tsv")).read().strip().split("\n")[-1]
    return last


for entry in json.load(open(sys.argv[1])):
    last = run(entry)
    if "unmeasured" in last:
        print("RERUN (unmeasured)", flush=True)
        last = run(dict(entry, desc=entry["desc"] + " (rerun: noise)"))
    print("RESULT", last, flush=True)
print("QUEUE DONE", flush=True)
