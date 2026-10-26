"""Baseline against final champion in one interleaved timing pass, for the README's headline chart.

Usage: python3 -I lab/analysis/head_to_head.py <tag> <baseline_run> <champion_commit>

Points lab/runs/champion at the baseline run for the duration, checks out nothing: the working
tree's lab/experiment.toml must already be the champion's (it is, at the tip of the run branch).
Runs the harness into lab/runs/h2h-<commit>, restores the champion link, and writes
lab/results/<tag>/head-to-head.json with both arms of the timing pass and the quality comparison.
"""
import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
tag, base, champ = sys.argv[1:4]
link = os.path.join(REPO, "lab", "runs", "champion")
old = os.readlink(link)
run_dir = os.path.join(REPO, "lab", "runs", f"h2h-{champ}")
try:
    os.unlink(link)
    os.symlink(base, link)
    with open(os.path.join(REPO, "lab", "run-h2h.log"), "w") as log:
        subprocess.run([sys.executable, "-I", os.path.join(REPO, "lab", "harness", "run.py"), run_dir],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
finally:
    os.unlink(link)
    os.symlink(old, link)
s = json.load(open(os.path.join(run_dir, "summary.dev.json")))
base_s = json.load(open(os.path.join(REPO, "lab", "runs", base, "summary.dev.json")))
t = s["timing"]
out = {
    "title": (f"Baseline ({base}) and champion ({champ}) in one interleaved timing pass of {t['messages']} dev "
              f"messages; quality on the 967 primary dev messages"),
    "baseline": dict(t["A"], cost_per_1k=base_s["cost_per_1k"], false_positives=base_s["false_positives"],
                     false_negatives=base_s["false_negatives"], provider=base_s.get("provider")),
    "champion": dict(t["B"], cost_per_1k=s["cost_per_1k"], false_positives=s["false_positives"],
                     false_negatives=s["false_negatives"], provider=s.get("provider")),
    "ratios": {k: {"ratio": t[k]["ratio"], "ci95": t[k].get("ci95")} for k in ["latency", "cpu", "ram"]},
    "quality": s["quality"],
    "noise": {"other_cpu_cores": t["other_cpu_cores"], "steal_cores": t["steal_cores"]},
}
os.makedirs(os.path.join(REPO, "lab", "results", tag), exist_ok=True)
json.dump(out, open(os.path.join(REPO, "lab", "results", tag, "head-to-head.json"), "w"), indent=1)
print(json.dumps(out, indent=1))
