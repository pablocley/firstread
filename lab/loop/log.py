"""Append one lab/results.tsv row, and a lab/pareto.tsv row when the gates passed, from a run's summary.

Usage: python3 -I log.py <commit> "<description>"
"""
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
c, desc = sys.argv[1], sys.argv[2]
s = json.load(open(os.path.join(REPO, "lab", "runs", c, "summary.dev.json")))
B = s.get("timing", {}).get("B", {})
axes = s.get("axes")
ax = ",".join(f"{k[0]}={v}" for k, v in axes.items()) if axes else s["gates"]
status = "keep" if s.get("keep") == "yes" else "discard"
q = s.get("quality", {})
extra = f" | q {q['point_per_1k']:+.1f} CI [{q['ci95_per_1k'][0]:+.1f},{q['ci95_per_1k'][1]:+.1f}]" if q else ""
for k in ["latency", "cpu", "ram"]:
    if k in s.get("timing", {}):
        extra += f" {k[0]} x{s['timing'][k]['ratio']:.3f}"
if s["gates"] != "pass":
    extra += f" gates {s['gates']}"
row = [c, f"{s['cost_per_1k']:.2f}", f"{B.get('latency_mean_ms', 0):.1f}", f"{B.get('cpu_ms_per_email', 0):.1f}",
       f"{B.get('peak_mb', 0):.0f}", ax, status, desc + extra]
open(os.path.join(REPO, "lab", "results.tsv"), "a").write("\t".join(row) + "\n")
if s["gates"] == "pass":
    p = s.get("provider") or {}
    prov = s["embedder"] + (f" {p['runtime']}-{p['precision']} t{p['max_tokens']} th{p['threads']}" if p else "")
    open(os.path.join(REPO, "lab", "pareto.tsv"), "a").write("\t".join(
        [c, prov, f"{s['cost_per_1k']:.2f}", f"{B.get('latency_mean_ms', 0):.1f}", f"{B.get('cpu_ms_per_email', 0):.1f}",
         f"{B.get('peak_mb', 0):.0f}", status]) + "\n")
print("\t".join(row))
