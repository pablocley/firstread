"""lab/results/<tag>/results.tsv as a Markdown table, with latency, CPU and memory indexed to the baseline.

Usage: python3 -I lab/analysis/table.py <tag>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plots import indexed, rows  # noqa: E402

tag = sys.argv[1]
print("| # | change | cost / 1k | Δ quality, CI95 | latency | CPU | memory | axes | kept |")
print("|---|---|---|---|---|---|---|---|---|")
n = 0
for r in indexed(rows(tag)):
    desc, _, rest = r["desc"].partition(" | ")
    q = ""
    if " CI [" in rest:
        q = rest.split(" l x")[0].replace("q ", "").replace(" CI ", " ")
    gates = " (" + rest.split("gates ")[1] + ")" if "gates " in rest else ""
    kept = "baseline" if r["axes"] == "baseline" else ("**yes**" if r["status"] == "keep" else "no")
    if r["status"] == "keep" or r["axes"] == "baseline":
        label = str(n)
        n += 1
    else:
        label = ""
    axes = r["axes"].replace("q=", "q ").replace("l=", "l ").replace("f=", "f ").replace(",", ", ")
    print(f"| {label} | {desc}{gates} | {r['cost']:.1f} | {q} | {r['lat_i']:.2f} | {r['cpu_i']:.2f} | "
          f"{r['ram_i']:.2f} | {axes} | {kept} |")
