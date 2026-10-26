"""The README charts, from committed lab results only.

Usage: python3 -I lab/analysis/plots.py <tag>      (reads lab/results/<tag>/, writes docs/img/)

- loop-<tag>-{light,dark}.svg: each kept step of the loop on each axis: cost per 1,000, and latency,
  CPU and memory indexed to the tag's baseline. Ratios are measured against the champion of the
  moment (interleaved timing pass), so a step's index is its ratio times its champion's index.
- head-to-head-<tag>-{light,dark}.svg: baseline and final champion measured in one interleaved
  timing pass (head-to-head.json), on each axis.
"""
import json
import os
import re
import sys

import matplotlib

matplotlib.use("svg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
THEMES = {
    "light": {"surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
              "grid": "#e1e0d9", "axis": "#c3c2b7", "series": "#2a78d6"},
    "dark": {"surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781",
             "grid": "#2c2c2a", "axis": "#383835", "series": "#3987e5"},
}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "svg.fonttype": "none", "svg.hashsalt": "firstread"})


def rows(tag):
    out = []
    for line in open(os.path.join(REPO, "lab", "results", tag, "results.tsv")):
        f = line.rstrip("\n").split("\t")
        if f[0] == "commit" or len(f) < 8 or f[6] == "crash":
            continue
        r = {"commit": f[0], "cost": float(f[1]), "axes": f[5], "status": f[6], "desc": f[7]}
        for k, key in [("l", "lat"), ("c", "cpu"), ("r", "ram")]:
            m = re.search(rf"\b{k} x([0-9.]+)", f[7])
            r[key] = float(m.group(1)) if m else None
        out.append(r)
    return out


def indexed(rs):
    champ = {"lat": 1.0, "cpu": 1.0, "ram": 1.0}
    for r in rs:
        if r["axes"] == "baseline":
            r.update(lat_i=1.0, cpu_i=1.0, ram_i=1.0)
            continue
        for k in ["lat", "cpu", "ram"]:
            r[k + "_i"] = champ[k] * r[k] if r[k] is not None else None
        if r["status"] == "keep":
            champ = {k: r[k + "_i"] for k in ["lat", "cpu", "ram"]}
    return [r for r in rs if r.get("lat_i") is not None]


def save(fig, path, t):
    """Write the SVG without a date and without indentation, so reruns are byte-identical and small."""
    fig.savefig(path, facecolor=t["surface"], metadata={"Date": None})
    plt.close(fig)
    svg = open(path).read()
    svg = re.sub(r">\s+<", "><", svg)
    svg = re.sub(r"<metadata>.*?</metadata>", "", svg, flags=re.S)
    svg = re.sub(r"<g id=\"[^\"]*\"", "<g", svg)
    svg = re.sub(r"<[^>]+>", lambda m: re.sub(r"(\d\.\d)\d+", r"\1", m.group(0)), svg)  # markup only, not labels
    svg = re.sub(r"\s*\n\s*", " ", svg)
    open(path, "w").write(svg)


def style(ax, t):
    ax.set_facecolor(t["surface"])
    for side in ["top", "right"]:
        ax.spines[side].set_visible(False)
    for side in ["left", "bottom"]:
        ax.spines[side].set_color(t["axis"])
    ax.tick_params(colors=t["ink2"], labelsize=9)
    ax.grid(True, color=t["grid"], linewidth=0.8)
    ax.set_axisbelow(True)


def loop_chart(tag, rs, mode):
    """One panel per axis, x = kept step (0 = baseline). Cost per 1,000 on the primary dev slice;
    latency, CPU and memory indexed to the baseline (each step's ratio against its champion, chained)."""
    t = THEMES[mode]
    kept = [r for r in rs if r["status"] == "keep" or r["axes"] == "baseline"]
    xs = list(range(len(kept)))
    panels = [("cost", "cost per 1,000 messages", "{:.0f}"), ("lat_i", "latency per email, index", "{:.2f}"),
              ("cpu_i", "CPU per email, index", "{:.2f}"), ("ram_i", "peak memory, index", "{:.2f}")]
    fig, axes = plt.subplots(1, 4, figsize=(10, 2.7), facecolor=t["surface"])
    for ax, (key, title, fmt) in zip(axes, panels):
        style(ax, t)
        ax.grid(True, axis="y", color=t["grid"], linewidth=0.8)
        ax.grid(False, axis="x")
        ys = [r[key] for r in kept]
        ax.plot(xs, ys, color=t["series"], linewidth=2, drawstyle="steps-post", zorder=3)
        ax.scatter(xs, ys, s=40, color=t["series"], edgecolors=t["surface"], linewidths=2, zorder=4)
        for i in [0, len(xs) - 1]:
            ax.annotate(fmt.format(ys[i]), (xs[i], ys[i]), xytext=(0, 7), textcoords="offset points",
                        ha="center", va="bottom", color=t["ink"], fontsize=8.5)
        ax.set_ylim(0, max(ys) * 1.25)
        ax.set_xticks(xs)
        ax.set_xlim(-0.5, len(xs) - 0.5)
        ax.set_title(title, color=t["ink"], fontsize=9.5, loc="left")
        ax.set_xlabel("kept step", color=t["ink2"], fontsize=9)
    fig.tight_layout()
    path = os.path.join(REPO, "docs", "img", f"loop-{tag}-{mode}.svg")
    save(fig, path, t)
    return path


def head_to_head_chart(tag, h, mode):
    """Baseline and champion from one interleaved timing pass, absolute values, one panel per axis."""
    t = THEMES[mode]
    panels = [("cost per 1,000", "cost_per_1k", "{:.0f}", None),
              ("latency, mean", "latency_mean_ms", "{:.0f} ms", "latency"),
              ("CPU per email", "cpu_ms_per_email", "{:.0f} ms", "cpu"),
              ("peak memory", "peak_mb", "{:,.0f} MB", "ram")]
    fig, axes = plt.subplots(1, 4, figsize=(10, 1.9), facecolor=t["surface"])
    for ax, (title, key, fmt, ratio) in zip(axes, panels):
        style(ax, t)
        ax.grid(False)
        vals = [h["baseline"][key], h["champion"][key]]
        bars = ax.barh([1, 0], vals, color=[t["muted"], t["series"]], height=0.62)
        for b, v in zip(bars, vals):
            ax.annotate(fmt.format(v), (b.get_width(), b.get_y() + b.get_height() / 2), xytext=(4, 0),
                        textcoords="offset points", va="center", color=t["ink"], fontsize=9)
        ax.set_yticks([1, 0], ["baseline", "champion"])
        ax.set_xticks([])
        ax.spines["bottom"].set_visible(False)
        ax.set_xlim(0, max(vals) * 1.6)
        r = h["ratios"][ratio]["ratio"] if ratio else vals[1] / vals[0]
        ax.set_title(f"{title}  ×{r:.2f}", color=t["ink"], fontsize=9.5, loc="left")
    fig.tight_layout()
    path = os.path.join(REPO, "docs", "img", f"head-to-head-{tag}-{mode}.svg")
    save(fig, path, t)
    return path


if __name__ == "__main__":
    tag = sys.argv[1]
    os.makedirs(os.path.join(REPO, "docs", "img"), exist_ok=True)
    rs = indexed(rows(tag))
    h2h = os.path.join(REPO, "lab", "results", tag, "head-to-head.json")
    for mode in THEMES:
        print(loop_chart(tag, rs, mode))
        if os.path.exists(h2h):
            print(head_to_head_chart(tag, json.load(open(h2h)), mode))
