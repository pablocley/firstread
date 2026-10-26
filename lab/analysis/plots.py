"""The README charts, from committed lab results only; plain SVG written directly, no plotting library.

Usage: python3 -I lab/analysis/plots.py <tag>      (reads lab/results/<tag>/, writes docs/img/)

- loop-<tag>-{light,dark}.svg: each kept step of the loop on each axis: cost per 1,000, and latency,
  CPU and memory indexed to the tag's baseline. Ratios are measured against the champion of the
  moment (interleaved timing pass), so a step's index is its ratio times its champion's index.
- head-to-head-<tag>-{light,dark}.svg: baseline and final champion measured in one interleaved
  timing pass (head-to-head.json), on each axis.
"""
import json
import math
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
THEMES = {
    "light": {"surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
              "grid": "#e1e0d9", "axis": "#c3c2b7", "series": "#2a78d6"},
    "dark": {"surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781",
             "grid": "#2c2c2a", "axis": "#383835", "series": "#3987e5"},
}
FONT = "font-family:system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"


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


def ticks(top):
    """Round axis ticks from 0 to at least `top`, four or five of them."""
    raw = top / 4
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in [1, 2, 2.5, 5, 10] if m * mag >= raw)
    n = math.ceil(top / step - 1e-9)
    return [round(i * step, 10) for i in range(n + 1)]


def svg(w, h, t, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'style="{FONT}"><rect width="{w}" height="{h}" fill="{t["surface"]}"/>{"".join(body)}</svg>\n')


def text(x, y, s, fill, size=11, anchor="start", weight=None):
    w = f' font-weight="{weight}"' if weight else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" text-anchor="{anchor}"{w}>{s}</text>'


def loop_chart(tag, rs, mode):
    """One panel per axis, x = kept step (0 = baseline). Cost per 1,000 on the primary dev slice;
    latency, CPU and memory indexed to the baseline (each step's ratio against its champion, chained)."""
    t = THEMES[mode]
    kept = [r for r in rs if r["status"] == "keep" or r["axes"] == "baseline"]
    panels = [("cost", "cost per 1,000 messages", "{:.0f}"), ("lat_i", "latency per email, index", "{:.2f}"),
              ("cpu_i", "CPU per email, index", "{:.2f}"), ("ram_i", "peak memory, index", "{:.2f}")]
    pw, h, left, top, bottom = 190, 200, 34, 30, 36
    body = []
    for k, (key, title, fmt) in enumerate(panels):
        x0 = k * pw + left
        x1 = (k + 1) * pw - 12
        y0, y1 = h - bottom, top
        ys = [r[key] for r in kept]
        tk = ticks(max(ys) * 1.15)
        sy = lambda v: y0 - (v / tk[-1]) * (y0 - y1)  # noqa: E731
        sx = lambda i: x0 + 8 + i * (x1 - x0 - 16) / (len(ys) - 1)  # noqa: E731
        body.append(text(k * pw + 4, 16, title, t["ink"], 12))
        for v in tk:
            body.append(f'<line x1="{x0}" x2="{x1}" y1="{sy(v):.1f}" y2="{sy(v):.1f}" stroke="{t["grid"]}"/>')
            body.append(text(x0 - 5, sy(v) + 4, f"{v:g}", t["ink2"], 10, "end"))
        body.append(f'<line x1="{x0}" x2="{x1}" y1="{y0}" y2="{y0}" stroke="{t["axis"]}"/>')
        for i in range(len(ys)):
            body.append(text(sx(i), y0 + 14, str(i), t["ink2"], 10, "middle"))
        body.append(text((x0 + x1) / 2, h - 6, "kept step", t["ink2"], 10, "middle"))
        d = f"M{sx(0):.1f},{sy(ys[0]):.1f}" + "".join(f"H{sx(i):.1f}V{sy(ys[i]):.1f}" for i in range(1, len(ys)))
        body.append(f'<path d="{d}" fill="none" stroke="{t["series"]}" stroke-width="2"/>')
        for i, v in enumerate(ys):
            body.append(f'<circle cx="{sx(i):.1f}" cy="{sy(v):.1f}" r="3.5" fill="{t["series"]}" '
                        f'stroke="{t["surface"]}" stroke-width="2"/>')
        for i in [0, len(ys) - 1]:
            body.append(text(sx(i), sy(ys[i]) - 8, fmt.format(ys[i]), t["ink"], 10.5, "middle"))
    path = os.path.join(REPO, "docs", "img", f"loop-{tag}-{mode}.svg")
    open(path, "w").write(svg(4 * pw, h, t, body))
    return path


def head_to_head_chart(tag, h, mode):
    """Baseline and champion from one interleaved timing pass, absolute values, one panel per axis."""
    t = THEMES[mode]
    panels = [("cost per 1,000", "cost_per_1k", "{:.0f}", None),
              ("latency, mean", "latency_mean_ms", "{:.0f} ms", "latency"),
              ("CPU per email", "cpu_ms_per_email", "{:.0f} ms", "cpu"),
              ("peak memory", "peak_mb", "{:,.0f} MB", "ram")]
    label_w, pw, height = 62, 174, 104
    body = [text(label_w - 8, 50, "baseline", t["ink2"], 11, "end"),
            text(label_w - 8, 84, "champion", t["ink2"], 11, "end")]
    for k, (title, key, fmt, ratio) in enumerate(panels):
        x0 = label_w + k * pw
        vals = [h["baseline"][key], h["champion"][key]]
        r = h["ratios"][ratio]["ratio"] if ratio else vals[1] / vals[0]
        body.append(f'<text x="{x0}" y="16" font-size="12" fill="{t["ink"]}">{title} '
                    f'<tspan fill="{t["ink2"]}">×{r:.2f}</tspan></text>')
        scale = (pw - 74) / max(vals)
        for j, (v, colour) in enumerate(zip(vals, [t["muted"], t["series"]])):
            y = 33 + j * 34
            body.append(f'<rect x="{x0}" y="{y}" width="{v * scale:.1f}" height="24" rx="2" fill="{colour}"/>')
            body.append(text(x0 + v * scale + 5, y + 16.5, fmt.format(v), t["ink"], 11))
        body.append(f'<line x1="{x0}" x2="{x0}" y1="28" y2="{height - 10}" stroke="{t["axis"]}"/>')
    path = os.path.join(REPO, "docs", "img", f"head-to-head-{tag}-{mode}.svg")
    open(path, "w").write(svg(label_w + 4 * pw, height, t, body))
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
