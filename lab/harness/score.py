"""The lab's scorer (docs/13-lab.md section 5). Read-only to the research agent.

Cost per 1,000 messages from the cost table, per slice; hard gates; a paired bootstrap against
the champion; calibration error; latency. The primary slice (what the keep rule uses) is the
within-source SpamAssassin data, the only public set here with ham and spam from one collection.
"""
import hashlib
import json
import math
import random

PRIMARY = {"sa", "sa_hard_ham"}


def cost_class(item):
    if item["label"] == "junk":
        sub = item["subclass"]
        if sub == "phishing":
            return "phishing"
        if sub.startswith("fraud"):
            return "fraud"
        return "junk"
    sub = item["subclass"]
    if sub == "newsletter" or sub.startswith("list:"):
        return "bulk_wanted"
    if sub == "machine":
        return "machine"
    return "personal_or_business"


def idem_key(path, recipient):
    h = hashlib.sha256(open(path, "rb").read())
    h.update(b"\0")
    h.update(recipient.lower().encode())
    return h.hexdigest()


def action(record):
    return "junk" if record["directive"].get("folder") == "junk" else "inbox"


def join(items, records):
    by_key = {r["idempotency_key"]: r for r in records}
    rows = []
    for it in items:
        r = by_key.get(idem_key(it["path"], it["recipient"]))
        rows.append((it, r))
    return rows


def per_message_cost(rows, costs):
    out = []
    for it, r in rows:
        act = action(r) if r else "inbox"
        out.append(costs[cost_class(it)][act])
    return out


def per1k(values):
    return 1000.0 * sum(values) / max(1, len(values))


def ece(rows, bins=10):
    pairs = [(r["p_junk"], 1 if it["label"] == "junk" else 0) for it, r in rows if r and r.get("p_junk") is not None]
    if not pairs:
        return float("nan")
    total = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, y) for p, y in pairs if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if sel:
            conf = sum(p for p, _ in sel) / len(sel)
            acc = sum(y for _, y in sel) / len(sel)
            total += len(sel) / len(pairs) * abs(conf - acc)
    return total


def pct(values, q):
    if not values:
        return float("nan")
    s = sorted(values)
    return s[min(len(s) - 1, int(math.ceil(q * len(s))) - 1)]


def bootstrap(delta, n=2000, seed=7):
    rng = random.Random(seed)
    means = []
    for _ in range(n):
        sample = [delta[rng.randrange(len(delta))] for _ in delta]
        means.append(sum(sample) / len(sample))
    means.sort()
    return means[int(0.025 * n)], means[int(0.975 * n) - 1]


def score(items, records, costs, champion_records=None, wall_ms=None):
    rows = join(items, records)
    missing = sum(1 for _, r in rows if r is None)
    slices = {}
    for (it, r), c in zip(rows, per_message_cost(rows, costs)):
        slices.setdefault(it["slice"], []).append(c)
    primary_rows = [(it, r) for it, r in rows if it["slice"] in PRIMARY]
    primary_costs = per_message_cost(primary_rows, costs)
    fp = sorted(it["id"] for it, r in rows if it["label"] == "legit" and r and action(r) == "junk")
    fn = sum(1 for it, r in rows if it["label"] == "junk" and (not r or action(r) == "inbox"))
    hard_fp = sorted(it["id"] for it, r in rows if it["hard_negative"] and r and action(r) == "junk")
    totals = [r["provenance"]["timings_us"].get("total", 0) / 1000 for _, r in rows if r]
    out = {
        "cost_per_1k": per1k(primary_costs),
        "cost_per_1k_by_slice": {k: per1k(v) for k, v in sorted(slices.items())},
        "n": len(rows), "missing_records": missing,
        "false_positives": len(fp), "false_negatives": fn,
        "hard_negative_fp": hard_fp,
        "ece_primary": ece(primary_rows),
        "daemon_p50_ms": pct(totals, 0.5), "daemon_p99_ms": pct(totals, 0.99),
        "errors": sum(1 for _, r in rows if r and r["provenance"]["errors"]),
        "not_allowed": sum(1 for _, r in rows if r and any("NotAllowed" in e for e in r["provenance"]["errors"])),
    }
    if wall_ms:
        out["filter_p50_ms"], out["filter_p99_ms"] = pct(wall_ms, 0.5), pct(wall_ms, 0.99)
    if champion_records is not None:
        champ_rows = join(items, champion_records)
        champ_primary = [(it, r) for it, r in champ_rows if it["slice"] in PRIMARY]
        champ_costs = per_message_cost(champ_primary, costs)
        delta = [a - b for a, b in zip(primary_costs, champ_costs)]
        lo, hi = bootstrap(delta)
        champ_hard_fp = {it["id"] for it, r in champ_rows if it["hard_negative"] and r and action(r) == "junk"}
        out["champion_cost_per_1k"] = per1k(champ_costs)
        out["delta_per_1k_ci95"] = [1000 * lo, 1000 * hi]
        out["significant"] = hi < 0
        out["new_hard_negative_fp"] = sorted(set(hard_fp) - champ_hard_fp)
    return out


def compare(items, records, other_records, costs):
    """Paired comparison of two runs on the same items: the quality axis of the keep rule.

    Returns the primary-slice cost difference (point and bootstrap CI95, per 1,000), the legitimate
    messages this run files in Junk that the other did not (any slice), and the slices whose cost
    is significantly worse.
    """
    rows, other = join(items, records), join(items, other_records)
    mine, theirs = per_message_cost(rows, costs), per_message_cost(other, costs)
    prim = [i for i, (it, _) in enumerate(rows) if it["slice"] in PRIMARY]
    delta = [mine[i] - theirs[i] for i in prim]
    lo, hi = bootstrap(delta)
    new_fp = sorted(it["id"] for (it, r), (_, o) in zip(rows, other)
                    if it["label"] == "legit" and r and action(r) == "junk" and not (o and action(o) == "junk"))
    slice_worse = []
    for sl in sorted({it["slice"] for it, _ in rows} - PRIMARY):
        idx = [i for i, (it, _) in enumerate(rows) if it["slice"] == sl]
        d = [mine[i] - theirs[i] for i in idx]
        if any(d):
            slo, _ = bootstrap(d)
            if slo > 0:
                slice_worse.append(sl)
    return {"point_per_1k": 1000 * sum(delta) / len(delta), "ci95_per_1k": [1000 * lo, 1000 * hi],
            "new_false_positives": new_fp, "slices_worse": slice_worse}


def sweep(items, records, costs, lambdas):
    """Outcomes at the Bayes threshold of other cost ratios, from the recorded probabilities.

    For each ratio l (a legitimate message in Junk costs l, spam in the inbox costs 1), the
    threshold is l / (1 + l). Only the folder decision depends on the threshold, so the recorded
    P(junk) answers this without rerunning anything.
    """
    rows = join(items, records)
    out = []
    for lam in lambdas:
        t = lam / (1 + lam)
        row = {"lambda": lam, "threshold": t, "by_slice": {}}
        for sl in sorted({it["slice"] for it, _ in rows}):
            sel = [(it, r) for it, r in rows if it["slice"] == sl and r and r.get("p_junk") is not None]
            fp = sum(1 for it, r in sel if it["label"] == "legit" and r["p_junk"] >= t)
            fn = sum(1 for it, r in sel if it["label"] == "junk" and r["p_junk"] < t)
            junk = sum(1 for it, _ in sel if it["label"] == "junk")
            row["by_slice"][sl] = {"fp": fp, "fn": fn, "legit": len(sel) - junk, "junk": junk}
        prim = [(it, r) for it, r in rows if it["slice"] in PRIMARY and r and r.get("p_junk") is not None]
        fp = sum(1 for it, r in prim if it["label"] == "legit" and r["p_junk"] >= t)
        fn = sum(1 for it, r in prim if it["label"] == "junk" and r["p_junk"] < t)
        row.update(primary_fp=fp, primary_fn=fn, primary_cost_per_1k_at_lambda=1000 * (lam * fp + fn) / len(prim))
        out.append(row)
    return out
