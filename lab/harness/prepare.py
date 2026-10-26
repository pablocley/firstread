"""Build the lab's items and splits (docs/13-lab.md section 3).

Usage: python3 -I prepare.py <lab-data-dir> [--write-reference]

Reads the extracted corpora under <lab-data-dir>/extract and <lab-data-dir>/raw/lore (fetch.py), writes one
`.eml` per item exactly as Dovecot would hand it to the filter (no mbox `From ` line, CRLF line
endings), and the split manifests train / calib / dev under <lab-data-dir>/splits and the sealed
split under <lab-data-dir>/sealed. Splits are by time first (the newest 20% of each source and
class go to sealed), then by near-duplicate cluster (simhash), so copies never straddle splits.

lab/data/untroubled.txt lists the untroubled messages taken (the October archive keeps growing),
so the sample does not depend on when the archive was fetched; paths that differ only in the
number before `.txt` share a line, as `prefix_{1,5,9}.txt`. lab/data/manifest.json holds a hash
over every message (origin and sha256 after normalisation) and one per split (ids, labels, slices,
message hashes; no local paths), so two machines can compare them; prepare refuses any difference
and writes <lab-data-dir>/items.tsv to find it. --write-reference writes both reference files from
the data at hand (a new tag).
"""

import hashlib
import json
import os
import random
import re
import subprocess
import sys
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime, parseaddr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import synth_nl  # noqa: E402
import tomllib  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
REF_UNTROUBLED = os.path.join(REPO, "lab", "data", "untroubled.txt")
REF_MANIFEST = os.path.join(REPO, "lab", "data", "manifest.json")
SEED = 20261026
UNTROUBLED_CAP = 1500


def normalise(raw: bytes) -> bytes:
    if raw.startswith(b"From ") :
        raw = raw.split(b"\n", 1)[1] if b"\n" in raw else b""
    raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return raw


def header_info(raw: bytes):
    try:
        h = BytesHeaderParser().parsebytes(raw)
    except Exception:
        return None, "", ""
    date = None
    try:
        if h.get("Date"):
            date = parsedate_to_datetime(str(h.get("Date"))).timestamp()
    except Exception:
        date = None
    rp = parseaddr(str(h.get("Return-Path", "")))[1]
    frm = parseaddr(str(h.get("From", "")))[1]
    return date, rp or frm, frm


def simhash(raw: bytes) -> int:
    body = raw.split(b"\r\n\r\n", 1)[-1].lower()
    words = body.split()
    shingles = [b" ".join(words[i:i + 3]) for i in range(max(1, len(words) - 2))]
    v = [0] * 64
    for s in shingles[:5000]:
        x = int.from_bytes(hashlib.blake2b(s, digest_size=8).digest(), "big")
        for i in range(64):
            v[i] += 1 if (x >> i) & 1 else -1
    return sum(1 << i for i in range(64) if v[i] > 0)


class Union:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, a):
        while self.p[a] != a:
            self.p[a] = self.p[self.p[a]]
            a = self.p[a]
        return a

    def join(self, a, b):
        self.p[self.find(a)] = self.find(b)


def clusters(hashes):
    u = Union(len(hashes))
    for band in range(4):
        buckets = {}
        for i, h in enumerate(hashes):
            buckets.setdefault((h >> (16 * band)) & 0xFFFF, []).append(i)
        for members in buckets.values():
            if len(members) > 200:
                continue
            for a in range(len(members)):
                for b in range(a + 1, len(members)):
                    i, j = members[a], members[b]
                    if bin(hashes[i] ^ hashes[j]).count("1") <= 3:
                        u.join(i, j)
    return [u.find(i) for i in range(len(hashes))]


def expand(line):
    m = re.match(r"^(.*)\{([^}]*)\}(.*)$", line)
    return [m.group(1) + x + m.group(3) for x in m.group(2).split(",")] if m else [line]


def compact(paths):
    """Paths that differ only in the number before `.txt` on one line: `prefix_{1,5,9}.txt`."""
    groups = {}
    for p in sorted(paths):
        m = re.match(r"^(.*_)(\d+)(\.txt)$", p)
        key = (m.group(1), m.group(3)) if m else (p, None)
        groups.setdefault(key, []).append(m.group(2) if m else None)
    out = []
    for (head, tail), ns in groups.items():
        if tail is None:
            out.append(head)
        else:
            out.append(head + (ns[0] if len(ns) == 1 else "{" + ",".join(ns) + "}") + tail)
    return out


def reference():
    if not os.path.exists(REF_UNTROUBLED):
        return None
    return {p for l in open(REF_UNTROUBLED) if l.strip() and not l.startswith("#") for p in expand(l.strip())}


def collect(data, ref):
    items = []
    sa = os.path.join(data, "extract", "sa")
    for sub, label, slice_ in [("easy_ham", "legit", "sa"), ("easy_ham_2", "legit", "sa"),
                               ("hard_ham", "legit", "sa_hard_ham"), ("spam", "junk", "sa"),
                               ("spam_2", "junk", "sa")]:
        d = os.path.join(sa, sub)
        for name in sorted(os.listdir(d)):
            if name == "cmds":
                continue
            items.append({"source": "spamassassin", "slice": slice_, "label": label, "subclass": sub,
                          "hard_negative": slice_ == "sa_hard_ham", "recipient": "user@sa.lab.invalid",
                          "raw": open(os.path.join(d, name), "rb").read(), "orig": f"sa/{sub}/{name}"})
    unt = os.path.join(data, "extract", "untroubled")
    paths = sorted(os.path.join(r, f) for r, _, fs in os.walk(unt) for f in fs if not f.startswith(".from-"))
    if ref is not None:
        chosen = sorted(p for p in paths if os.path.relpath(p, unt) in ref)
    else:
        random.Random(SEED).shuffle(paths)
        chosen = sorted(paths[:UNTROUBLED_CAP])
    for p in chosen:
        items.append({"source": "untroubled", "slice": "modern_cross_source", "label": "junk",
                      "subclass": "spam", "hard_negative": False, "recipient": "bruce@untroubled.org",
                      "raw": open(p, "rb").read(), "orig": os.path.relpath(p, unt)})
    lore = os.path.join(data, "raw", "lore")
    pins = {e["list"]: e for e in tomllib.load(open(os.path.join(REPO, "lab", "datasets.toml"), "rb"))["lore"]}
    for lst in sorted(pins):
        repo = os.path.join(lore, lst)
        commits = subprocess.run(["git", "-C", repo, "rev-list", "-n", str(pins[lst]["count"]), pins[lst]["head"]],
                                 capture_output=True, text=True, check=True).stdout.split()
        for c in commits:
            raw = subprocess.run(["git", "-C", repo, "show", f"{c}:m"], capture_output=True).stdout
            if raw:
                items.append({"source": "lore", "slice": "modern_cross_source", "label": "legit",
                              "subclass": f"list:{lst}", "hard_negative": False,
                              "recipient": f"{lst}@lists.lab.invalid", "raw": raw, "orig": f"lore/{lst}/{c}"})
    for i, s in enumerate(synth_nl.gen()):
        items.append({"source": "synthetic_nl", "slice": "synthetic_nl", "label": s["class"],
                      "subclass": s["subclass"], "hard_negative": s["hard_negative"],
                      "recipient": "administratie@ons-bedrijf.example", "raw": s["raw"], "orig": f"synthetic/{i}"})
    return items


def split_hash(members):
    lines = sorted(f"{it['source']}-{it['sha256'][:16]}\t{it['label']}\t{it['slice']}\t{it['sha256']}" for it in members)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def main(data, write_reference=False):
    ref = None if write_reference else reference()
    items = collect(data, ref)
    seen = set()
    unique = []
    for it in items:
        it["raw"] = normalise(it["raw"])
        h = hashlib.sha256(it["raw"]).hexdigest()
        if h in seen or len(it["raw"]) < 20:
            continue
        seen.add(h)
        it["sha256"] = h
        date, sender, frm = header_info(it["raw"])
        it["date"], it["sender"] = date, sender
        unique.append(it)
    print(f"items: {len(items)} collected, {len(unique)} after exact de-duplication")
    if ref is not None:
        got = {it["orig"] for it in unique if it["source"] == "untroubled"}
        if got != ref:
            sys.exit(f"untroubled messages differ from lab/data/untroubled.txt: {len(ref - got)} missing")
    item_lines = sorted(f"{it['orig']}\t{it['sha256']}" for it in unique)
    with open(os.path.join(data, "items.tsv"), "w") as f:
        f.write("\n".join(item_lines) + "\n")
    items_sha256 = hashlib.sha256("\n".join(item_lines).encode()).hexdigest()

    rng = random.Random(SEED)
    splits = {"train": [], "calib": [], "dev": [], "sealed": []}
    groups = {}
    for it in unique:
        groups.setdefault((it["source"], it["label"]), []).append(it)
    for key in sorted(groups):
        g = groups[key]
        cl = clusters([simhash(it["raw"]) for it in g])
        by = {}
        for it, c in zip(g, cl):
            by.setdefault(c, []).append(it)
        cls = sorted(by.values(), key=lambda m: min((x["date"] or 0.0) for x in m))
        total, taken, sealed = len(g), 0, []
        while cls and taken < 0.2 * total:
            m = cls.pop()
            sealed.append(m)
            taken += len(m)
        rng.shuffle(cls)
        n = sum(len(m) for m in cls)
        acc = 0
        for m in cls:
            frac = acc / max(1, n)
            split = "train" if frac < 0.6 else ("calib" if frac < 0.8 else "dev")
            splits[split].extend(m)
            acc += len(m)
        for m in sealed:
            splits["sealed"].extend(m)

    os.makedirs(os.path.join(data, "splits"), exist_ok=True)
    os.makedirs(os.path.join(data, "sealed"), exist_ok=True)
    summary = {}
    for split, members in splits.items():
        base = os.path.join(data, "sealed" if split == "sealed" else "items", split if split != "sealed" else "items")
        os.makedirs(base, exist_ok=True)
        manifest = os.path.join(data, "sealed" if split == "sealed" else "splits", f"{split}.jsonl")
        with open(manifest, "w") as f:
            for it in sorted(members, key=lambda x: x["sha256"]):
                iid = f"{it['source']}-{it['sha256'][:16]}"
                path = os.path.join(base, iid + ".eml")
                with open(path, "wb") as o:
                    o.write(it["raw"])
                f.write(json.dumps({"id": iid, "path": path, "source": it["source"], "slice": it["slice"],
                                    "label": it["label"], "subclass": it["subclass"],
                                    "hard_negative": it["hard_negative"], "recipient": it["recipient"],
                                    "user": it["recipient"], "sender": it["sender"], "date": it["date"],
                                    "sha256": it["sha256"], "orig": it["orig"]}) + "\n")
        counts = {}
        for it in members:
            counts[f"{it['slice']}:{it['label']}"] = counts.get(f"{it['slice']}:{it['label']}", 0) + 1
        summary[split] = {"n": len(members), "by_slice_label": dict(sorted(counts.items())),
                          "split_sha256": split_hash(members)}
    doc = {"seed": SEED, "untroubled_cap": UNTROUBLED_CAP, "items": len(unique), "items_sha256": items_sha256,
           "splits": summary}
    with open(os.path.join(data, "manifest.json"), "w") as f:
        json.dump(doc, f, indent=1)
    print(json.dumps(summary, indent=1))
    if write_reference:
        os.makedirs(os.path.dirname(REF_UNTROUBLED), exist_ok=True)
        with open(REF_UNTROUBLED, "w") as f:
            f.write("# untroubled.org messages in the lab, by path inside lab-data/extract/untroubled (prepare.py);\n"
                    "# prefix_{1,5,9}.txt stands for prefix_1.txt, prefix_5.txt and prefix_9.txt\n")
            f.write("\n".join(compact(it["orig"] for it in unique if it["source"] == "untroubled")) + "\n")
        json.dump(doc, open(REF_MANIFEST, "w"), indent=1)
        print("reference written: lab/data/untroubled.txt, lab/data/manifest.json")
    elif os.path.exists(REF_MANIFEST) and json.load(open(REF_MANIFEST)) != doc:
        sys.exit(f"messages or splits differ from lab/data/manifest.json; per-message hashes in {data}/items.tsv")


if __name__ == "__main__":
    main(sys.argv[1], "--write-reference" in sys.argv)
