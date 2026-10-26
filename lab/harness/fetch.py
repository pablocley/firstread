"""Download and unpack the lab's public data and models (docs/13-lab.md section 3).

Usage: python3 -I fetch.py <lab_data>

- every [[archive]] of lab/datasets.toml into <lab_data>/raw, checked against its sha256, unpacked
  into <lab_data>/extract/<extract> (tar or 7z). A changed hash stops the fetch, except for an
  archive marked `mutable` (still growing at the publisher), which only warns: prepare.py then
  takes exactly the messages listed in lab/data/untroubled.txt.
- every [[lore]] list as a bare git clone into <lab_data>/raw/lore/<list>, deep enough to hold the
  pinned head and the `count` messages before it.
- every embedder of ml/sidecar/providers.py at its pinned revision into <lab_data>/hf.

Needs curl, tar, 7z and git on the path. Writes <lab_data>/raw/SHA256SUMS.
"""
import hashlib
import os
import subprocess
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "ml", "sidecar"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def archives(lab, d):
    raw = os.path.join(lab, "raw")
    os.makedirs(raw, exist_ok=True)
    sums = []
    for a in d["archive"]:
        name = a["url"].rsplit("/", 1)[1]
        path = os.path.join(raw, name)
        if not os.path.exists(path):
            print(f"fetch {a['url']}", flush=True)
            run(["curl", "-sSfL", "-o", path + ".part", a["url"]])
            os.replace(path + ".part", path)
        got = sha256(path)
        if got != a["sha256"]:
            if not a.get("mutable"):
                sys.exit(f"{name}: sha256 {got} differs from lab/datasets.toml; refusing")
            print(f"warning: {name} changed at the publisher since 2026-10-26 (mutable); "
                  "prepare.py selects the recorded messages", flush=True)
        sums.append(f"{got}  {name}")
        out = os.path.join(lab, "extract", a["extract"])
        marker = os.path.join(out, f".from-{name}")
        if not os.path.exists(marker):
            os.makedirs(out, exist_ok=True)
            if name.endswith(".7z"):
                run(["7z", "x", "-y", f"-o{out}", path], stdout=subprocess.DEVNULL)
            else:
                run(["tar", "-xf", path, "-C", out])
            open(marker, "w").write(got + "\n")
    open(os.path.join(raw, "SHA256SUMS"), "w").write("\n".join(sums) + "\n")


def lore(lab, d):
    for entry in d["lore"]:
        repo = os.path.join(lab, "raw", "lore", entry["list"])
        if not os.path.exists(repo):
            print(f"clone {entry['url']}", flush=True)
            run(["git", "clone", "-q", "--bare", "--depth", str(entry["count"] + 200), entry["url"], repo])
        for _ in range(20):
            have = subprocess.run(["git", "-C", repo, "cat-file", "-e", entry["head"]], capture_output=True).returncode == 0
            n = 0
            if have:
                n = len(subprocess.run(["git", "-C", repo, "rev-list", "-n", str(entry["count"]), entry["head"]],
                                       capture_output=True, text=True).stdout.split())
            if have and n == entry["count"]:
                break
            run(["git", "-C", repo, "fetch", "-q", "--deepen", "1000", "origin"])
        else:
            sys.exit(f"lore {entry['list']}: pinned head {entry['head']} not reachable")


def models(lab):
    os.environ.setdefault("HF_HOME", os.path.join(lab, "hf"))
    from providers import EMBEDDERS, resolve, snapshot
    for name in EMBEDDERS:
        print(f"model {name} @ {EMBEDDERS[name]['revision'][:12]}", flush=True)
        snapshot(resolve(name))


if __name__ == "__main__":
    lab = os.path.abspath(sys.argv[1])
    d = tomllib.load(open(os.path.join(REPO, "lab", "datasets.toml"), "rb"))
    archives(lab, d)
    lore(lab, d)
    models(lab)
    print("fetch done", flush=True)
