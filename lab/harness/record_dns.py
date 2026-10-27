"""Record the DNS answers firstread's own DKIM and DMARC checks need for the lab's messages, so every
run replays the same answers (docs/13-lab.md section 2, "The network"). Read-only to the agent.

Usage: python3 -I record_dns.py <lab_data> [--sealed]

Asks the real code which names it needs (`firstread auth-batch` against the recording so far: a
name it does not hold comes back as "not recorded"), resolves them over DNS-over-HTTPS
(dns.google, the JSON API), adds them to the recording, and repeats until nothing new is asked.
A name the resolver could not answer is recorded as a temporary error, so a replay is the same.

Recorded only for messages whose answers today stand in for the answers at arrival: real mail
(not the synthetic slice) dated within the window, from 400 days before the recording day to the
end of the day after it. The window goes into the meta file, and the daemon is given it
(`--dns-window`): a message dated outside it gets no answers, even for a name the recording holds
(SpamAssassin's 2002 mail from hotmail.com would otherwise get hotmail.com's policy of today).
So for older corpora the checks come out Unavailable, as docs/13-lab.md section 2 prescribes.

Train, calib and dev go to lab/data/dns-recorded/<n>.jsonl (public DNS data, committed with its
date and window in dns-recorded.meta.json), in 8 shards by a hash of the name, so no one file is
large. With --sealed, the sealed split's lookups go to <lab_data>/sealed/dns-recorded.jsonl and
only totals are printed.
"""
import concurrent.futures
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CLI = os.path.join(REPO, "target", "release", "firstread")
RESOLVER = "https://dns.google/resolve"
TYPES = {"TXT": 16, "A": 1, "AAAA": 28, "MX": 15, "PTR": 12}
SOURCES = {"lore", "untroubled"}
WINDOW_DAYS = 400
SHARDS = 8


def shard(name, n):
    return int(hashlib.sha256(name.encode()).hexdigest()[:8], 16) % n


def resolve(rtype, name):
    url = f"{RESOLVER}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            d = json.load(r)
    except Exception as e:  # noqa: BLE001 - any failure is a temporary error, recorded as such
        return {"result": "temp_error", "reason": f"resolver: {type(e).__name__}"}
    status = d.get("Status")
    if status == 3:
        return {"result": "no_records"}
    if status != 0:
        return {"result": "temp_error", "reason": f"rcode {status}"}
    records = [a["data"] for a in d.get("Answer", []) if a.get("type") == TYPES[rtype]]
    return {"result": "records", "records": records} if records else {"result": "no_records"}


def asked(items_path, recording):
    """Names the code looked up and the recording (a list of files) does not hold."""
    cmd = [CLI, "auth-batch", items_path, "--clock", "message"]
    for f in recording:
        if os.path.exists(f):
            cmd += ["--dns", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    need = set()
    for line in out.splitlines():
        for lk in json.loads(line)["lookups"]:
            if lk["result"] == "temp_error" and lk.get("reason") == "not recorded":
                need.add((lk["type"], lk["name"]))
    return need


def main():
    lab = sys.argv[1]
    sealed = "--sealed" in sys.argv
    splits = ["sealed"] if sealed else ["train", "calib", "dev"]
    items = []
    for s in splits:
        path = os.path.join(lab, "sealed", "sealed.jsonl") if s == "sealed" else os.path.join(lab, "splits", f"{s}.jsonl")
        items += [json.loads(l) for l in open(path)]
    today = datetime.datetime.now(datetime.UTC).date()
    midnight = int(datetime.datetime(today.year, today.month, today.day, tzinfo=datetime.UTC).timestamp())
    window = [midnight - WINDOW_DAYS * 86400, midnight + 2 * 86400 - 1]
    items = [it for it in items if it.get("source") in SOURCES and it.get("date")
             and window[0] <= it["date"] <= window[1]]
    recording = ([os.path.join(lab, "sealed", "dns-recorded.jsonl")] if sealed
                 else [os.path.join(REPO, "lab", "data", "dns-recorded", f"{i}.jsonl") for i in range(SHARDS)])
    os.makedirs(os.path.dirname(recording[0]), exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        for it in items:
            f.write(json.dumps({"id": it["id"], "path": it["path"]}) + "\n")
        items_path = f.name
    total = 0
    try:
        for rnd in range(1, 6):
            need = sorted(asked(items_path, recording))
            if not need:
                break
            with concurrent.futures.ThreadPoolExecutor(8) as ex:
                answers = list(ex.map(lambda tn: resolve(*tn), need))
            for (t, n), a in zip(need, answers):
                with open(recording[shard(n, len(recording))], "a") as out:
                    out.write(json.dumps({"type": t, "name": n, **a}) + "\n")
            total += len(need)
            print(f"round {rnd}: recorded {len(need)} names", flush=True)
    finally:
        os.unlink(items_path)
    counts = {}
    for f in recording:
        for line in open(f) if os.path.exists(f) else []:
            r = json.loads(line)["result"]
            counts[r] = counts.get(r, 0) + 1
    print(f"recording: {sum(counts.values())} answers {counts}")
    meta = {"recorded": today.isoformat(), "resolver": RESOLVER, "answers": counts,
            "messages": len(items), "splits": splits, "sources": sorted(SOURCES), "window_days": WINDOW_DAYS,
            "window": window, "shards": len(recording)}
    meta_path = (os.path.join(lab, "sealed", "dns-recorded.meta.json") if sealed
                 else os.path.join(REPO, "lab", "data", "dns-recorded.meta.json"))
    json.dump(meta, open(meta_path, "w"), indent=1)


if __name__ == "__main__":
    main()
