"""The learning test (docs/13-lab.md section 7, docs/07-evaluation.md): simulated mailboxes on a
clock, with simulated owners who react to what firstread did. Read-only to the agent.

Usage: python3 -I learning.py <run_dir> [--profiles none,passive,active] [--no-poison]

Every train, calib and dev message (never the sealed split) is delivered through the real
`firstread-filter` to the real `firstreadd` with mailbox memory on, in the order of its Date header
(missing dates keep the previous time), to its own mailbox (the item's recipient). After each
delivery the simulated owner may act on it, after a delay, through the real `firstread feedback`:

  none     never acts; memory learns only from deliveries (known senders, known threads)
  passive  moves 30 % of the junk left in the inbox into Junk, rescues 50 % of legitimate mail
           from Junk, after 1 to 48 hours; never replies
  active   80 % and 90 %, after 1 to 12 hours; replies to 10 % of legitimate non-list mail in the
           inbox (a copy reaches Sent)

Owners act on true labels, so these profiles are assumptions; results are reported per profile.

Conditions, all with the same heads (trained on train as in run.py):
  off      no memory: calib delivered, combiner C0 trained on its records, dev scored (= run.py)
  <profile>  pass A: the whole timeline with C0 deciding and the owner reacting to C0; combiner C1
           trained on pass A's calib records (now with mailbox.* inputs); pass B: the timeline
           again from empty memory with C1 deciding and the owner reacting to C1; dev scored
           from pass B and compared with `off` (paired bootstrap, scorer of run.py)

Poisoning check (scope isolation, docs/07-evaluation.md): pass B of the last profile is repeated
with one mailbox's owner labelling every delivery junk; the decisions in every other mailbox must
be identical to pass B's.

Writes <run_dir>/learning.json and prints a summary.
"""
import heapq
import json
import os
import random
import shutil
import subprocess
import sys
import time
import tomllib
from email.parser import BytesHeaderParser
from email.utils import parseaddr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run as H  # noqa: E402
import score  # noqa: E402

PROFILES = {
    "none": {"junk_inbox": 0.0, "rescue": 0.0, "reply": 0.0, "delay": (3600, 3600)},
    "passive": {"junk_inbox": 0.3, "rescue": 0.5, "reply": 0.0, "delay": (3600, 172800)},
    "active": {"junk_inbox": 0.8, "rescue": 0.9, "reply": 0.1, "delay": (3600, 43200)},
}
POISON_MAILBOX = "ksummit@lists.lab.invalid"
SEED = 20261027
CLI = os.path.join(H.BIN, "firstread")


def start_daemon(d, combiner, threshold, sidecar_sock, calibration, memory=True):
    """firstreadd as run.py starts it, plus mailbox memory and the feedback socket."""
    sock, fb = os.path.join(d, "d.sock"), os.path.join(d, "fb.sock")
    records = os.path.join(d, "records.jsonl")
    for p in [records]:
        if os.path.exists(p):
            os.unlink(p)
    cmd = [os.path.join(H.BIN, "firstreadd"), "--socket", sock, "--records", records, "--deployment", "lab",
           "--mac-key", H.MAC_KEY, "--trusted-authserv", H.TRUSTED_AUTHSERV, "--junk-threshold", str(threshold),
           "--data-class", "public", "--sidecar", sidecar_sock, "--calibration", calibration]
    if combiner:
        cmd += ["--combiner", combiner]
    if memory:
        mem = os.path.join(d, "memory")
        shutil.rmtree(mem, ignore_errors=True)
        cmd += ["--memory", mem, "--feedback-socket", fb]
    proc = subprocess.Popen(cmd, stderr=open(os.path.join(d, "daemon.log"), "w"))
    H.wait_for(sock, proc)
    if memory:
        H.wait_for(fb, proc)
    return proc, sock, fb, records


def headers(path):
    h = BytesHeaderParser().parsebytes(open(path, "rb").read())
    return parseaddr(str(h.get("From", "")))[1], str(h.get("Message-ID", "")).strip()


def feedback(fb, mailbox, op, message, at):
    r = subprocess.run([CLI, "feedback", "--socket", fb, "--mailbox", mailbox, f"--{op}", "--at", str(int(at))],
                       input=message, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"feedback {op}: {r.stderr.decode(errors='replace')[:200]}")
    return json.loads(r.stdout)["result"]


def reply_message(item, n):
    sender, mid = headers(item["path"])
    if not sender:
        return None
    return (f"From: {item['user']}\r\nTo: {sender}\r\nMessage-ID: <reply-{n}@lab.invalid>\r\n"
            f"In-Reply-To: {mid}\r\nSubject: Re\r\n\r\nThanks.\r\n").encode()


def timeline(items):
    """Items in Date order; a message without a date keeps the time of the one before it."""
    dated = sorted(items, key=lambda it: (it["date"] is None, it["date"] or 0, it["id"]))
    out, last = [], 0.0
    for it in dated:
        t = it["date"] if it["date"] is not None else last
        last = max(last, t)
        out.append((t, it))
    return out


def replay(d, events, combiner, threshold, side_sock, calibration, profile, poison=False):
    """One pass over the timeline. Returns the records and the owner's actions."""
    os.makedirs(d, exist_ok=True)
    proc, sock, fb, records = start_daemon(d, combiner, threshold, side_sock, calibration)
    rng = random.Random(SEED)
    pending, seq, acts = [], 0, {"junk": 0, "not-junk": 0, "sent": 0, "dropped_or_duplicate": 0}
    violations = []
    try:
        for t, it in events:
            while pending and pending[0][0] <= t:
                at, _, mailbox, op, message = heapq.heappop(pending)
                res = feedback(fb, mailbox, op, message, at)
                acts[op if res == "applied" else "dropped_or_duplicate"] += 1
            raw, p, _, _ = H.filter_once(it, sock)
            violations += H.check_output(it, raw, p)
            # The record is written before the reply; read the decision from the reply itself.
            filed = b"X-Firstread-Folder: junk" in p.stdout.split(b"\r\n\r\n", 1)[0]
            lo, hi = profile["delay"]
            due = t + rng.uniform(lo, hi)
            u = rng.random()
            legit = it["label"] == "legit"
            if poison and it["user"] == POISON_MAILBOX:
                heapq.heappush(pending, (t + 60, seq, it["user"], "junk", raw))
            elif not legit and not filed and u < profile["junk_inbox"]:
                heapq.heappush(pending, (due, seq, it["user"], "junk", raw))
            elif legit and filed and u < profile["rescue"]:
                heapq.heappush(pending, (due, seq, it["user"], "not-junk", raw))
            elif legit and not filed and "list:" not in it["subclass"] and u < profile["reply"]:
                msg = reply_message(it, seq)
                if msg:
                    heapq.heappush(pending, (due, seq, it["user"], "sent", msg))
            seq += 1
    finally:
        H.stop(proc)
    acts["not_junk"] = acts.pop("not-junk")
    return [json.loads(l) for l in open(records)], acts, violations


def train_combiner(d, exp_path, records_path, py):
    subprocess.run(py + [os.path.join(H.REPO, "ml", "heads", "train.py"), "combiner", d, exp_path, H.LAB, records_path],
                   check=True, env=H.side_env())
    return os.path.join(d, "combiner.json")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    profiles = ["none", "passive", "active"]
    for a in sys.argv[1:]:
        if a.startswith("--profiles="):
            profiles = a.split("=", 1)[1].split(",")
    H.check_lock()
    H.check_training_sources()
    run_dir = os.path.abspath(args[0])
    os.makedirs(run_dir, exist_ok=True)
    exp_path = os.path.join(H.REPO, "lab", "experiment.toml")
    shutil.copy(exp_path, os.path.join(run_dir, "experiment.toml"))
    exp = tomllib.load(open(exp_path, "rb"))
    costs = H.load_costs()
    c = costs["cost"]
    threshold = H.threshold_of(exp, costs)
    py = [sys.executable, "-I"]
    rv = exp["render"]["version"]
    cfg = H.provider_cfg(exp)
    if not cfg:
        sys.exit("the learning test needs a tier-1 provider")
    t0 = time.time()
    H.ensure_cache(cfg, rv, py)
    subprocess.run(py + [os.path.join(H.REPO, "ml", "heads", "train.py"), "heads", run_dir, exp_path, H.LAB,
                         os.path.join(H.LAB, "cache")], check=True, env=H.side_env())
    calibration = os.path.join(run_dir, "calibration.json")
    side, side_sock, _ = H.start_sidecar(run_dir, "quality", cfg, rv, os.path.join(run_dir, "heads.json"), py, False)
    split = {s: [json.loads(l) for l in open(os.path.join(H.LAB, "splits", f"{s}.jsonl"))] for s in ["train", "calib", "dev"]}
    dev = split["dev"]
    events = timeline(split["train"] + split["calib"] + dev)
    out = {"profiles": {}, "messages": len(events), "threshold": threshold}
    try:
        # off: no memory, exactly run.py's quality pass.
        off = os.path.join(run_dir, "off")
        os.makedirs(off, exist_ok=True)
        d, sock, calib_rec = H.start_daemon(off, "calib", side_sock, calibration, None, threshold)
        H.feed(split["calib"], sock, [])
        H.stop(d)
        c0 = train_combiner(off, exp_path, calib_rec, py)
        d, sock, dev_rec = H.start_daemon(off, "dev", side_sock, calibration, c0, threshold)
        H.feed(dev, sock, [])
        H.stop(d)
        off_records = [json.loads(l) for l in open(dev_rec)]
        s_off = score.score(dev, off_records, c)
        out["off"] = {k: s_off[k] for k in ["cost_per_1k", "cost_per_1k_by_slice", "false_positives", "false_negatives"]}
        print(f"off: cost {s_off['cost_per_1k']:.2f} FP {s_off['false_positives']} FN {s_off['false_negatives']}", flush=True)

        last_b = None
        for name in profiles:
            prof = PROFILES[name]
            pd = os.path.join(run_dir, name)
            a_records, a_acts, a_viol = replay(os.path.join(pd, "A"), events, c0, threshold, side_sock, calibration, prof)
            c1 = train_combiner(pd, exp_path, os.path.join(pd, "A", "records.jsonl"), py)
            b_records, b_acts, b_viol = replay(os.path.join(pd, "B"), events, c1, threshold, side_sock, calibration, prof)
            ids = {score.idem_key(it["path"], it["recipient"]) for it in dev}
            b_dev = [r for r in b_records if r["idempotency_key"] in ids]
            s = score.score(dev, b_dev, c)
            cmp = score.compare(dev, b_dev, off_records, c)
            weights = json.load(open(c1))["weights"]
            out["profiles"][name] = {
                "cost_per_1k": s["cost_per_1k"], "cost_per_1k_by_slice": s["cost_per_1k_by_slice"],
                "false_positives": s["false_positives"], "false_negatives": s["false_negatives"],
                "hard_negative_fp": len(s["hard_negative_fp"]), "vs_off": cmp,
                "owner_actions_pass_A": a_acts, "owner_actions_pass_B": b_acts,
                "invariant_violations": len(a_viol) + len(b_viol),
                "mailbox_weights": {k: round(v, 3) for k, v in sorted(weights.items()) if k.startswith("mailbox.")},
                "combiner": json.load(open(c1))["release"],
            }
            print(f"{name}: cost {s['cost_per_1k']:.2f} FP {s['false_positives']} FN {s['false_negatives']} | vs off "
                  f"{cmp['point_per_1k']:+.2f} CI [{cmp['ci95_per_1k'][0]:+.2f}, {cmp['ci95_per_1k'][1]:+.2f}] "
                  f"new_fp {len(cmp['new_false_positives'])} slices_worse {cmp['slices_worse']} | actions B {b_acts}",
                  flush=True)
            last_b = (name, pd, c1, prof, b_records)

        if last_b and "--no-poison" not in sys.argv:
            name, pd, c1, prof, b_records = last_b
            p_records, _, _ = replay(os.path.join(pd, "B-poison"), events, c1, threshold, side_sock, calibration, prof,
                                     poison=True)
            base = {r["idempotency_key"]: r for r in b_records}
            other_diff, poisoned_flips = 0.0, 0
            poisoned_keys = {score.idem_key(it["path"], it["recipient"]) for _, it in events if it["user"] == POISON_MAILBOX}
            for r in p_records:
                o = base[r["idempotency_key"]]
                if r["idempotency_key"] in poisoned_keys:
                    poisoned_flips += r["directive"].get("folder") != o["directive"].get("folder")
                elif r.get("p_junk") is not None and o.get("p_junk") is not None:
                    other_diff = max(other_diff, abs(r["p_junk"] - o["p_junk"]))
            out["poison"] = {"profile": name, "mailbox": POISON_MAILBOX, "max_p_change_other_mailboxes": other_diff,
                             "decisions_changed_in_poisoned_mailbox": poisoned_flips,
                             "pass": other_diff == 0.0}
            print(f"poison: other mailboxes max |dp| {other_diff:.3g}; decisions changed in {POISON_MAILBOX}: "
                  f"{poisoned_flips}", flush=True)
    finally:
        H.stop(side)
    out["seconds"] = round(time.time() - t0, 1)
    json.dump(out, open(os.path.join(run_dir, "learning.json"), "w"), indent=1)
    print(f"seconds: {out['seconds']}")


if __name__ == "__main__":
    main()
