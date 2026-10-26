"""Run one lab experiment through the real delivery path (docs/13-lab.md). Read-only to the agent.

Usage: python3 -I run.py [--sealed] [--no-timing] [--write-lock] <run_dir>

Reads lab/experiment.toml and lab/cost.toml, checks the read-only files against
lab/protected.sha256 and the training sources against lab/datasets.toml, fills the embedding cache
of the experiment's space if needed, trains heads, starts the tier-1 sidecar and the real
`firstreadd`, feeds every calib item through the real `firstread-filter` the way Dovecot does
(message on stdin, delivery context in the environment), trains the combiner on what the pipeline
recorded, then feeds the dev items (or, with --sealed, the sealed items) and scores them. A sealed
query is counted against the ration in lab/cost.toml first, and its per-message output is kept in
the lab data directory, out of the run directory (docs/13-lab.md section 4).

Then the timing pass: the champion (lab/runs/champion) and this run each get a sidecar that
computes every vector (no cache, model loaded first) and a daemon, and the same sample of dev
messages goes through the real filter to both, interleaved message by message, so machine noise
hits both alike. It measures latency per email (filter wall time), CPU per email (filter, sidecar
and daemon) and peak memory (sidecar and daemon).

The keep rule (lab/program.md) has three axes, quality, latency and footprint; a run is kept when
at least one improves beyond noise and none is worse. Prints the summary block.
"""
import glob
import hashlib
import json
import math
import os
import random
import resource
import shutil
import subprocess
import sys
import time
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
LAB = os.environ.get("FIRSTREAD_LAB_DATA", "/home/claude/lab-data")
BIN = os.path.join(REPO, "target", "release")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "ml", "sidecar"))
import score  # noqa: E402
from providers import config_args, resolve, space_id  # noqa: E402

PROTECTED = ["lab/harness/*.py", "lab/l2/*", "lab/l2/*/*", "ml/sidecar/*.py", "lab/cost.toml", "lab/datasets.toml", "lab/program.md",
             "crates/*/src/*.rs", "crates/*/Cargo.toml", "Cargo.toml", "Cargo.lock"]
TRUSTED_AUTHSERV = "smtp.subspace.kernel.org,mx.lab.firstread.invalid"
MAC_KEY = "lab-only-key-not-a-secret"
TIMING_SEED = 20261026
CLK_TCK = os.sysconf("SC_CLK_TCK")


def protected_files():
    out = []
    for pat in PROTECTED:
        out += [p for p in glob.glob(os.path.join(REPO, pat)) if os.path.isfile(p)]
    out.append(os.path.join(LAB, "manifest.json"))
    return sorted(set(out))


def digest(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def lock_lines():
    """`sha256  path`, with repository files relative to the repository and the lab data's manifest
    as `<lab_data>/manifest.json`, so the lock holds wherever either lives."""
    def name(p):
        if p == os.path.join(LAB, "manifest.json"):
            return "<lab_data>/manifest.json"
        return os.path.relpath(p, REPO)
    return sorted((f"{digest(p)}  {name(p)}" for p in protected_files()), key=lambda l: l.split("  ", 1)[1])


def check_lock():
    lock = os.path.join(REPO, "lab", "protected.sha256")
    if not os.path.exists(lock):
        sys.exit("lab/protected.sha256 missing: a person writes it with --write-lock")
    want = open(lock).read().split("\n")
    have = lock_lines()
    if [l for l in want if l] != have:
        changed = sorted(set(have) ^ set(l for l in want if l))
        sys.exit("read-only files changed since the lock:\n  " + "\n  ".join(changed[:20]))


def load_costs():
    c = tomllib.load(open(os.path.join(REPO, "lab", "cost.toml"), "rb"))
    reachable = ["inbox", "junk"]
    for cls, row in c["cost"].items():
        for act in reachable:
            if not isinstance(row.get(act), (int, float)) or math.isnan(row[act]):
                sys.exit(f"cost.{cls}.{act} is not set; the owner sets it")
    for k in ["experiment_budget_minutes", "sealed_queries_per_tag"]:
        if math.isnan(float(c["run"][k])):
            sys.exit(f"run.{k} is not set")
    for k, v in c["keep"].items():
        if isinstance(v, float) and math.isnan(v):
            sys.exit(f"keep.{k} is not set")
    return c


# Item "source" in the split manifests -> source name in lab/datasets.toml.
SOURCE_NAMES = {"spamassassin": "spamassassin-public", "lore": "lore-kernel", "untroubled": "untroubled-spam",
                "synthetic_nl": "synthetic-nl"}


def check_training_sources():
    """Train and calib may hold only sources whose recorded use allows training (lab/datasets.toml)."""
    d = tomllib.load(open(os.path.join(REPO, "lab", "datasets.toml"), "rb"))
    use = {s["name"]: s["use"] for s in d["source"]}
    allowed = {n for n, u in use.items() if u == "train"} | set(d.get("lab", {}).get("internal_training", []))
    for split in ["train", "calib"]:
        for line in open(os.path.join(LAB, "splits", f"{split}.jsonl")):
            src = SOURCE_NAMES.get(json.loads(line)["source"])
            if src not in allowed:
                sys.exit(f"{split} split holds source {src!r} (use = {use.get(src)!r}); "
                         "lab/datasets.toml does not allow training on it")


def provider_cfg(exp):
    p = exp["providers"]
    if p["embedder"] == "none":
        return None
    return resolve(p["embedder"], p.get("runtime"), p.get("precision"), p.get("max_tokens") or None,
                   p.get("threads") or None, p.get("ort_arena"), p.get("tokenizer") or None)


def threshold_of(exp, costs):
    c = costs["cost"]
    fp_cost = c["personal_or_business"]["junk"] - c["personal_or_business"]["inbox"]
    fn_cost = c["junk"]["inbox"] - c["junk"]["junk"]
    t = exp["thresholds"]["junk"]
    return fp_cost / (fp_cost + fn_cost) if t == "cost" else float(t)


def side_env():
    return dict(os.environ, HF_HOME=os.path.join(LAB, "hf"), HF_HUB_OFFLINE="1",
                FIRSTREAD_ONNX_DIR=os.path.join(LAB, "onnx"))


def ensure_cache(cfg, rv, py):
    """Embed whatever train, calib and dev texts the experiment's space does not have yet."""
    files = [os.path.join(LAB, "rendered", f"{s}.{rv}.jsonl") for s in ["train", "calib", "dev"]]
    t = time.time()
    subprocess.run(py + [os.path.join(REPO, "ml", "sidecar", "embed_batch.py")] + config_args(cfg) +
                   ["--render-version", rv, "--cache", os.path.join(LAB, "cache")] + files,
                   check=True, env=side_env(), stdout=sys.stderr)
    return time.time() - t


def wait_for(path, proc, secs=900):
    t = time.time()
    while not os.path.exists(path):
        if proc.poll() is not None:
            sys.exit(f"process exited early with {proc.returncode}")
        if time.time() - t > secs:
            sys.exit(f"timed out waiting for {path}")
        time.sleep(0.1)


def header_block(b):
    i = b.find(b"\r\n\r\n")
    return (b, b"") if i < 0 else (b[:i], b[i:])


def filter_once(it, sock):
    """One message through the real filter; returns (stdout, stderr, returncode, wall_ms, cpu_ms)."""
    raw = open(it["path"], "rb").read()
    env = {"USER": it["user"], "RECIPIENT": it["recipient"], "SENDER": it["sender"] or "",
           "FIRSTREAD_SOCKET": sock, "FIRSTREAD_DEADLINE_MS": "30000", "PATH": "/usr/bin:/bin"}
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    t = time.perf_counter()
    p = subprocess.run([os.path.join(BIN, "firstread-filter")], input=raw, capture_output=True, env=env)
    wall = (time.perf_counter() - t) * 1000
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = ((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime)) * 1000
    return raw, p, wall, cpu


def feed(items, sock, wall):
    """Every item through the real filter; returns invariant violations."""
    violations = []
    for it in items:
        raw, p, ms, _ = filter_once(it, sock)
        wall.append(ms)
        violations += check_output(it, raw, p)
    return violations


def check_output(it, raw, p):
    v = []
    if p.returncode != 0:
        return [(it["id"], f"exit {p.returncode}")]
    head_in, body_in = header_block(raw)
    head_out, body_out = header_block(p.stdout)
    if body_in != body_out:
        v.append((it["id"], "body changed"))
    if not p.stdout.startswith(b"X-Firstread:"):
        v.append((it["id"], "stamp not first"))
    lines = [l for l in head_out.split(b"\r\n") if l and l[:1] not in (b" ", b"\t")]
    ours = [i for i, l in enumerate(lines) if l.lower().split(b":")[0].strip().startswith(b"x-firstread")]
    if ours != list(range(len(ours))):
        v.append((it["id"], "foreign firstread header survived"))
    if b"fallback" in p.stderr:
        v.append((it["id"], "fallback: " + p.stderr.decode(errors="replace").strip()[:200]))
    return v


def proc_status(pid, field):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith(field + ":"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return float("nan")


def proc_cpu_ms(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) * 1000 / CLK_TCK
    except (OSError, IndexError, ValueError):
        return float("nan")


def host_busy_ms():
    f = [int(x) for x in open("/proc/stat").readline().split()[1:]]
    idle = f[3] + f[4]
    return (sum(f[:8]) - idle) * 1000 / CLK_TCK, f[7] * 1000 / CLK_TCK  # busy incl. steal, steal


def start_sidecar(run_dir, name, cfg, rv, heads, py, timing):
    sock = os.path.join(run_dir, f"{name}.sidecar.sock")
    stats = os.path.join(run_dir, f"{name}.sidecar.stats.jsonl")
    if os.path.exists(stats):
        os.unlink(stats)
    cmd = py + [os.path.join(REPO, "ml", "sidecar", "server.py"), "--socket", sock] + config_args(cfg) + \
        ["--render-version", rv, "--cache", os.path.join(LAB, "cache"), "--heads", heads]
    if timing:
        cmd += ["--no-cache", "--preload", "--stats", stats]
    proc = subprocess.Popen(cmd, env=side_env(), stdout=open(os.path.join(run_dir, f"{name}.sidecar.log"), "w"),
                            stderr=subprocess.STDOUT)
    wait_for(sock, proc)
    return proc, sock, stats


def start_daemon(run_dir, name, sidecar, calibration, combiner, threshold):
    sock = os.path.join(run_dir, f"{name}.sock")
    records = os.path.join(run_dir, f"{name}.records.jsonl")
    if os.path.exists(records):
        os.unlink(records)
    cmd = [os.path.join(BIN, "firstreadd"), "--socket", sock, "--records", records, "--deployment", "lab",
           "--mac-key", MAC_KEY, "--trusted-authserv", TRUSTED_AUTHSERV, "--junk-threshold", str(threshold),
           "--data-class", "public"]
    if sidecar:
        cmd += ["--sidecar", sidecar, "--calibration", calibration]
    if combiner:
        cmd += ["--combiner", combiner]
    proc = subprocess.Popen(cmd, stderr=open(os.path.join(run_dir, f"{name}.daemon.log"), "w"))
    wait_for(sock, proc)
    return proc, sock, records


def stop(*procs):
    for p in procs:
        if p:
            p.terminate()
            p.wait()


def timing_sample(dev, n, warm):
    ids = sorted(it["id"] for it in dev)
    random.Random(TIMING_SEED).shuffle(ids)
    by_id = {it["id"]: it for it in dev}
    return [by_id[i] for i in ids[:warm]], [by_id[i] for i in ids[warm:warm + n]]


class Arm:
    """One configuration in the timing pass: its sidecar (if any) and daemon."""

    def __init__(self, run_dir, label, cfg_dir, exp, costs, py):
        self.label = label
        rv = exp["render"]["version"]
        cfg = provider_cfg(exp)
        self.side = self.side_sock = self.stats = None
        if cfg:
            self.side, self.side_sock, self.stats = start_sidecar(run_dir, f"timing-{label}", cfg, rv,
                                                                  os.path.join(cfg_dir, "heads.json"), py, True)
        combiner = os.path.join(cfg_dir, "combiner.json")
        self.daemon, self.sock, self.records = start_daemon(
            run_dir, f"timing-{label}", self.side_sock, os.path.join(cfg_dir, "calibration.json") if cfg else None,
            combiner if os.path.exists(combiner) else None, threshold_of(exp, costs))
        self.wall, self.cpu, self.seen = [], [], 0
        self.violations = []

    def own_cpu_ms(self):
        return sum(proc_cpu_ms(p.pid) for p in [self.side, self.daemon] if p)

    def sidecar_cpu_since_last(self):
        if not self.stats:
            return 0.0
        lines = open(self.stats).read().splitlines()
        new, self.seen = lines[self.seen:], len(lines)
        return sum(json.loads(l)["cpu_ms"] for l in new)

    def one(self, it, record):
        d0 = proc_cpu_ms(self.daemon.pid)
        raw, p, wall, fcpu = filter_once(it, self.sock)
        dcpu = proc_cpu_ms(self.daemon.pid) - d0
        scpu = self.sidecar_cpu_since_last()
        if record:
            self.wall.append(wall)
            self.cpu.append(fcpu + scpu + dcpu)
            self.violations += check_output(it, raw, p)

    def peak_mb(self):
        return sum(proc_status(p.pid, "VmHWM") for p in [self.side, self.daemon] if p)

    def close(self):
        stop(self.daemon, self.side)


def ratio_ci(a, b, n=2000, seed=7):
    """Ratio of means sum(b)/sum(a) over paired messages, with a bootstrap CI95."""
    rng = random.Random(seed)
    k = len(a)
    rs = []
    for _ in range(n):
        idx = [rng.randrange(k) for _ in range(k)]
        sa = sum(a[i] for i in idx)
        rs.append(sum(b[i] for i in idx) / sa if sa else float("nan"))
    rs.sort()
    return sum(b) / sum(a), [rs[int(0.025 * n)], rs[int(0.975 * n) - 1]]


def ratio_verdict(point, ci, improve, worse):
    if ci[1] < 1.0 and point <= improve:
        return "improve"
    if ci[0] > 1.0 or point >= worse:
        return "worse"
    return "equal"


def timing_pass(run_dir, exp, costs, py, champ_dir, dev, keep):
    """Champion (A) and this run (B), interleaved on the same messages. Returns the timing block."""
    warm, sample = timing_sample(dev, int(keep["timing_messages"]), int(keep["timing_warmup"]))
    arms = []
    try:
        if champ_dir:
            arms.append(Arm(run_dir, "A", champ_dir, tomllib.load(open(os.path.join(champ_dir, "experiment.toml"), "rb")),
                            costs, py))
        arms.append(Arm(run_dir, "B", run_dir, exp, costs, py))
        for it in warm:
            for arm in arms:
                arm.one(it, False)
        busy0, steal0 = host_busy_ms()
        ours0 = sum(a.own_cpu_ms() for a in arms) + sum(resource.getrusage(w).ru_utime * 1000 + resource.getrusage(w).ru_stime * 1000
                                                         for w in [resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN])
        t0 = time.perf_counter()
        for i, it in enumerate(sample):
            for arm in (arms if i % 2 == 0 else arms[::-1]):
                arm.one(it, True)
        wall_s = time.perf_counter() - t0
        busy1, steal1 = host_busy_ms()
        ours1 = sum(a.own_cpu_ms() for a in arms) + sum(resource.getrusage(w).ru_utime * 1000 + resource.getrusage(w).ru_stime * 1000
                                                         for w in [resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN])
        peaks = {a.label: a.peak_mb() for a in arms}
    finally:
        for a in arms:
            a.close()
    # CPU on this machine that was neither ours nor idle (other processes, or the hypervisor
    # taking the CPU away) while we measured, as a share of one core.
    other = max(0.0, (busy1 - busy0) - (ours1 - ours0)) / (wall_s * 1000)
    steal = (steal1 - steal0) / (wall_s * 1000)
    B = arms[-1]
    out = {"messages": len(sample), "other_cpu_cores": round(other, 3), "steal_cores": round(steal, 3),
           "B": summary_of(B, peaks["B"]), "violations": B.violations[:5], "n_violations": len(B.violations)}
    out["B"]["records"] = B.records
    if champ_dir:
        A = arms[0]
        out["A"] = summary_of(A, peaks["A"])
        lat, lat_ci = ratio_ci(A.wall, B.wall)
        cpu, cpu_ci = ratio_ci(A.cpu, B.cpu)
        ram = peaks["B"] / peaks["A"] if peaks["A"] else float("nan")
        noisy = other > float(keep["max_other_cpu_cores"])
        out["latency"] = {"ratio": lat, "ci95": lat_ci,
                          "verdict": "unmeasured" if noisy else ratio_verdict(lat, lat_ci, keep["latency_improve"], keep["latency_worse"])}
        out["cpu"] = {"ratio": cpu, "ci95": cpu_ci,
                      "verdict": "unmeasured" if noisy else ratio_verdict(cpu, cpu_ci, keep["cpu_improve"], keep["cpu_worse"])}
        out["ram"] = {"ratio": ram, "verdict": "improve" if ram <= keep["ram_improve"] else
                      ("worse" if ram >= keep["ram_worse"] else "equal")}
    return out


def summary_of(arm, peak):
    w = sorted(arm.wall)
    return {"latency_p50_ms": score.pct(w, 0.5), "latency_p99_ms": score.pct(w, 0.99),
            "latency_mean_ms": sum(w) / len(w), "cpu_ms_per_email": sum(arm.cpu) / len(arm.cpu), "peak_mb": peak}


def live_vs_cached(timing_records, quality_records):
    """Decisions computed live in the timing pass must equal those from the cached vectors."""
    q = {r["idempotency_key"]: r for r in quality_records}
    dp, flips = 0.0, 0
    for r in timing_records:
        o = q.get(r["idempotency_key"])
        if o and r.get("p_junk") is not None and o.get("p_junk") is not None:
            dp = max(dp, abs(r["p_junk"] - o["p_junk"]))
            flips += (r["directive"].get("folder") == "junk") != (o["directive"].get("folder") == "junk")
    return dp, flips


def quality_verdict(cmp, tol):
    if cmp["new_false_positives"] or cmp["slices_worse"] or cmp["ci95_per_1k"][0] > 0 or cmp["point_per_1k"] > tol:
        return "worse"
    if cmp["ci95_per_1k"][1] < 0:
        return "improve"
    return "equal"


def run_tag():
    """The run tag is the branch name without its lab/ prefix (lab/program.md: branch lab/<tag>)."""
    b = subprocess.run(["git", "-C", REPO, "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True).stdout.strip()
    return b.removeprefix("lab/") or "untagged"


def sealed_query(costs):
    """Count and log a sealed query before it runs (docs/13-lab.md section 4); refuse past the ration."""
    log = os.path.join(LAB, "sealed", "queries.log")
    tag = run_tag()
    used = [l for l in open(log) if l.split("\t")[1] == tag] if os.path.exists(log) else []
    if len(used) >= int(costs["run"]["sealed_queries_per_tag"]):
        sys.exit(f"sealed queries for tag {tag}: {len(used)} used of {costs['run']['sealed_queries_per_tag']}; refusing")
    commit = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    open(log, "a").write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\t{tag}\t{commit}\n")
    return os.path.join(LAB, "sealed", "runs", f"{tag}-{len(used) + 1}")


def seal_away(run_dir, private, s):
    """Per-message sealed output (records, daemon log, message ids) goes to the lab data dir, not run_dir."""
    os.makedirs(private, exist_ok=True)
    for f in ["sealed.records.jsonl", "sealed.daemon.log"]:
        if os.path.exists(os.path.join(run_dir, f)):
            shutil.move(os.path.join(run_dir, f), os.path.join(private, f))
    json.dump(s, open(os.path.join(private, "summary.sealed.json"), "w"), indent=1)
    s["hard_negative_fp"] = len(s.get("hard_negative_fp", []))
    s["violation_examples"] = len(s.get("violation_examples", []))
    s["private"] = private


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--write-lock" in sys.argv:
        open(os.path.join(REPO, "lab", "protected.sha256"), "w").write("\n".join(lock_lines()) + "\n")
        print("lock written")
        return
    check_lock()
    check_training_sources()
    sealed = "--sealed" in sys.argv
    timing = not sealed and "--no-timing" not in sys.argv
    run_dir = os.path.abspath(args[0])
    os.makedirs(run_dir, exist_ok=True)
    exp_path = os.path.join(REPO, "lab", "experiment.toml")
    shutil.copy(exp_path, os.path.join(run_dir, "experiment.toml"))
    exp = tomllib.load(open(exp_path, "rb"))
    costs = load_costs()
    private = sealed_query(costs) if sealed else None
    keep = costs["keep"]
    c = costs["cost"]
    threshold = threshold_of(exp, costs)
    t0 = time.time()
    py = [sys.executable, "-I"]
    cache = os.path.join(LAB, "cache")
    rv = exp["render"]["version"]
    cfg = provider_cfg(exp)
    name = exp["providers"]["embedder"]
    embed_s = 0.0
    sidecar_sock = calibration = side = None
    if cfg:
        embed_s = ensure_cache(cfg, rv, py)
        subprocess.run(py + [os.path.join(REPO, "ml", "heads", "train.py"), "heads", run_dir, exp_path, LAB, cache],
                       check=True, env=side_env())
        side, sidecar_sock, _ = start_sidecar(run_dir, "quality", cfg, rv, os.path.join(run_dir, "heads.json"), py, False)
        calibration = os.path.join(run_dir, "calibration.json")
    try:
        calib = [json.loads(l) for l in open(os.path.join(LAB, "splits", "calib.jsonl"))]
        d, sock, calib_records = start_daemon(run_dir, "calib", sidecar_sock, calibration, None, threshold)
        v1 = feed(calib, sock, [])
        stop(d)
        if sum(1 for _ in open(calib_records)) != len(calib):
            sys.exit("calib records missing: every decision must be recorded")
        subprocess.run(py + [os.path.join(REPO, "ml", "heads", "train.py"), "combiner", run_dir, exp_path, LAB, calib_records],
                       check=True, env=side_env())
        target = "sealed" if sealed else "dev"
        mpath = os.path.join(LAB, "sealed", "sealed.jsonl") if sealed else os.path.join(LAB, "splits", "dev.jsonl")
        items = [json.loads(l) for l in open(mpath)]
        d, sock, recs_path = start_daemon(run_dir, target, sidecar_sock, calibration, os.path.join(run_dir, "combiner.json"), threshold)
        wall = []
        v2 = feed(items, sock, wall)
        stop(d)
    finally:
        stop(side)
    records = [json.loads(l) for l in open(recs_path)]
    champ_dir = os.path.realpath(os.path.join(REPO, "lab", "runs", "champion"))
    champ_dir = champ_dir if not sealed and os.path.exists(os.path.join(champ_dir, "dev.records.jsonl")) else None
    base_dir = os.path.realpath(os.path.join(REPO, "lab", "runs", "baseline"))
    base_dir = base_dir if not sealed and os.path.exists(os.path.join(base_dir, "dev.records.jsonl")) else None
    champ = [json.loads(l) for l in open(os.path.join(champ_dir, "dev.records.jsonl"))] if champ_dir else None
    s = score.score(items, records, c, champ, wall)
    s.update({"threshold": threshold, "embedder": name, "provider": {k: cfg[k] for k in ["runtime", "precision", "max_tokens", "threads"]} if cfg else None,
              "split": target, "embed_seconds": round(embed_s, 1), "invariant_violations": len(v1) + len(v2),
              "violation_examples": (v1 + v2)[:5]})
    if sealed:
        s["sweep"] = score.sweep(items, records, c, [9, 20, 30, 50, 100, 200, 999])
    gates = []
    tol = float(keep["quality_tolerance_per_1k"])
    if champ:
        s["quality"] = score.compare(items, records, champ, c)
        s["quality"]["verdict"] = quality_verdict(s["quality"], tol)
    if base_dir:
        base = [json.loads(l) for l in open(os.path.join(base_dir, "dev.records.jsonl"))]
        s["quality_vs_baseline"] = score.compare(items, records, base, c)
        if quality_verdict(s["quality_vs_baseline"], tol) == "worse":
            gates.append("drift_vs_baseline")
    if timing:
        tp = timing_pass(run_dir, exp, costs, py, champ_dir, items, keep)
        trec = [json.loads(l) for l in open(tp["B"].pop("records"))]
        tp["live_vs_cached_max_dp"], tp["live_vs_cached_flips"] = live_vs_cached(trec, records)
        s["timing"] = tp
        if tp["n_violations"]:
            gates.append("invariants")
        if tp["live_vs_cached_flips"]:
            gates.append("train_serve_skew")
    if s["invariant_violations"]:
        gates.append("invariants")
    if s["not_allowed"]:
        gates.append("data_rules")
    if s["missing_records"]:
        gates.append("records")
    s["gates"] = "pass" if not gates else "fail:" + ",".join(sorted(set(gates)))
    s["seconds"] = round(time.time() - t0, 1)
    # The keep rule: one axis better beyond noise, none worse, every gate passing.
    if champ and timing:
        q, tp = s["quality"]["verdict"], s["timing"]
        fp = [tp["cpu"]["verdict"], tp["ram"]["verdict"]]
        foot = "unmeasured" if "unmeasured" in fp else ("worse" if "worse" in fp else ("improve" if "improve" in fp else "equal"))
        axes = {"quality": q, "latency": tp["latency"]["verdict"], "footprint": foot}
        s["axes"] = axes
        ok = s["gates"] == "pass" and "worse" not in axes.values() and "unmeasured" not in axes.values() \
            and "improve" in axes.values()
        s["keep"] = "yes" if ok else "no"
    if sealed:
        seal_away(run_dir, private, s)
    json.dump(s, open(os.path.join(run_dir, f"summary.{target}.json"), "w"), indent=1)
    print("---")
    for k in ["keep", "axes", "gates", "cost_per_1k", "champion_cost_per_1k", "false_positives", "false_negatives",
              "hard_negative_fp", "ece_primary", "threshold", "embedder", "provider", "invariant_violations",
              "embed_seconds", "seconds"]:
        if k in s:
            print(f"{k + ':':<22}{s[k]}")
    if "quality" in s:
        qd = s["quality"]
        print(f"{'quality:':<22}{qd['verdict']} delta {qd['point_per_1k']:+.2f}/1k CI95 [{qd['ci95_per_1k'][0]:+.2f}, "
              f"{qd['ci95_per_1k'][1]:+.2f}] new_fp {len(qd['new_false_positives'])} slices_worse {qd['slices_worse']}")
    if "timing" in s:
        tp = s["timing"]
        for arm in ["A", "B"]:
            if arm in tp:
                a = tp[arm]
                print(f"{'timing_' + arm + ':':<22}p50 {a['latency_p50_ms']:.1f} ms p99 {a['latency_p99_ms']:.1f} ms "
                      f"cpu {a['cpu_ms_per_email']:.1f} ms/email peak {a['peak_mb']:.0f} MB")
        for k in ["latency", "cpu", "ram"]:
            if k in tp:
                ci = f" CI95 [{tp[k]['ci95'][0]:.3f}, {tp[k]['ci95'][1]:.3f}]" if "ci95" in tp[k] else ""
                print(f"{k + ':':<22}{tp[k]['verdict']} ratio {tp[k]['ratio']:.3f}{ci}")
        print(f"{'timing_noise:':<22}other {tp['other_cpu_cores']} cores, steal {tp['steal_cores']} cores; "
              f"live vs cached max dp {tp['live_vs_cached_max_dp']:.2e}, flips {tp['live_vs_cached_flips']}")
    print(f"{'by_slice:':<22}{json.dumps({k: round(v, 1) for k, v in s['cost_per_1k_by_slice'].items()})}")


if __name__ == "__main__":
    main()
