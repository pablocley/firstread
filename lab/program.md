# firstread lab: instructions for the research agent

Adapted from Karpathy's autoresearch `program.md` (MIT). The design is in `docs/13-lab.md`; read it
first. If the lab harness described there does not exist yet, stop and say so: this file is for
running experiments, not for building the harness.

## Setup

1. **Agree on a run tag** with the human, based on today's date (for example `oct27`). The branch
   `lab/<tag>` must not exist yet.
2. **Create the branch** `lab/<tag>` from the current main.
3. **Read for context**: `README.md`, `docs/13-lab.md`, `docs/14-providers.md`, `docs/07-evaluation.md`,
   this file, `lab/experiment.toml`, `lab/cost.toml`, `lab/datasets.toml`.
4. **Check the harness refuses nothing**: the cost table has every value set, the datasets in the
   manifest are present with matching hashes, the reference machine is the one recorded in the
   cost table. If any check fails, tell the human and stop.
5. **Initialise `lab/results.tsv`** with the header row only, and `lab/pareto.tsv` likewise. Neither
   file is committed on the run branch; when the tag ends, a person copies both to
   `lab/results/<tag>/` on main.
6. Confirm with the human, then start. The first run is always the baseline, unchanged: point
   both `lab/runs/baseline` and `lab/runs/champion` at it.

## What you may change

- `lab/experiment.toml`: providers from the registry with their runtime, numeric format, token
  limit and threads; deterministic signals and their combiner weights; per-action thresholds;
  learner settings. A new provider configuration fills its own embedding cache on its first run
  (one message at a time, so it takes minutes); later runs in the same space are fast.
- The heads-training script named in the experiment file: features, architecture, training,
  calibration.

## What you may not change

The harness, the scorer, the datasets and splits, the cost table, the provider data rules, anything
under `crates/`, and this file. Do not install packages. Do not try to read the sealed split. If a
good idea needs Rust (a new signal, a parser fix), write it in the notes column and move on.

## The score and the keep rule

Three axes, judged against the champion on every run (owner, 2026-10-26):

- **Quality**: cost per 1,000 messages on the primary slice of the dev split, from the cost table.
- **Latency**: wall time per email through the real filter, with the model computing every vector.
- **Footprint**: CPU time per email (filter, daemon, sidecar) and peak memory (daemon plus sidecar).

The harness measures latency and footprint in a timing pass: the champion and the run each get a
sidecar without cache and a daemon, and the same sample of dev messages goes to both, interleaved,
so machine noise hits both alike. It prints a verdict per axis, `improve`, `equal` or `worse`, by
the tolerances in the `[keep]` section of the cost table, and `keep: yes` only when **at least one
axis improves and none is worse**, every gate passes, and quality is not worse than the tag's
baseline (`lab/runs/baseline`). If other processes took more CPU than allowed during the timing
pass, latency and CPU are `unmeasured`: rerun.

Follow the harness's `keep` line. Do not override it in either direction. A trade (better on one
axis, worse on another) is a discard however good it looks; log it, it belongs on the Pareto list.

## Output

The harness prints a summary block after `---`. Read only the lines you need from its log, never
the whole log: `keep`, `axes`, `gates`, `cost_per_1k`, `quality`, `timing_A`, `timing_B`,
`latency`, `cpu`, `ram`, `timing_noise`, `by_slice`. The full summary is in
`lab/runs/<commit>/summary.dev.json`.

The harness fills a new space's cache itself. To time the model alone, outside the delivery
path: `python3 -I lab/harness/latency.py <lab_data> --embedder <name> [--runtime ...]`. ONNX
models are exported once by a person (`ml/sidecar/export_onnx.py`). A person changes the
read-only files on main and re-locks with `python3 -I lab/harness/run.py --write-lock`, then
merges main into the run branch.

## Logging

Append one line per run to `lab/results.tsv`, tab-separated:

```
commit	cost_per_1k	latency_ms	cpu_ms	peak_mb	axes	status	description
```

`latency_ms` is the run's mean filter wall time per email in the timing pass, `cpu_ms` its CPU per
email, `peak_mb` its peak memory, `axes` the three verdicts (for example `q=equal,l=improve,f=improve`).
`status` is `keep`, `discard` or `crash`. For crashes write zeros. For every run whose gates passed,
also append the provider configuration, `cost_per_1k`, `latency_ms`, `cpu_ms` and `peak_mb` to
`lab/pareto.tsv`, kept or not: the trades the keep rule refuses are the Pareto front.

## The loop

The run happens on `lab/<tag>`. LOOP FOREVER:

1. Look at the git state.
2. Change the experiment file or the heads script with one idea.
3. `git commit`.
4. Run the harness with its output redirected to `lab/run.log` (`lab/loop/exp.sh "<idea>"` does
   steps 3 to 7; `lab/loop/queue.py` runs a list of ideas through it):
   `python3 -I lab/harness/run.py lab/runs/<short commit> > lab/run.log 2>&1`
   (data under `FIRSTREAD_LAB_DATA`, default `/home/claude/lab-data`; release binaries built with
   `cargo build --release`). After every keep, point the symlink `lab/runs/champion` at that run's
   directory: the harness compares each run against `lab/runs/champion/dev.records.jsonl`.
5. Read the summary lines. If they are missing, read the last 50 lines of the log, fix an obvious
   mistake and rerun; if the idea itself is broken, log `crash` and move on.
6. Log the result.
7. Keep: advance the branch and point `lab/runs/champion` at the run. Discard: `git reset` to where
   you started.
8. Every tenth keep, if the run tag allows sealed queries, ask the scorer for the sealed verdict on
   the current branch head (`python3 -I lab/harness/run.py --sealed lab/runs/<commit>-sealed`)
   and log it with the query count. Never tune on it.

A run that exceeds twice the experiment budget is killed and counts as a crash.

**Never stop.** Do not ask whether to continue; the human may be asleep. When ideas run out, reread
the docs, the slice results and the near-misses in `results.tsv`, combine near-misses, try another
provider or precision, or simplify.
