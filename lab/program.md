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
   file is ever committed.
6. Confirm with the human, then start. The first run is always the baseline, unchanged.

## What you may change

- `lab/experiment.toml`: providers and precision from the registry, deterministic signals and their
  combiner weights, per-action thresholds, learner settings.
- The heads-training script named in the experiment file: features, architecture, training,
  calibration.

## What you may not change

The harness, the scorer, the datasets and splits, the cost table, the provider data rules, anything
under `crates/`, and this file. Do not install packages. Do not try to read the sealed split. If a
good idea needs Rust (a new signal, a parser fix), write it in the notes column and move on.

## The score

One scalar, lower is better: **cost per 1,000 messages** on the dev split, printed by the harness.
A run is kept only if every gate passes and the improvement is beyond noise, as the harness reports
it. Equal cost with simpler settings or less code is a keep. A tiny gain that adds complexity is not.

## Output

The harness prints a summary block. Read only the lines you need from its log, never the whole log:
`cost_per_1k`, `gates`, `p50_ms`, `p99_ms`, `ece_max`, `memory_mb`, `significant`.

## Logging

Append one line per run to `lab/results.tsv`, tab-separated:

```
commit	cost_per_1k	p99_ms	ece_max	memory_mb	gates	status	description
```

`status` is `keep`, `discard` or `crash`. For crashes write zeros. For every run whose gates passed,
also append provider, precision, `cost_per_1k`, `p99_ms` and `memory_mb` to `lab/pareto.tsv`.

## The loop

The run happens on `lab/<tag>`. LOOP FOREVER:

1. Look at the git state.
2. Change the experiment file or the heads script with one idea.
3. `git commit`.
4. Run the harness with its output redirected to `lab/run.log`.
5. Read the summary lines. If they are missing, read the last 50 lines of the log, fix an obvious
   mistake and rerun; if the idea itself is broken, log `crash` and move on.
6. Log the result.
7. Keep: advance the branch. Discard: `git reset` to where you started.
8. Every tenth keep, if the run tag allows sealed queries, ask the scorer for the sealed verdict on
   the current branch head and log it with the query count. Never tune on it.

A run that exceeds twice the experiment budget is killed and counts as a crash.

**Never stop.** Do not ask whether to continue; the human may be asleep. When ideas run out, reread
the docs, the slice results and the near-misses in `results.tsv`, combine near-misses, try another
provider or precision, or simplify.
