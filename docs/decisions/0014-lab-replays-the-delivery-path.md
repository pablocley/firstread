# ADR-0014 · Improve firstread in a lab that replays the real delivery path, autoresearch-style

Status: accepted

## Context

Choosing between System 1 models, precisions and deterministic knobs needs repeatable measurements
on mail that enters exactly as it does in production. Karpathy's autoresearch shows a loop that
works unattended: one editable surface, a fixed budget per run, one score, keep or `git reset`.
Its weakness for us is that it scores every run on the same validation set.

## Decision

- The lab runs the real filter and daemon binaries with the delivery context Dovecot provides
  (L1), a real Dovecot and Pigeonhole stack for candidates (L2), and shadow mode before release (L3).
- Replay is deterministic: a replay clock, recorded lookups, no live network, simulated mailboxes.
- The agent edits only the experiment file and one heads-training script. The harness, data,
  splits, scorer and cost table are read-only and hash-checked.
- The score is cost per 1,000 messages from a cost table people set, with hard gates (hard
  negatives, latency, calibration, slices, memory, data rules). Improvements count only beyond
  measured noise.
- A sealed test split, newer than all other data and invisible to the agent, is queried a rationed
  number of times with coarse answers.
- Public corpora are used only within their terms, recorded per source. Dutch mail with full
  headers comes from consenting mailboxes in capture mode, never from the repository.

## Consequences

- Model and knob choices come with a Pareto table of quality, latency and memory per provider.
- Nothing from the lab ships directly: candidates still go through champion / challenger, the L2
  stack and shadow mode.
- Details: [13 · Lab](../13-lab.md).
