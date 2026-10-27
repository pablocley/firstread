# lab: a mock instance fed like production, and an autoresearch loop over it

Design: [docs/13-lab.md](../docs/13-lab.md). Agent instructions: [program.md](program.md).
Results: [results/](results/) and [docs/measurements/](../docs/measurements/).

## Reproduce

Scripts are run through `sh` / `bash` because the GitHub copy does not keep executable bits.

```sh
sh lab/reproduce.sh ./lab-data     # venv with the pinned packages, build, fetch (about 2.7 GB with all four models), prepare, render, export, one run
sudo sh lab/l2/setup.sh && python3 -I lab/l2/cases.py    # optional: the real Dovecot stack
```

Needs Rust, Python 3.13, curl, tar, 7z and git. Python packages go into `./lab-data/venv`;
for later commands by hand, `export PATH="$PWD/lab-data/venv/bin:$PATH"`.

On main, `lab/experiment.toml` is the champion of tag `oct26b`; the run at the end of
`reproduce.sh` gives cost 84.8 per 1,000 on dev with no legitimate message in Junk and 95 spam
missed (checked 2026-10-27 from the main worktree, `--no-timing`).

What makes a rerun identical:

| step | pinned by |
|---|---|
| archives | URL and sha256 per archive in `datasets.toml`; the one archive still growing (untroubled 2026-10) is marked `mutable` |
| lore mail | list, pinned commit and count in `datasets.toml` |
| messages | `data/untroubled.txt` fixes the untroubled sample; `data/manifest.json` holds a hash over all 9,566 messages (origin, sha256 after normalisation); `prepare.py` refuses any difference and writes the per-message list to find it |
| splits | `data/manifest.json`: per-split hash over ids, labels, slices and message hashes |
| models | Hugging Face repo, revision and file list in `ml/sidecar/providers.py` |
| DNS | `data/dns-recorded/`: every answer our own DKIM and DMARC checks ask for, recorded once (`harness/record_dns.py`, DNS-over-HTTPS) for the 2026 mail, with the window it stands for in `dns-recorded.meta.json`; replayed by the daemon, never resolved again |
| ONNX | `export_onnx.py` checks fp32 against torch (max abs diff 1e-4); `data/onnx-e5-small.json` holds the hashes of our export |
| packages | `requirements.txt` |
| harness | `protected.sha256`, checked before every run |

Not in the repository: the mail itself (terms in `datasets.toml`; lore and SpamAssassin may not be
redistributed), model weights, embedding caches, per-run records, and anything trained on
evaluation-only sources.

## Layout

```
datasets.toml   sources, terms, archives, lore pins        cost.toml      costs and keep tolerances
experiment.toml the agent's file                            program.md     the agent's instructions
harness/        fetch, prepare, render, run, score, synthetic Dutch, latency, learning (mailboxes on a clock)
loop/           exp.sh (one iteration), queue.py (a list of one-change ideas), log.py, patches/, queues/
l2/             Dovecot config, Sieve scripts, fixtures, setup.sh, cases.py
data/           message and split references (hashes only)
results/<tag>/  results.tsv, pareto.tsv and head-to-head.json of each run tag, committed when the tag ends
analysis/       probes outside the harness and the README charts
```

## The learning test

```sh
HF_HUB_OFFLINE=1 python3 -I lab/harness/learning.py <run_dir>   # memory off vs on, three owner profiles, poisoning check
```

Mailboxes on a clock, owners acting through the real `firstread feedback`; `[combiner] memory` in
`experiment.toml` picks how memory is fitted. Keep `<run_dir>` short (Unix socket paths). Results:
[`results/memory-v0/`](results/memory-v0/) ([measurement](../docs/measurements/2026-10-27-mailbox-memory.md)),
[`results/memory-v1/`](results/memory-v1/) ([measurement](../docs/measurements/2026-10-27-auth-dns-memory-v1.md)).

## One iteration

```sh
git checkout -b lab/<tag>                     # from main
# edit lab/experiment.toml (one idea), then:
bash lab/loop/exp.sh "<what changed>"         # keep or discard, as the harness decides
python3 -I lab/loop/queue.py lab/loop/queues/<file>.json   # or many, in order
```
