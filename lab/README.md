# lab: a mock instance fed like production, and an autoresearch loop over it

Design: [docs/13-lab.md](../docs/13-lab.md). Agent instructions: [program.md](program.md).
Results: [results/](results/) and [docs/measurements/](../docs/measurements/).

## Reproduce

```sh
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1+cpu
pip install -r lab/requirements.txt
lab/reproduce.sh ./lab-data        # build, fetch (about 2.7 GB with all four models), prepare, render, export, one run
sudo lab/l2/setup.sh && python3 -I lab/l2/cases.py    # optional: the real Dovecot stack
```

What makes a rerun identical:

| step | pinned by |
|---|---|
| archives | URL and sha256 per archive in `datasets.toml`; the one archive still growing (untroubled 2026-10) is marked `mutable` |
| lore mail | list, pinned commit and count in `datasets.toml` |
| messages | `data/untroubled.txt` fixes the untroubled sample; `data/manifest.json` holds a hash over all 9,566 messages (origin, sha256 after normalisation); `prepare.py` refuses any difference and writes the per-message list to find it |
| splits | `data/manifest.json`: per-split hash over ids, labels, slices and message hashes |
| models | Hugging Face repo, revision and file list in `ml/sidecar/providers.py` |
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
harness/        fetch, prepare, render, run, score, synthetic Dutch, latency
loop/           exp.sh (one iteration), queue.py (a list of one-change ideas), log.py, patches/, queues/
l2/             Dovecot config, Sieve scripts, fixtures, setup.sh, cases.py
data/           message and split references (hashes only)
results/<tag>/  results.tsv and pareto.tsv of each run tag, committed when the tag ends
analysis/       probes outside the harness and the README charts
```

## One iteration

```sh
git checkout -b lab/<tag>                     # from main
# edit lab/experiment.toml (one idea), then:
lab/loop/exp.sh "<what changed>"              # keep or discard, as the harness decides
python3 -I lab/loop/queue.py lab/loop/queues/<file>.json   # or many, in order
```
