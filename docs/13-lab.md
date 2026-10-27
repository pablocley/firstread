# 13 · The lab: a mock instance, a blind test, and an autoresearch loop

The lab is a complete firstread instance that runs offline. It receives mail exactly as production
does, decides with frozen state and recorded lookups, and scores every decision against labels.
An agent improves it the way [autoresearch](https://github.com/karpathy/autoresearch) improves a
training script: change one thing, run for a fixed budget, keep the commit if the score improved,
reset if not, and repeat until stopped. The question it answers is which System 1 model, at which
precision, with which deterministic knobs, gives the best quality inside the latency budget.

## 1 · What autoresearch does, and what changes here

Checked against the repository at commit `228791f` (2026-03-25), MIT licensed:

| autoresearch | the firstread lab |
|---|---|
| `prepare.py`: data, tokenizer, evaluation. Read-only | the harness, the datasets, the scorer, the cost table. Read-only, hash-checked before every run |
| `train.py`: the one file the agent edits | the experiment file (`lab/experiment.toml`: model choice, precision, knobs, thresholds) and one heads-training script. Nothing else |
| `program.md`: instructions, edited by the human | [`lab/program.md`](../lab/program.md), edited by the human |
| fixed 5-minute training budget | fixed wall-clock budget per experiment, set in the cost table |
| one metric, `val_bpb`, lower is better | one scalar, **cost per 1,000 messages** on the dev split, lower is better, plus hard gates (section 5) |
| keep if strictly better, else `git reset` | keep only if quality, latency or footprint is better **beyond noise** and none is worse (paired bootstrap on quality, an interleaved timing pass on latency and footprint), and every gate passes |
| `results.tsv`, untracked | `results.tsv` and `pareto.tsv`, untracked during the run, committed under `lab/results/<tag>/` when the tag ends |
| simplicity criterion | the same: equal score with less complexity is a win |
| never stop | the same |

The one deliberate departure: autoresearch scores every run on the same validation set, which
invites overfitting to it over hundreds of runs. firstread adds a **sealed test split** the agent
never sees (section 4).

## 2 · Fidelity levels: "exactly how we would receive them"

| level | what runs | what goes in | what comes out | used for |
|---|---|---|---|---|
| **L1 filter harness** | the real `firstread-filter` binary and the real daemon, as separate processes over the real Unix socket | the message bytes on stdin (CRLF, as Dovecot sends by default), `USER` / `SENDER` / `RECIPIENT` / `ORIG_RECIPIENT` in the environment, the filter's deadline | the written bytes, the exit code, the record | every experiment in the loop |
| **L2 stack harness** | a container with Dovecot and Pigeonhole, the two global Sieve scripts of [12](12-interfaces.md) section 4.1.1, and simulated user scripts | each message delivered over LMTP | what the mailbox ends up holding, read back over IMAP: folder, keywords, headers, body bytes | promotion candidates and nightly; it also closes the verification list in [12](12-interfaces.md) section 7 |
| **L3 shadow** | production, decisions logged, nothing applied | real deliveries | events and records | promotion out of the lab ([07](07-evaluation.md) rollout step 1) |

At every level the harness controls three things production does not:

- **The clock.** Each message carries its recorded arrival time; counters decay and lookups resolve
  as of that time.
- **The network.** No live lookups. DNS, RDAP and similar answers come from the recorded lookups of
  [12](12-interfaces.md) section 3.3. A message without recorded lookups has its authentication
  and reputation signals marked `Unavailable` and is scored on a slice of its own. Live lookups
  during replay would make results unrepeatable, and keys and domains in old corpora have changed.
- **The mailboxes.** Corpus messages are assigned to simulated mailboxes so that mailbox-scope
  signals (first contact, vendor IBAN history, folder habits) mean something.

## 3 · Data

### 3.1 Public corpora, checked 2026-10-26

Every source is listed in [`lab/datasets.toml`](../lab/datasets.toml) with its licence, its
fidelity and what we may use it for. The ones worth using:

| source | what it is | raw headers | terms | use |
|---|---|---|---|---|
| [untroubled.org spam archive](https://untroubled.org/spam) | spam received since 1998, yearly archives to 2025 and monthly in 2026 (to October), updated daily | messages as received; the page notes most carry forged headers | "Permission is hereby granted to use this archive without restriction" | spam for training and evaluation; note the page's own warning that the main receiving domain expired in April 2018, so recent volume may be thin |
| [lore.kernel.org list archives](https://kernel.org/lore.html) | public mailing-list traffic, cloneable with git | **full**: we inspected three October 2026 messages with `Received`, `DKIM-Signature`, ARC and `Authentication-Results` from the list server | no terms stated on the page; authors keep copyright | modern ham with real authentication results; English, technical, list mail only; evaluation, never redistributed |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html) | 6,047 messages including 250 `hard_ham`, assembled 2002 to 2006 | "All headers are reproduced in full", some addresses obfuscated | no formal licence; "Copyright for the text in the messages remains with the original senders" | parser robustness and a classic regression slice |
| [Enron, CMU release of 7 May 2015](https://www.cs.cmu.edu/%7E./enron/) | about 0.5M messages of a real company, organised per user with their folders | attachments removed, some addresses rewritten; transport headers not documented | no licence; made public by FERC; "be sensitive to the privacy of the people involved" | English business ham, and real per-user folder habits for the week-one learning test |
| [TREC 2007 public corpus](https://plg.uwaterloo.ca/~gvcormac/treccorpus07/about.html) | 75,419 messages (25,220 ham, 50,199 spam), April to July 2007 | not stated | [usage agreement](https://plg.uwaterloo.ca/~gvcormac/treccorpus): research and development only, no redistribution | evaluation only, after accepting the agreement |

Not usable as they stand:

- [Phishing Pot](https://github.com/rf-peixoto/phishing_pot): 12,271 real phishing `.eml` files with
  routing and authentication headers, updated 2026-10-10, but CC BY-NC 4.0 and its dataset card
  forbids "training, evaluation, enrichment" for commercial products without the maintainer's
  permission. Ask for permission; until then, do not use it.
- [MeAJOR](https://arxiv.org/html/2507.17978v2) (135,894 emails from Nazario, Nigerian fraud and
  TREC 2005 to 2007): processed and masked fields, no full headers, licence not stated.
- [University of Twente phishing validation set](https://research.utwente.nl/en/datasets/phishing-validation-emails-dataset/):
  2,000 English texts without headers; licence unclear.

**The gap no public corpus fills: Dutch, personal and business mail, with full headers.** We found
none. It has to come from section 3.2.

### 3.2 Our own data

| source | fidelity | handling |
|---|---|---|
| **capture mode** at delivery, for mailboxes whose owners consent (starting with our own) | perfect: the bytes, the delivery context and the lookups as they were at that moment | stays in an encrypted vault on our own hardware; never in the repository, a model hub or an external API ([06](06-security-privacy.md)) |
| labels for captured mail | from what the owner did later: moves to and from Junk, folder moves, replies, tag edits ([08](08-learning.md) section 1), plus an owner review of a sample | label noise is measured on the reviewed sample |
| the platform's spam traps and abuse reports, if they exist | real, fresh, full headers | security processing; treated like captured mail |
| L3 shadow events | features and decisions, not content | the learning tests of [07](07-evaluation.md) |
| **synthetic Dutch** fraud, invoices, government and parcel mail, and hard negatives | as realistic as we make it | always tagged `synthetic` and scored as its own slice; never the only evidence for a decision |

### 3.3 Splits

- **Split by time first:** the test split is always newer than anything in dev or train, the way
  production meets mail it has never seen.
- **Then by cluster:** near-duplicates (static-embedding fingerprints) and messages of one campaign
  or one sender domain never straddle splits, or bulk spam inflates every score.
- **Per slice:** language, protocol (IMAP / POP3), mailbox mode, synthetic or real, with or
  without recorded lookups. A result is reported per slice, never only on average.

## 4 · The blind test

- The sealed split lives in the lab data directory (`<lab_data>/sealed/`), outside the repository
  and outside the splits the loop reads. Only the harness reads it. Not built yet: a separate Unix
  user for the scorer. Today the agent and the harness run as the same user, so the split is blind
  by rule and by what the harness returns, not by file permissions.
- The agent never sees its messages, labels or per-message results. `run.py --sealed` returns
  aggregates only: cost per 1,000, false-positive and false-negative counts, cost per slice, and
  the λ sweep (counts per λ). Records and message ids go to `<lab_data>/sealed/runs/<tag>-<n>/`.
  Not built yet: comparing with the champion on the sealed split in the same query.
- Sealed queries are rationed (`sealed_queries_per_tag` in the cost table). The harness counts
  them per run tag in `<lab_data>/sealed/queries.log` before it runs and refuses past the ration,
  so the number of looks is known when a result is judged.
- One lapse, recorded: the first query (tag `oct26b`) ran before the harness held per-message
  output back, and printed the ids of the three sealed false positives. The ids were removed from
  the run directory and the log; nobody opened those messages, and nothing was changed after the
  query.
- The sealed split is refreshed from newly captured mail, which keeps it newer than everything the
  agent tuned on.
- A lab result is a candidate, not a release. Release goes through champion / challenger on platform
  replay, the L2 stack harness and shadow mode ([07](07-evaluation.md), [08](08-learning.md)).

## 5 · The score

**Cost per 1,000 messages** on the dev split: every (true class, action taken) pair has a cost in
the cost table (`lab/cost.toml`). Missing a fraudulent IBAN change and filing a real customer's
invoice in Junk are both expensive; a newsletter left in the inbox is cheap. The costs are product
decisions set by a person before the first run; the harness refuses to start while any is unset.

Three axes decide a keep (owner, 2026-10-26): **quality** (that cost), **latency** (wall time per
email through the real filter, with the model computing every vector) and **footprint** (CPU time
per email and peak memory of daemon plus sidecar). A run is kept when at least one axis is better
beyond noise and none is worse; a trade (better here, worse there) is never kept, only recorded.

How each axis is measured and judged, with the tolerances in the `[keep]` section of `lab/cost.toml`:

| axis | measurement | improve | worse |
|---|---|---|---|
| quality | paired bootstrap over primary dev messages of the cost difference against the champion | CI95 below 0 | any legitimate message newly in Junk (any slice), a slice significantly worse, CI95 above 0, or a point difference above the tolerance |
| latency | timing pass: champion and run, each with a no-cache sidecar and a daemon, get the same 200 dev messages interleaved; ratio of mean filter wall times, bootstrap CI95 | CI95 below 1 and ratio at most 0.95 | CI95 above 1, or ratio at least 1.05 |
| footprint | CPU per email (filter, daemon, sidecar), same pass; peak resident memory of sidecar plus daemon | CPU as latency, or memory at most 0.95 of the champion's, and neither worse | CPU as latency, or memory at least 1.03 of the champion's |

Gates, failing any one discards: the invariants of [12](12-interfaces.md) section 5, records
complete, data rules (every provider allowed to see every input it saw, section 6), decisions
computed live in the timing pass equal to those from the cached vectors, and quality not worse than
the tag's baseline (so a chain of "equal" steps cannot drift). If other processes take more than
0.15 of a core during the timing pass, latency and CPU are unmeasured and the run is repeated.
Results from different machines are never compared.

`pareto.tsv` records cost, latency, CPU and memory for every run that passed the gates, per
provider configuration, kept or not. That table answers "which classifier gives the best quality
for its latency and footprint"; the keep rule only answers "is this better than what we have".

## 6 · What the agent may change

In the experiment file, and only there:

- which embedder and which decision provider from the registry ([14](14-providers.md)), and at
  which precision;
- which deterministic signals are on, their weights in the combiner, and per-action thresholds;
- learner settings (decay, regularisation, k-thresholds within their allowed range);
- the simulated users' behaviour profiles, only when the run tag says it is a robustness run.

In the heads-training script: features, head architecture, training and calibration.

Never: the harness, the scorer, the datasets and splits, the cost table, the providers' data rules,
anything in `crates/`. A change that needs Rust (a new signal, a parser fix) goes into the run's
notes as a proposal; it reaches the code through the normal review with fixtures.

## 7 · The learning test in the lab

The week-one test of [07](07-evaluation.md) runs on simulated mailboxes: messages are delivered in
time order, simulated users react to them according to their labels (moving junk, rescuing mail,
replying), with delays, and only some of the time. Built as `lab/harness/learning.py` for mailbox
memory ([ADR-0018](decisions/0018-mailbox-memory-v0.md)): every train, calib and dev message in Date
order to its own mailbox through the real filter and daemon, owners acting through the real
`firstread feedback`, the combiner retrained with the `mailbox.*` inputs, dev scored against memory
off, plus a poisoning check (one mailbox's owner labels everything junk; no other mailbox's decision
may change). First results:
[measurements/2026-10-27-mailbox-memory.md](measurements/2026-10-27-mailbox-memory.md). How often
and how fast users react is an assumption, so learner changes must improve the cost under several
user profiles, not one. Enron's per-user folders give real filing habits to test the folder-habit
learner against.

## 8 · Status

Built and run on 2026-10-26: tag `oct26` (quality keep rule) and tag `oct26b` (the three-axis rule
of section 5), L2 on Dovecot 2.3.21 for the cases of [12](12-interfaces.md) section 7, one sealed
query. Results: [measurements/2026-10-26-lab-v0.md](measurements/2026-10-26-lab-v0.md),
[measurements/2026-10-26-lab-pareto-loop.md](measurements/2026-10-26-lab-pareto-loop.md),
[`lab/results/`](../lab/results/); decisions: [ADR-0017](decisions/0017-lab-v0-choices.md).
Reproduce: [`lab/README.md`](../lab/README.md).

Built: fetch (sha256-checked archives, pinned lore commits, pinned model revisions), prepare
(checked against `lab/data/`), render, the harness with the timing pass and the sealed-query
ration and log, the scorer, the hash lock, the sidecar (four embedders; torch, ONNX Runtime or
numpy; fp32 or int8; per-space cache), ONNX export with a parity check, the heads script, the loop
helpers, the L2 setup.

Built on 2026-10-27: the learning test of section 7 for mailbox memory, with mailboxes on a
simulated clock (Date order, owner delays), and hook D on Dovecot 2.3.21 (L2 case M).

Not built yet: recorded lookups (section 2), a sealed counterpart of the learning test, L3 shadow
beyond `firstreadd --shadow`, a separate Unix user for the sealed split and a champion comparison
inside a sealed query (section 4). The only within-source labelled data is English from 2002 to
2005.
