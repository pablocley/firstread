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
| keep if strictly better, else `git reset` | keep only if better **beyond noise** (paired bootstrap on quality, repeated runs on latency) and every gate passes |
| `results.tsv`, untracked | `results.tsv` and `pareto.tsv`, untracked |
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

- The sealed split lives outside the agent's workspace. Only the scorer process can read it.
- The agent never sees its messages, labels or per-message results. It receives one coarse answer
  per query: whether the candidate beats the current champion on the sealed split, and the
  rounded cost.
- Sealed queries are rationed (a fixed number per run tag, set in the cost table) and every query
  is logged, so the number of looks is known when a result is judged.
- The sealed split is refreshed from newly captured mail, which keeps it newer than everything the
  agent tuned on.
- A lab result is a candidate, not a release. Release goes through champion / challenger on platform
  replay, the L2 stack harness and shadow mode ([07](07-evaluation.md), [08](08-learning.md)).

## 5 · The score

**Cost per 1,000 messages** on the dev split: every (true class, action taken) pair has a cost in
the cost table (`lab/cost.toml`). Missing a fraudulent IBAN change and filing a real customer's
invoice in Junk are both expensive; a newsletter left in the inbox is cheap. The costs are product
decisions set by a person before the first run; the harness refuses to start while any is unset.

Hard gates. A candidate that fails any one is discarded, whatever its cost:

| gate | rule |
|---|---|
| hard negatives | no new false positive on the veto set |
| latency | p99 of the inline path within the budget, measured on the reference machine |
| calibration | expected calibration error per head within the limit |
| slices | no slice worse than the champion beyond its tolerance |
| memory | resident memory within the limit |
| data rules | every provider allowed to see every input it saw (section 6) |

Noise: quality differences count only if a paired bootstrap over dev messages puts the cost
difference below zero with 95% confidence; latency counts only outside the spread of repeated
baseline runs on the same machine. Results from different machines are never compared.

`pareto.tsv` records cost, p99 latency and memory for every run that passed the gates, per
provider and precision. That table answers "which classifier gives the best quality for its
latency"; the keep rule only answers "is this better than what we have".

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
replying), with delays, and only some of the time. How often and how fast users react is an
assumption, so learner changes must improve the cost under several user profiles, not one. Enron's
per-user folders give real filing habits to test the folder-habit learner against.

## 8 · Status

Designed, not built. [`lab/build-prompt.txt`](../lab/build-prompt.txt) is the goal prompt for the
coding agent that builds it; [`lab/program.md`](../lab/program.md) is what the research agent reads
once it exists.
