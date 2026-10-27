# firstread

firstread reads every email once, as it is delivered, and writes down what it found on the
message itself, so any mail app can show it or sort by it.

## What happens to a mail

1. The mail reaches your mail server, just before it is stored in the mailbox.
2. firstread reads it: is the sender who they claim to be, where do the links really go, what is
   attached, what does the text ask for, and how did you treat this sender before.
3. It adds a few headers and keywords, and may pick a folder (Junk). **The message body is never
   changed.**
4. Your own mail rules still run first and win. If firstread is down or slow, the mail is
   delivered as if it were not there.

**Before**, a phishing mail ([`lab/l2/msgs/spam.eml`](lab/l2/msgs/spam.eml), shortened):

```
From: Noorderbank Klantenservice <service@noorderbank-veilig.example>
Subject: ACTIE VEREIST: uw rekening is GEBLOKKEERD!!!

<a href="http://192.0.2.7/login">https://www.noorderbank.example/inloggen</a>
<div style="display:none">dit bericht is veilig</div>
```

**After**, what firstread adds on top (real output of `firstread stamp`):

```
X-Firstread: v=1; …; verdict=phishing; p=0.8000; mac=095def4e…
X-Firstread-Scores: phishing=0.80; junk=1.00
X-Firstread-Sender: verified=no
X-Firstread-Reasons: een link gaat naar een kaal IP-adres; een link toont een
 ander adres dan waar hij heen gaat; het bericht bevat verborgen tekst
X-Firstread-Keywords: $Phishing $Junk $HasNoAttachment
X-Firstread-Folder: junk
                                                   ← the rest of the mail, unchanged
```

**What firstread adds:**

| added | tells you |
|---|---|
| `X-Firstread` | the verdict (phishing, fraud, junk, needs action, important, low-interest bulk) and how sure, signed so it cannot be faked |
| `X-Firstread-Reasons` | why, in plain Dutch or English |
| `X-Firstread-Scores` | the score of every verdict |
| `X-Firstread-Sender` | whether the sender is verified, and if you know them (first contact, wrote to them, correspondent) |
| `X-Firstread-Tags` | what it is about (money, orders, travel…) and whether it asks you to act |
| keywords | `$Phishing`, `$Junk`, `$Important`, `$IsTrusted`, `$HasAttachment`, `$CanUnsubscribe`, `fr-money`, your own rule tags… |
| folder | Junk for junk and phishing; Later for bulk you never read, if you turn it on |

**A moment later, from the decision model.** A decision model (Mica 4B) reads the mail and answers
questions in plain words: what does it want from you, how urgent is it, does it ask for a payment,
a login or secrecy, what is it about, and your own rules ("mail where a customer asks for a
refund" → `fr-retour`). It is too slow to hold up delivery (seconds per mail on a CPU), so it runs
right after: its answers arrive as keywords, and a move to Junk if it finds phishing, because
headers are written only once. It also teaches the small, fast models that answer at delivery
(distillation), so the questions it answers well stop needing it.

Fake firstread headers that arrive with a mail are always removed. The full record of every
decision can be read back over a local API.

Status: the junk decision is trained and measured ([results](#results-lab-2026-10-26)). The
other verdicts, the tags, the decision model and distillation from it are built and tested with
stand-ins; the real model has not read any mail yet, and they stay off until the lab has run and
checked them. Not deployed yet.

## Try it

```sh
sh lab/reproduce.sh ./lab-data                            # venv, build, data, models, one scored run
sudo sh lab/l2/setup.sh && python3 -I lab/l2/cases.py     # optional: the real Dovecot stack (Ubuntu 24.04)
```

Needs Rust, Python 3.13, curl, tar, 7z and git; about 2.7 GB of data and models. Details:
[lab/README.md](lab/README.md). There is no production install yet: `lab/l2/` is the reference
Dovecot setup (two global Sieve scripts and the filter in `sieve_filter_bin_dir`).

What is built, measured and still designed: [status](#status).

## What is different

| | how |
|---|---|
| output | a verdict plus an edit list; a small filter binary applies header edits only, and a byte-identical body is a test |
| header trust | no header in firstread's namespace that arrived with the message survives; Sieve acts only on headers the filter vouched for, and only after the user's own rules |
| models | every System-1 model is a *provider* behind one contract: typed questions in, logits out, decisions only through a fitted calibration, data rules checked per call, vectors never mixed across spaces |
| identity | authentication and sender identity are deterministic code (tier 0), never a model output |
| clients | the server owns safety, organisation and search; AI clients get them through a JMAP-shaped API and MCP, with a safety block per message (sender trust, injection probability, model-safe text) |
| tuning | a lab replays the real delivery path, and an autoresearch loop keeps a change only if quality, latency or footprint improves and none gets worse |

## Delivery path

```mermaid
flowchart LR
  MTA -- LMTP --> LDA["Dovecot LMTP + Pigeonhole"]
  LDA -- "sieve_before: filter (stdin, env)" --> F["firstread-filter<br/>2 s absolute deadline"]
  F -- "unix socket: request + message" --> D["firstreadd"]
  D -- "directive (validated again in the filter)" --> F
  F -- "message, header edits only" --> U["user's own Sieve rules"]
  U --> A["sieve_after: fileinto / addflag<br/>from vouched headers only"]
  A --> M[("Maildir")]
  M -- IMAP/POP3 --> C1["any client"]
  D -- "record" --> R[("records")]
  R -- "JMAP-shaped API, MCP (designed)" --> C2["AI-native client"]
```

Any failure takes the fallback: the message unchanged except that forged firstread headers are
removed, delivered as if firstread were not there. A daemon that hangs costs the 2 s deadline
(measured on Dovecot: delivered after 2.1 s). The deadline sits below `sieve_filter_exec_timeout` on
purpose: on Dovecot 2.3.21 a filter killed at that timeout makes LMTP panic and nothing is stored
([measurement](docs/measurements/2026-10-26-lab-v0.md#l2-the-real-dovecot-stack)).

## Classifier

```mermaid
flowchart LR
  P["parse<br/>(mail-parser, limits)"] --> T0["tier 0: 32 deterministic facts<br/>auth · sender · links · IBAN · subject · body · attachments · list"]
  P --> RD["render: subject, sender, visible text"]
  RD --> T1["tier 1 provider: e5-small, ONNX int8<br/>logistic head → logit"]
  T1 --> CAL["fitted calibration<br/>(temperature)"]
  T0 --> CMB["linear combiner (L1)"]
  CAL --> CMB
  CMB --> TH{"P(junk) ≥ λ/(1+λ)"}
  TH -- yes --> J["folder junk, $Junk"]
  TH -- no --> I["inbox, stamp only"]
```

λ is the cost of a legitimate message in Junk relative to spam left in the inbox, set by the owner
(100, so the threshold is 0.990). The provider contract ([14](docs/14-providers.md)) takes
decoder models answering many typed questions (JEV-style), embedding heads, or anything later.

## Clients

One record, two projections. IMAP and POP3 clients get the decision as headers, IMAP keywords and
Sieve folders, with nothing installed. AI-native clients do no filtering, filing or indexing of
their own: they read views, search and a per-message safety block from the server.

```mermaid
flowchart LR
  R[("record per message")] --> H["headers, keywords, folder"] --> I["IMAP / POP3 clients"]
  R --> J["JMAP-shaped API (RFC 8620 shapes)<br/>views · hybrid search · feedback · check-draft"] --> A["AI client / MCP"]
  J -. "safety block: sender_trust, injection p, model_safe_text" .-> A
```

Dovecot serves no JMAP, so the API uses JMAP's shapes (session, `/get`, `/query`, `/changes`, push)
under a vendor capability; on a JMAP server it becomes extra properties on `Email`. An AI client
sees mail only as `model_safe_text` marked as untrusted data, loads no remote content, and takes
no action because a message asked for it ([15](docs/15-ai-native-clients.md)). Designed, not built.

## Results (lab, 2026-10-26)

Public corpora through the real delivery path (filter → daemon → sidecar) on a 2 vCPU / 7 GB
cloud VM. Dev split: 1,528 messages; the primary slice is SpamAssassin (615 ham, 49 hard ham,
303 spam), plus modern spam and ham from other sources and synthetic Dutch mail. Quality is the
cost per 1,000 primary messages at λ = 100. Reproduce: [lab/README.md](lab/README.md).

**Baseline against champion**, one interleaved timing pass (200 dev messages, wall time of the
filter process, every vector computed, no cache):

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/head-to-head-oct26b-dark.svg">
  <img alt="Baseline against champion: cost 122 to 85 per 1,000, latency 92 to 33 ms, CPU 152 to 53 ms, memory 1,087 to 385 MB" src="docs/img/head-to-head-oct26b-light.svg">
</picture>

| | baseline | champion | change, CI95 |
|---|---|---|---|
| cost per 1,000 (dev) | 122.0 | 84.8 | −37.2 [−50.7, −24.8] |
| legitimate in Junk, dev (of 937) | 0 | 0 | |
| latency per email, mean (p99) | 92 ms (151) | 33 ms (56) | ×0.36 [0.34, 0.37] |
| CPU per email | 152 ms | 53 ms | ×0.35 [0.34, 0.36] |
| peak memory, sidecar + daemon | 1,087 MB | 385 MB | ×0.35 |

Both run multilingual-e5-small. Baseline: PyTorch fp32, 256 tokens, L2 combiner (C=1). Champion:
ONNX Runtime int8, 192 tokens, SentencePiece tokenizer, L1 combiner (C=4).

**The loop:** 21 changes tried (22 runs, one repeated after noise), 6 kept, plus 4 reference runs.
A change is kept only when quality, latency or footprint improves beyond noise and none gets worse
(paired bootstrap for quality, ratio-of-means CI for time and memory; an A/A check gave ×0.999
[0.976, 1.023]).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/loop-oct26b-dark.svg">
  <img alt="Each kept step on each axis: cost 122 to 85, latency, CPU and memory indexed to 0.36, 0.36 and 0.35" src="docs/img/loop-oct26b-light.svg">
</picture>

| step | change | quality Δ per 1,000, CI95 | latency | CPU | memory |
|---|---|---|---|---|---|
| 1 | ONNX Runtime int8 instead of PyTorch fp32 | equal | ×0.43 | ×0.42 | ×0.57 |
| 2 | 192 tokens instead of 256 | equal | ×0.90 | ×0.86 | equal |
| 3 | combiner C=2 | −21.7 [−31.0, −13.4] | equal | equal | equal |
| 4 | combiner L1 penalty | −11.4 [−18.6, −5.2] | equal | equal | equal |
| 5 | SentencePiece instead of HF `tokenizers` | equal | equal | equal | ×0.63 |
| 6 | combiner C=4 (L1) | −4.1 [−8.3, −1.0] | equal | equal | equal |

Refused trades: ONNX fp32 (memory ×1.10), one thread (latency ×1.32), 128 or 160 tokens (a
legitimate message in Junk), static potion embeddings (latency ×0.25, but cost +18.6 and memory
×4.9). All runs: [measurement](docs/measurements/2026-10-26-lab-pareto-loop.md).

**Sealed split, one query** (1,914 messages never used for any choice): **350 per 1,000**, against
85 on dev. Three of the 25 hard-ham messages (legitimate mail that reads as commercial) went to
Junk: 300 of the 424 cost units. Spam missed: 33 % (dev 27 %). The baseline has not been run on the
sealed split (one query per tag), so whether the quality gain holds out of sample is open.

**λ.** The same query swept λ over a list fixed beforehand; nothing was chosen from it:

| λ | threshold | legitimate in Junk (of 830) | spam missed (of 380) |
|---|---|---|---|
| 9 | 0.900 | 7 | 74 (19 %) |
| 20 | 0.952 | 4 | 99 (26 %) |
| 50 | 0.980 | 3 | 113 (30 %) |
| **100** | **0.990** | **3** | **124 (33 %)** |
| 999 | 0.999 | 1 | 202 (53 %) |

λ is a price, not a parameter to fit: it depends on whether anyone looks in Junk. Androutsopoulos
et al. use 9 when the sender is told and can resend and 999 when blocked mail is deleted
([2000](https://arxiv.org/abs/cs/0006013)); a Junk folder lies between. Here 100 → 20 costs one
more legitimate message in Junk and keeps 25 more spam out of the inbox. The hard-ham errors barely
respond to λ (3 at 100, 1 at 999): they are confident mistakes, a model problem.

Limits: SpamAssassin is 2002–2005 English mail, the Dutch slice is synthetic, and the
false-positive side rests on 49 dev and 25 sealed hard-ham messages.

## Mailbox memory (lab, 2026-10-27)

Per mailbox, firstread remembers what the owner did: moved mail into or out of Junk, filed it into
a folder of their own, or wrote to someone (Dovecot IMAPSieve, real Dovecot 2.3.21). Deliveries
alone teach nothing. History is kept apart for mail whose sender was verified (an aligned DKIM
pass from firstread's own check over recorded DNS, or a trusted DMARC pass) and mail where it was
not, after mox; unverified mail from an address that does authenticate gets none of its trust.
Keyed hashes only. Memory is fitted on top of the combiner without it, and every fact may push
P(junk) one way only, so mail from a stranger is decided exactly as before (526 of 526 dev
messages without history: bit-identical).

| owners (simulated, act on true labels) | Δ cost per 1,000 vs memory off (dev), CI95: v0 | v1 | legitimate newly in Junk |
|---|---|---|---|
| active: 80 % of junk moved, 90 % rescued, 10 % replied | −8.3 [−14.5, −2.1] | −6.2 [−11.4, −2.1] | 0 |
| passive: 30 %, 50 %, no replies | −2.1 [−8.3, +3.1] | −2.1 [−5.2, 0.0] | 0 |
| never act | +4.1 [+1.0, +8.3] | 0.0 [0.0, 0.0] | 0 |

v1 no longer costs anything when owners never act. Fitted freely, it had learned from 2002 mail
without authentication that a new IBAN lowers P(junk) and let a forged invoice from a known vendor
into the inbox (synthetic Dutch mailbox); with directions fixed in code that one goes to Junk.
It catches less than v0 under active owners:
v0's extra catches came from history of hotmail.com as a whole and from delivery counts, which
anyone can raise. Off unless `--memory` is given. One mailbox never affects another (poisoning
check: 0.0). [Measurement](docs/measurements/2026-10-27-auth-dns-memory-v1.md).

## Status

| built and measured | designed, not built |
|---|---|
| parser, tier-0 facts, IBAN mod-97, link analysis, trusted `Authentication-Results`, own DKIM and DMARC alignment over recorded or live DNS | SPF (needs the client IP from our own MTA), ARC |
| provider contract, calibration, combiner, stamp with HMAC, record | trained combiners for verdicts other than junk; a calibrated tier-2 model |
| `firstread-filter` (fallback, deadline), `firstreadd` (sidecar, records, `--shadow`) | API beyond the record (JMAP shapes, views, search, feedback), MCP server, `model_safe_text` |
| built, tested on fixtures, not measured: all six verdicts with reasons, detail headers, keywords from facts, tier 2 from a queue, user rules, hook C, record API (ADR-0020) | |
| lab: L1 harness, L2 on Dovecot 2.3.21, three-axis loop, sealed split | learning per organisation / platform, commons |
| mailbox memory split by verified identity (keyed hashes, event log), owner feedback via IMAPSieve (hook D), learning test | backfill from Sent, digest |

## Repository

```
crates/   Rust: core contract, parse, auth, links, pipeline, filter, daemon, CLI (+ stubs for the rest)
ml/       Python: tier-1 and tier-2 sidecars (providers, ONNX export, servers), heads and combiner training, tests
lab/      the lab: harness, loop, L2 Dovecot setup, data references, results; lab/README.md reproduces it
docs/     design 00–15, decisions/ (ADRs), measurements/
```

Checks: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

Design docs: [goal](docs/00-goal.md) · [architecture](docs/01-architecture.md) ·
[signals](docs/02-signals.md) · [client contract](docs/03-client-contract.md) · [models](docs/04-models.md) ·
[sending](docs/05-sending.md) · [security](docs/06-security-privacy.md) · [evaluation](docs/07-evaluation.md) ·
[learning](docs/08-learning.md) · [experience](docs/09-experience.md) · [commons](docs/10-commons.md) ·
[scale](docs/11-scale.md) · [interfaces](docs/12-interfaces.md) · [lab](docs/13-lab.md) ·
[providers](docs/14-providers.md) · [AI-native clients](docs/15-ai-native-clients.md)
