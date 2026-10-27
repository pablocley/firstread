# 04 · Models

## What "JEV-like" means

JEV is a family of *typed-decision* models, also called System 1 models. Instead of generating
text, the model takes a **state** (here: an email) and a **typed question**, and returns a
calibrated probability distribution in one forward pass:

| type | question | returns |
|---|---|---|
| `noul` | is this statement true? | P(false), P(true) |
| `choice` | which of these options? | one probability per option |
| `score` | where on this ordered scale? | a distribution over the levels, plus the expected value |

The idea comes from TypeSafe AI's hosted, closed Jev. The open models people mean by "JEV" are
independent students of it, for example `autotrust/JEV-9B` (Qwen3.5-9B backbone plus a 40.2M-parameter
decision block; a linear head over the final hidden state at a verdict token; Apache-2.0). Its card
reports a median ≈ 90 ms per decision on one B200 GPU, an English-only training corpus, and
multilingual behaviour "not systematically measured". Source: [autotrust/JEV-9B model card](https://huggingface.co/autotrust/JEV-9B).

Why the shape fits mail: every question firstread asks is one of these three types ("is this asking
for a payment?", "which category?", "how urgent, 0–5?"), probabilities let us set a separate
threshold per action, and new questions need no retraining when the model generalises.

## The open landscape, as checked on 2026-10-26

| model | size / runtime | languages | license | relevance to firstread |
|---|---|---|---|---|
| [autotrust/JEV-9B](https://huggingface.co/autotrust/JEV-9B) | 9B, GPU (18 GB) | English corpus | Apache-2.0 | strong teacher; too heavy for per-message CPU use |
| [autotrust/JEV-27B](https://huggingface.co/autotrust/JEV-27B), JEV-35B | 27B / 35B-A3B, GPU | English corpus | Apache-2.0 | best teacher for offline distillation |
| [chaoliangUNSW/Jev-Style-0.8B-Decision-v3](https://huggingface.co/chaoliangUNSW/Jev-Style-0.8B-Decision-v3) | 0.8B (Qwen3.5-0.8B), 1.5 GB bf16, 0.53 GB Q4 GGUF | 51 evaluated; 14 locales trained; **Dutch held out**: 82% vs English 93% on 20-way MASSIVE intent (100 rows each, from its published data) | Apache-2.0 | tier-2 candidate on CPU; Dutch needs fine-tuning |
| [com-kotobalabs/open-jev-deberta-v3-large](https://huggingface.co/com-kotobalabs/open-jev-deberta-v3-large) | encoder, reads state and all questions in one pass | English | Apache-2.0 | the right *architecture* for a multi-question encoder; wrong language; card reports OOD accuracy 0.69 vs 0.85 in-domain |
| [sky7350/Mica-v0.5-4B](https://huggingface.co/sky7350/Mica-v0.5-4B) | 4B (Qwen3.5-4B), INT8 CUDA runtime or llama.cpp GGUF (Q8_0 4.48 GB for CPU) | English, Korean, Chinese "+ more" on the card; no Dutch number | Apache-2.0 | **teacher and tier-2 candidate**: separated all four labelled questions on a 24-mail lab sample, Jev 0.8B did not; 37.6 s per mail through transformers BF16 on our CPU, llama.cpp not yet measured ([bake-off](measurements/2026-10-27-decision-model-bakeoff.md)) |
| [samatv256/mini-Jev](https://huggingface.co/samatv256/mini-Jev) | 0.6B | — | Apache-2.0 | tool selection; card reports 34% on general typed decisions; not for us |
| [JackKozmo29/mailguard-jev-style-1.5b](https://huggingface.co/JackKozmo29/mailguard-jev-style-1.5b) | 1.5B, generates JSON (decoding, not a decision head) | English | Apache-2.0 | mail-specific, but its comparisons with Jev are self-reported and unverifiable; generative; skip |

## What we measured

Full numbers and scripts: [measurements/2026-10-26-cpu-baseline.md](measurements/2026-10-26-cpu-baseline.md).
Hardware was a 2-vCPU sandbox with eager PyTorch, so the numbers order the options; they are not
production latencies.

**The 0.8B JEV-style model, zero-shot, on a Dutch CEO-fraud email** (fake "Maarten" from a Gmail
address, Reply-To at another free-mail provider, urgent payment, changed IBAN, "bespreek dit niet
met anderen"):

| question | P(true) or top answer |
|---|---|
| asks for a payment or changed bank details | **0.97** (correct) |
| sender is impersonating someone | 0.41 (**missed**) |
| pressures to keep it secret / skip checks | 0.49 (**missed**, despite the explicit sentence) |
| what kind of email is this | "transactional" 0.61 (**wrong**, "scam" was an option) |

And ≈ 2.1 s per question, ≈ 13 s for six questions about the same message.

Conclusions, in order of importance:

1. **Identity is not a language problem.** The model cannot see that "Maarten" is not Maarten.
   The address, Reply-To, authentication and sender relationship are deterministic tier-0 signals,
   and they carry identity. The model carries meaning (payment request, pressure, secrecy).
2. **Zero-shot is a starting point, not a verdict.** Off-the-shelf typed-decision models are not
   good enough on Dutch mail to drive actions. They must be fine-tuned and measured on Dutch.
3. **Per-question decoder passes do not fit the delivery path.** One read per question is too
   expensive on CPU. Read the message once, answer many questions.

### The first lab loop (2026-10-26)

Full numbers: [measurements/2026-10-26-lab-v0.md](measurements/2026-10-26-lab-v0.md); decisions:
[ADR-0017](decisions/0017-lab-v0-choices.md). Through the real filter and daemon, scored by cost
(a legitimate message in Junk costs 100, spam in the inbox 1) on the SpamAssassin corpus, the only
within-source labelled data available (English, 2002 to 2005):

| configuration | cost / 1,000 | spam caught | legitimate in Junk |
|---|---|---|---|
| tier 0 only (32 deterministic facts) | 414.7 | 102 / 303 | 2 |
| tier 0 + potion head (after the IBAN fix) | 134.4 | 173 / 303 | 0 |
| **tier 0 + multilingual-e5-small head (v0 choice)** | **122.0** | **185 / 303** | **0** |
| tier 0 + mmBERT-small head | 116.9, not different beyond noise | 190 / 303 | 0 |

What it settles: an embedding head on top of the deterministic facts more than halves the cost;
e5-small beats potion beyond noise; the cost-derived threshold (0.990) is kept over a dev-tuned
one. The second loop, with the owner's three-axis rule (keep only if quality, latency or footprint
improves and none gets worse), then moved the same model to ONNX Runtime int8 at 192 tokens with a
SentencePiece tokenizer at equal quality (latency ×0.36, CPU ×0.35, memory ×0.35), and an L1
combiner cut dev cost from 122 to 85 per 1,000. On the one sealed query the champion scored 350
per 1,000, three of 25 hard-ham messages in Junk; the starting point is not scored there yet
([measurements/2026-10-26-lab-pareto-loop.md](measurements/2026-10-26-lab-pareto-loop.md)).
What it does not settle: anything about Dutch mail, phishing or fraud, because no labelled data for
them exists here yet. A plain bag-of-words n-gram head ranks this old English mail better
than every embedder (AUC 0.993 against 0.987 for e5) and is the baseline to beat on Dutch data.

## The plan: two forms of System 1

### Tier 1: one embedding, many calibrated heads

1. Encode each unique content once (subject, sender display name, visible body, link and
   attachment summary) with a multilingual embedder; copies of bulk mail reuse the cached vector
   ([11-scale.md](11-scale.md)).
2. Each fixed decision (the axes in [02-signals.md](02-signals.md): sender kind, topics, intent,
   risks, urgency) is a small head on that embedding (logistic regression or a 1-hidden-layer MLP)
   with the same `noul` / `choice` / `score` output contract as tier 2, temperature-calibrated per head.
3. Per mailbox, the global head's logit is adjusted by a personal residual head and by the votes of
   the mailbox's labelled exemplars; reputation counters and deterministic signals join in the
   combiner. This is where self-learning happens ([08-learning.md](08-learning.md)): the encoder
   stays fixed, the cheap parts on top of it learn continuously.
4. If frozen-embedding heads underperform on the evaluation set, fine-tune the encoder itself as
   a multi-task model (all heads trained jointly), still one forward pass per unique content.

Embedder candidates, all MIT-licensed and ungated:

| model | dims | measured, eager fp32, 2 vCPU, ~512 tokens | note |
|---|---|---|---|
| [intfloat/multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small) | 384 | **177 ms** | cheapest contextual option; cosine similarities compressed into a narrow band (needs heads, not raw thresholds) |
| [microsoft/harrier-oss-v1-270m](https://huggingface.co/microsoft/harrier-oss-v1-270m) | 640 | **778 ms** (2,253 ms if loaded in bf16 on this CPU) | 94 languages including Dutch, 32K context, reported 66.5 on Multilingual MTEB v2; better separation in our tiny check |
| [jhu-clsp/mmBERT-small](https://huggingface.co/jhu-clsp/mmBERT-small) | 384 | **291 ms** at 256 tokens, **398 ms** at 512 | encoder to fine-tune if frozen heads are not enough; 1,800+ languages |
| [minishlab/potion-multilingual-128M](https://huggingface.co/minishlab/potion-multilingual-128M) | 256 | **1.3 ms** | static embeddings; tier 0 near-duplicate and campaign fingerprints, not semantics |

Ruled out: `jina-embeddings-v5-text-small` (strong, but CC BY-NC 4.0, non-commercial), 
`google/embeddinggemma-300m` (gated, Gemma license; legal review cost with no measured gain yet),
English-only phishing classifiers such as the DistilBERT fine-tunes that top the Hub's
"phishing" search (English-only training; at most a feature or a teacher signal).

### Tier 2: the full typed-decision model

Asynchronous. Runs only for:

- tier-1 decisions inside an uncertainty band (confidence-gated escalation),
- natural-language rules users write ("tag mails where a customer asks for a refund as Retour"),
- confirming a suspected campaign once, on one representative copy.

The model: **Mica v0.5 4B**, chosen over the 0.8B JEV-style model in a quick
[bake-off](measurements/2026-10-27-decision-model-bakeoff.md). Built
([ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)): `ml/sidecar/decision_server.py` puts
Mica's own server (llama.cpp with the Q8_0 GGUF on CPU) behind the sidecar protocol (it declares `*`
and reads each question's text, at most 16 questions per read), and `firstreadd --tier2` asks it after
delivery from a bounded in-memory queue. Before it acts on mail: its llama.cpp runtime measured on the
production CPU, a calibration fitted on the lab's dev split, and a Dutch evaluation. The output
contract is identical to tier 1, so swapping is a config change.

### Rules get cheaper the more they are used

A user rule starts life in tier 2 (no training needed). Every time the user removes or adds that
tag by hand, it becomes a label. When a rule has enough labels and its head beats tier 2 on
held-out data, it is promoted to a tier-1 head and stops costing a decision-model call.

## Distillation

Built ([ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)): `ml/distill/teach.py` has a decision
model behind the sidecar protocol answer the whole question catalogue for lab messages, resumably,
and checks it against the lab's human labels (`agreement.json`); `ml/heads/train.py` with `[heads]
teacher` distils heads for the questions the lab has no labels for (noul by confidence-weighted
P(true) ≥ 0.5, choice and score as matrix heads), calibrated against the teacher. The teacher is
Mica 4B (the bake-off); not run yet, and its agreement decides what is kept.

| ingredient | what | caution |
|---|---|---|
| teacher | JEV-27B / JEV-35B (Apache-2.0) on a GPU, offline, answering the decision catalogue for each training message | English-centric; validate the teacher on Dutch against human labels before trusting its distributions |
| behaviour labels | users moving mail to / from Junk (hook D), `$NotJunk`, abuse reports, operator-confirmed campaigns | biased towards what users notice; use for evaluation first |
| deterministic labels | DMARC failures, known-bad URLs, confirmed campaign membership | label leakage: do not train a head to predict a signal it can read directly |
| general typed-decision data | [SargeDev/jev-distill-corpus-v3](https://huggingface.co/datasets/SargeDev/jev-distill-corpus-v3) (Apache-2.0, English) | general skill only; not mail, not Dutch |
| public mail corpora | only after checking each corpus's license individually | many are research-only |

Base models (encoder, tier-2 model) are not trained on customer mail unless a separate lawful basis
and consent exist ([06-security-privacy.md](06-security-privacy.md)); continuous learning on
customer mail happens only in the scoped learners of [08-learning.md](08-learning.md).

Every student is calibrated (per-head temperature on a held-out split), exported to ONNX,
quantised, and accepted only if the quantised model agrees with full precision on a fixed parity
set and meets the latency target on production hardware.

## Runtime

- Every model below is a **provider** behind one contract ([14 · Providers](14-providers.md)):
  deciders answer many typed questions per call and return logits, calibration per (release,
  question) turns them into decisions, embedders tag vectors with their space. Which provider wins
  is decided in the lab ([13 · Lab](13-lab.md)), not by its model card.
- Inference in-process in Rust with the [`ort`](https://docs.rs/crate/ort/latest) crate (wraps
  ONNX Runtime 1.28; still `2.0.0-rc.13`, so pin the exact version), tokenisation with the Rust
  `tokenizers` crate. `ort` is the ONNX path of Hugging Face's Text Embeddings Inference and of
  fastembed-rs (both listed in its README).
- Tier 2 runs as a separate local service (llama.cpp server for GGUF, or vLLM on a GPU box)
  that the daemon calls over HTTP with a queue in front. It never runs in the delivery path.
- Every stamp records the model release and the learner snapshot that produced it.

## Why not Rspamd's GPT plugin with a local model

Rspamd's GPT module can call a local LLM through Ollama and returns a spam probability
([docs](https://docs.rspamd.com/modules/gpt/)). It is a per-message generative call aimed at
spam / ham, without per-mailbox memory, typed multi-question output or calibration. Useful as one
more signal if already enabled; not the core of firstread.
