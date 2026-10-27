# 2026-10-26 · CPU baseline in a sandbox

Purpose: order the model options by cost and sanity-check one JEV-style model on Dutch mail
before designing around it. **Not production latencies.**

## Environment

- 2 vCPU, Intel Xeon @ 2.80 GHz, 7 GB RAM, Linux
- Python 3.13, torch 2.14.1+cpu, transformers 5.20.2, eager mode, float32, `torch.set_num_threads(2)`
- No ONNX Runtime, no quantisation, no batching
- The 0.8B Qwen3.5-based model ran with transformers' reference kernels for its linear-attention
  layers (`causal_conv1d` and `flash-linear-attention` not installed; transformers warns this is
  "much slower")
- Model files for the 0.8B model verified against its published sha256 manifest

Scripts: `ml/bench/bench_jev08.py` (removed with the model after the [bake-off](2026-10-27-decision-model-bakeoff.md); in git at 2c029ae), [`ml/bench/bench_encoders.py`](../../ml/bench/bench_encoders.py).
Medians over 6–50 warm runs. The script loads harrier with its default dtype (bfloat16), which is
what `bench_encoders_result.json` records; the float32 figure below came from re-running the same
encode with `model_kwargs={"dtype": torch.float32}` (8 warm runs).

## Latency

| model | input | median |
|---|---|---|
| chaoliangUNSW/Jev-Style-0.8B-Decision-v3, one `noul` question | 142–237 tokens | **2,059 ms** (p90 2,159 ms) |
| same, six questions on one message (`decide_many`, torch path) | 237 tokens | **13,134 ms** |
| same, model load | | 7.6 s |
| jhu-clsp/mmBERT-small, encoder forward | 256 tokens | **291 ms** |
| jhu-clsp/mmBERT-small, encoder forward | 512 tokens | **398 ms** |
| intfloat/multilingual-e5-small, embedding | 512 tokens (truncated) | **177 ms** |
| microsoft/harrier-oss-v1-270m, embedding, float32 | 512 tokens (truncated from 580) | **778 ms** |
| same, default load in bfloat16 on this CPU | 512 tokens | 2,253 ms |
| minishlab/potion-multilingual-128M, static embedding | ~580 tokens of text | **1.3 ms** |

## Zero-shot decisions, 0.8B JEV-style model

Three messages: a Dutch CEO-fraud mail (display name "Maarten de Vries", address at a free-mail
provider, Reply-To at another, urgent payment of EUR 18,450, "Het IBAN is gewijzigd", "bespreek
dit niet met anderen, het is vertrouwelijk"), a Dutch energy invoice notice with automatic debit,
and an English shop newsletter.

| question | CEO fraud (nl) | invoice (nl) | newsletter (en) |
|---|---|---|---|
| `noul` asks for a payment or changed bank details | **0.97** | 0.12 | 0.51 |
| `noul` sender impersonates someone | 0.41 | 0.29 | 0.42 |
| `choice` kind of email (personal, transactional, marketing, notification, security, scam) | transactional 0.61 | transactional 0.72 | marketing 0.76 |
| `score` urgency 0–5 (top level, its probability) | 5 (0.41) | 0 (0.76) | 2 (0.26) |
| `noul` recipient expected to act | 0.60 | 0.38 | 0.66 |
| `noul` pressure to keep it secret or skip checks | 0.49 | 0.09 | 0.07 |

Read: the payment request is caught; impersonation and the explicit secrecy demand are not, and
the scam is filed as "transactional". The newsletter's 0.51 on "asks for a payment" is a coin flip.
Three messages are an illustration, not an evaluation.

## Embedding sanity check (5 short sentences, cosine similarity)

| pair | e5-small | harrier-270m | potion-128M |
|---|---|---|---|
| Dutch invoice ~ English invoice (same meaning) | 0.907 | 0.844 | 0.616 |
| Dutch invoice ~ Dutch newsletter (different) | 0.813 | 0.620 | 0.233 |
| Dutch CEO fraud ~ English CEO fraud (same meaning) | 0.917 | 0.741 | 0.611 |
| Dutch CEO fraud ~ Dutch invoice (different) | 0.874 | 0.700 | 0.275 |

e5-small packs everything into a narrow high band, so raw cosine thresholds are useless and
trained heads are required; harrier and potion separate more. Five sentences prove nothing about
quality; the Dutch evaluation set decides.

## Still to measure

- ONNX Runtime with int8 quantisation for the tier-1 encoders, on production CPUs
- the 0.8B model through its GGUF runtime with all questions in one call
- JEV-9B on a GPU, if one is available
- end-to-end delivery latency with the Sieve filter in place
