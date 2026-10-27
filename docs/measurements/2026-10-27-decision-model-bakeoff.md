# Decision-model bake-off, quick (2026-10-27)

Which typed-decision model to use as teacher and tier 2, by cheap signals only: separation (AUC) on
the four questions the lab has labels for, and wall time per mail. A ranking, not an evaluation
([07](../07-evaluation.md)).

## Setup

| | |
|---|---|
| hardware | Intel Xeon Gold 6240 @ 2.60GHz, 16 cores visible, shared host, `nice`; Jev 8 threads, Mica 12 threads |
| runtime | PyTorch 2.14.1+cpu, transformers 5.20.2 |
| Jev | `chaoliangUNSW/Jev-Style-0.8B-Decision-v3` @ b023d1f9, fp32, its own `JevStyleDecision` (manifest verified); score = logit(yes) − logit(no) |
| Mica | `sky7350/Mica-v0.5-4B` @ 5ea7aafe, BF16 safetensors through transformers (not its INT8 CUDA or llama.cpp runtime), prompt from its own runtime (`mica.native.prompt_for`, akivet/Mica @ 5529ffa1); score = logit("Yes") − logit("No") at the last position |
| baseline | the lab champion's tier-1 e5 head (`head.is_spam.logit` of `runs/reproduce/dev.records.jsonl`) |
| questions | `is_spam`, `risk_phishing`, `risk_fraud`, `asks_payment_or_bank_change`, worded as in `crates/firstread-stamp/data/questions.json`, one call per question, uncalibrated |
| labels | `ml/heads/labels.py`; phishing, fraud and payment labels come from the synthetic Dutch slice only |
| sample | dev split, seed 20261027, 3 per group (24 mails): synthetic phishing, CEO and IBAN fraud, legitimate invoices and reminders, other synthetic legitimate, synthetic spam, SpamAssassin ham, hard ham, spam. Jev also ran on 8 per group (64) |
| script | `ml/bench/bakeoff.py` (`sample`, `mica`, `report`); the `jev` path as run is in git at 2c029ae, removed afterwards |

## Results, same 24 mails

AUC / accuracy at score 0 (n = mails with a label for that question):

| model | is_spam (24) | risk_phishing (21) | risk_fraud (21) | asks_payment (15) | median per mail, 4 questions |
|---|---|---|---|---|---|
| Mica v0.5 4B | **1.000** / 0.958 | **1.000** / 1.000 | **1.000** / 0.952 | **1.000** / 1.000 | 37.6 s (transformers BF16); **4.6 s** (llama.cpp Q8_0, below) |
| Jev-Style 0.8B v3 | 0.924 / 0.917 | 0.889 / 0.857 | 0.852 / 0.667 | 1.000 / 0.733 | 3.5 s |
| e5 head (tier 1) | 0.972 | | | | |

Jev on all 64: is_spam 0.918, phishing 0.878, fraud 0.779, payment 0.997 (AUC); 3.4 s per mail.

## Mica on its own CPU runtime

Mica's server (akivet/Mica @ 5529ffa1, `mica.server`) on llama.cpp b11700 with its long-input patch,
built for this CPU (`GGML_NATIVE=ON`, shared libraries, no GPU), `mica-v0.5-4b-Q8_0.gguf` @ 5ea7aafe,
`--n-ctx 4096`, started through `ml/sidecar/mica_serve.py` to set the thread count (its server leaves
llama.cpp at its default of 4), called through `ml/sidecar/decision_server.py` as firstreadd calls it
(`bakeoff.py sidecar`). Same 24 mails; the AUC and accuracy of every question are identical to the
BF16 run above.

| runtime | median per mail, 4 questions | one mail, all 34 questions |
|---|---|---|
| transformers BF16, 12 threads | 37.6 s | |
| llama.cpp Q8_0, 4 threads (its default), `--seqs 4` | 11.1 s | 82.0 s |
| llama.cpp Q8_0, 12 threads, `--seqs 4` | | 34.8 s |
| llama.cpp Q8_0, 12 threads, `--seqs 16` | **4.6 s** | **29.6 s** |

About 0.9 s per question on 12 threads of this CPU. The 34-question figure is one mail (a synthetic
phishing message), not a median.

## What it says, and what it does not

- Mica 4B separates all four questions on this sample; Jev 0.8B misses most on fraud (accuracy 0.67
  at 0) and is below the e5 head on spam. Zero-shot, neither was told anything about our mail.
- 24 mails, few positives per question (3 to 9), synthetic Dutch positives: an AUC of 1.000 here
  says "no mistake on these", not "no mistakes". The order is clear enough to choose a teacher; the
  numbers are not a quality claim.
- The first Mica time is transformers in BF16 on a CPU without BF16 matrix units, the slowest way to
  run it; its llama.cpp Q8_0 runtime is the table above. Production hardware is not this machine.

## Decision

Mica 4B is the teacher for distillation (about 30 s per mail for the whole catalogue: an offline job on
a lab sample) and the tier-2 model (a few questions per unsure mail: seconds, after delivery). Before it
serves tier 2: its runtime measured on the production CPU, a calibration fitted on the lab's dev split, and the agreement check of
`ml/distill/teach.py` on a larger sample. Jev 0.8B is dropped (code and weights removed).

Why Mica was slow here: this CPU has AVX-512 VNNI but no BF16 units, so BF16 ran emulated; the
Qwen3.5 linear-attention layers ran transformers' reference PyTorch code (its fast kernels are not
installed, and are GPU kernels); and each question re-read the mail, where Mica's own runtime reads it
once and only adds each question. Its llama.cpp Q8_0 path addresses all three.
