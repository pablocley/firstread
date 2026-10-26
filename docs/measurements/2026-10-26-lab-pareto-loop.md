# 2026-10-26 · Lab loop with the three-axis keep rule (tag `oct26b`)

The owner's rule, set later the same day: **keep a change only when quality, latency or footprint
improves beyond noise and none of the three gets worse.** Same machine, data and harness as
[2026-10-26-lab-v0.md](2026-10-26-lab-v0.md), plus the timing pass below. Results:
[`lab/results/oct26b/`](../../lab/results/oct26b/). Queues run: [`lab/loop/queues/`](../../lab/loop/queues/).

## How each axis is measured

- **Quality**: cost per 1,000 messages on the primary dev slice (SpamAssassin, 967 messages),
  λ = 100, threshold 0.990. Paired bootstrap against the champion. Worse also means any legitimate
  message newly in Junk on any slice, a slice significantly worse, or drifting from the baseline.
- **Latency**: wall time of the real `firstread-filter` process per email (process start, socket,
  daemon pipeline, sidecar with the model computing every vector, no cache).
- **Footprint**: CPU time per email of filter, daemon and sidecar, and peak resident memory
  (VmHWM) of sidecar plus daemon.

Latency and footprint come from a timing pass inside every run: the champion and the candidate each
get their own sidecar (model loaded first, cache off) and daemon, and the same 200 dev messages
(seeded sample, 10 warm-up) go through the filter to both, alternating which goes first. Verdicts
use ratios of means with bootstrap CI95; tolerances in `lab/cost.toml` `[keep]` (improve: CI95 below
1 and at least 5 % better; worse: CI95 above 1 or at least 5 % worse; memory: 5 % better, 3 % worse).

Noise check (A/A, the baseline against itself, quiet machine): latency 0.999 [0.976, 1.023], CPU
1.004 [0.982, 1.027], memory 1.000, all `equal`. Under 1.4 cores of load from another process an
identical pair measured latency 0.944 [0.893, 0.997], which would have passed as an improvement;
the harness therefore marks a pass `unmeasured` when other processes take more than 0.15 of a core,
and the run is repeated. Absolute milliseconds move between passes (the same champion measured
40 ms in one pass and 54 ms in another); ratios within a pass are what the rule uses, and the
headline numbers below come from one pass with baseline and champion side by side.

## Runs

| # | change | cost / 1k | Δ quality, CI95 | latency | CPU | memory | axes | kept |
|---|---|---|---|---|---|---|---|---|
| 0 | baseline: e5-small torch fp32, 256 tokens, 2 threads; threshold 0.990 from the cost table | 122.0 |  | 1.00 | 1.00 | 1.00 | baseline | baseline |
|  | e5-small on onnxruntime fp32 instead of torch | 122.0 | +0.0 [+0.0,+0.0] | 0.74 | 0.80 | 1.10 | q equal, l improve, f worse | no |
| 1 | e5-small onnxruntime int8 (dynamic quantisation) instead of torch fp32 | 121.0 | -1.0 [-7.2,+5.2] | 0.43 | 0.42 | 0.57 | q equal, l improve, f improve | **yes** |
| 2 | token limit 192 instead of 256 | 121.0 | +0.0 [-9.3,+9.3] | 0.38 | 0.36 | 0.57 | q equal, l improve, f improve | **yes** |
|  | token limit 128 (fail:drift_vs_baseline) | 220.3 | +99.3 [-11.4,+311.3] | 0.31 | 0.27 | 0.57 | q worse, l improve, f improve | no |
|  | 1 compute thread instead of 2 | 121.0 | +0.0 [+0.0,+0.0] | 0.51 | 0.28 | 0.57 | q equal, l worse, f improve | no |
|  | combiner: cross-fitted Platt recalibration on calib (fail:drift_vs_baseline) | 295.8 | +174.8 [-38.3,+489.1] | 0.38 | 0.36 | 0.57 | q worse, l equal, f equal | no |
|  | head C=3 | 115.8 | -5.2 [-10.3,+0.0] | 0.38 | 0.36 | 0.57 | q equal, l equal, f equal | no |
| 3 | combiner C=2 | 99.3 | -21.7 [-31.0,-13.4] | 0.38 | 0.36 | 0.57 | q improve, l equal, f equal | **yes** |
|  | onnxruntime memory arena and memory patterns off | 99.3 | +0.0 [+0.0,+0.0] | 0.39 | 0.36 | 0.57 | q equal, l equal, f equal | no |
|  | token limit 160 (fail:drift_vs_baseline) | 206.8 | +107.5 [-1.0,+316.4] | 0.34 | 0.32 | 0.57 | q worse, l unmeasured, f unmeasured | no |
|  | token limit 160 (rerun: noise) (fail:drift_vs_baseline) | 206.8 | +107.5 [-1.0,+316.4] | 0.34 | 0.31 | 0.57 | q worse, l unmeasured, f unmeasured | no |
|  | combiner C=4 (fail:drift_vs_baseline) | 298.9 | +199.6 [-10.3,+511.9] | 0.37 | 0.35 | 0.57 | q worse, l equal, f equal | no |
|  | head: class-balanced logistic (fail:drift_vs_baseline) | 309.2 | +209.9 [+2.1,+520.2] | 0.39 | 0.36 | 0.57 | q worse, l equal, f equal | no |
| 4 | combiner: L1 penalty (sparser) | 87.9 | -11.4 [-18.6,-5.2] | 0.38 | 0.36 | 0.57 | q improve, l equal, f equal | **yes** |
|  | head C=3 | 82.7 | -5.2 [-10.3,+0.0] | 0.37 | 0.36 | 0.57 | q worse, l equal, f equal | no |
|  | head C=0.5 | 93.1 | +5.2 [+1.0,+10.3] | 0.38 | 0.36 | 0.57 | q worse, l equal, f equal | no |
| 5 | SentencePiece tokenizer instead of the tokenizers library | 88.9 | +1.0 [+0.0,+3.1] | 0.38 | 0.36 | 0.35 | q equal, l equal, f improve | **yes** |
| 6 | combiner C=4 with L1 | 84.8 | -4.1 [-8.3,-1.0] | 0.36 | 0.36 | 0.35 | q improve, l equal, f equal | **yes** |
|  | combiner C=1 with L1 | 95.1 | +10.3 [+4.1,+17.6] | 0.36 | 0.35 | 0.35 | q worse, l equal, f equal | no |
|  | information: harrier-270m torch fp32 256 tokens (fail:drift_vs_baseline) | 175.8 | +91.0 [-22.8,+305.1] | 3.59 | 4.05 | 1.83 | q worse, l worse, f worse | no |
|  | information: potion-multilingual-128M (static embeddings) | 103.4 | +18.6 [+5.2,+32.1] | 0.09 | 0.03 | 1.74 | q worse, l improve, f worse | no |
|  | information: tier 0 only, no model (fail:drift_vs_baseline) | 293.7 | +208.9 [+90.0,+427.1] | 0.05 | 0.01 | 0.00 | q worse, l improve, f improve | no |
|  | information: mmbert-small torch int8 192 tokens | 113.8 | +29.0 [+14.5,+43.4] | 1.12 | 1.15 | 1.67 | q worse, l worse, f worse | no |
|  | combiner C=8 with L1 | 83.8 | -1.0 [-3.1,+0.0] | 0.35 | 0.36 | 0.35 | q equal, l equal, f equal | no |
|  | head C=3 (on the L1 combiner) | 79.6 | -5.2 [-11.4,+0.0] | 0.36 | 0.36 | 0.35 | q equal, l equal, f equal | no |
|  | head C=2 | 81.7 | -3.1 [-7.2,+0.0] | 0.37 | 0.36 | 0.35 | q worse, l equal, f equal | no |

Index columns: each run's ratio against the champion of the moment, chained from the baseline
(1.00), so a kept step's index carries into the next. `unmeasured`: the noise guard tripped; the
run was repeated. Quality `worse` with a CI touching 0 means a slice got significantly worse
(`modern_cross_source` for both head C=3 on ce592b3 and head C=2) or a legitimate message went to
Junk. `drift_vs_baseline`: worse than the baseline run, not only the champion. The four
`information` runs are other providers measured against the champion of the moment, not candidates.
Raw rows: [`lab/results/oct26b/results.tsv`](../../lab/results/oct26b/results.tsv).

## Baseline against champion, one pass

Command: `python3 -I lab/analysis/head_to_head.py oct26b 24923a5 edf10a6` (one harness run with
the baseline as the champion arm). Raw: [`head-to-head.json`](../../lab/results/oct26b/head-to-head.json).
Other processes took 0.006 cores during the pass.

| | baseline 24923a5 | champion edf10a6 | change, CI95 |
|---|---|---|---|
| provider | e5-small, PyTorch fp32, 256 tokens, HF `tokenizers` | e5-small, ONNX Runtime int8, 192 tokens, SentencePiece | |
| combiner | L2, C=1 | L1, C=4 | |
| cost per 1,000, primary dev (967) | 122.0 | 84.8 | −37.2 [−50.7, −24.8] |
| legitimate in Junk, all dev (937 legitimate) | 0 | 0 | |
| spam left in the inbox, all dev (591 spam) | 153 | 95 | |
| latency per email, p50 / mean / p99 | 91.7 / 92.4 / 150.8 ms | 32.1 / 32.9 / 55.8 ms | mean ×0.356 [0.342, 0.370] |
| CPU per email (filter, daemon, sidecar) | 151.5 ms | 52.5 ms | ×0.347 [0.336, 0.358] |
| peak memory (sidecar + daemon, VmHWM) | 1,087 MB | 385 MB | ×0.354 |

The indexes chained through the loop (latency 0.36, CPU 0.36, memory 0.35) agree with this
direct pass, so the chaining did not drift.

## Sealed split: one query, and the cost ratio

One query (`sealed_queries_per_tag = 1`), on edf10a6 after the loop ended:
`python3 -I lab/harness/run.py --sealed lab/runs/edf10a6-sealed`. 1,914 messages: primary
SpamAssassin 1,210 (805 ham, 25 hard ham, 380 spam), modern cross-source 540, synthetic Dutch 164.

| | dev | sealed |
|---|---|---|
| cost per 1,000, primary | 84.8 | 350.4 |
| legitimate in Junk | 0 of 937 | 3 of 1,174, all hard ham (3 of 25) |
| spam left in the inbox, primary | 82 of 303 (27 %) | 124 of 380 (33 %) |
| cost per 1,000, modern cross-source | 20.8 | 25.9 |
| cost per 1,000, synthetic Dutch | 31.0 | 30.5 |
| ECE, primary | 0.020 | 0.021 |

The three hard-ham false positives are 300 of the 424 cost units on the sealed primary slice. With
49 hard-ham messages in dev and 25 in sealed, one false positive adds 83 per 1,000 to the sealed
primary cost (103 on dev), so dev and sealed are far apart on few messages. The baseline was not
scored on the sealed split; whether the loop's dev quality gain holds there is open. A second query
(baseline and champion together) needs the owner to raise the ration.

**λ sweep**, same query, list fixed in the harness before it ran, nothing chosen from it.
Primary slice; the other slices had no false positives at any λ.

| λ | threshold | legitimate in Junk (of 830) | spam missed (of 380) | modern spam missed (of 300) | Dutch spam missed (of 60) |
|---|---|---|---|---|---|
| 9 | 0.900 | 7 (2 ham, 5 hard ham) | 74 (19 %) | 3 | 0 |
| 20 | 0.952 | 4 (hard ham) | 99 (26 %) | 4 | 0 |
| 30 | 0.968 | 4 | 104 (27 %) | 8 | 1 |
| 50 | 0.980 | 3 | 113 (30 %) | 9 | 3 |
| 100 | 0.990 | 3 | 124 (33 %) | 14 | 5 |
| 200 | 0.995 | 2 | 142 (37 %) | 17 | 11 |
| 999 | 0.999 | 1 | 202 (53 %) | 32 | 14 |

Reading it: λ prices a legitimate message in Junk; it is not fitted to data, because minimising
cost at λ only says which threshold is best for that λ. What the curve says: between λ = 20 and
100 the false-positive count is flat (4 to 3, all hard ham) while missed spam rises from 26 % to
33 %; below 20 ordinary ham starts going to Junk; above 100 missed spam climbs fast for one or two
fewer false positives. The hard-ham errors survive high thresholds, so they need better evidence
(sender history, which the lab has no per-mailbox state for), not a different λ.
Androutsopoulos et al. price a blocked legitimate message at 9 when the sender is asked to resend
and 999 when it is deleted ([2000](https://arxiv.org/abs/cs/0006013)); a visible Junk folder lies
between.

## Reproducing the champion from main

The loop trained the L1 combiner with scikit-learn's `saga` solver unseeded, so two trainings
differ in the fifth decimal of the calibration error. Main seeds it (`random_state=0` in
`ml/heads/train.py`); two runs of main's `lab/experiment.toml` (`run.py --no-timing`, 2026-10-27)
gave the same combiner release and the champion's dev result: 84.8 per 1,000, 0 legitimate in Junk,
95 spam missed.

## What the rule refused, and why that matters

A trade is never kept, whatever its size. The ones this loop met, each a real option for a
deployment that weighs the axes differently:

| change | better | worse |
|---|---|---|
| ONNX Runtime fp32 instead of torch fp32 | latency ×0.74, CPU ×0.80 | memory ×1.10 |
| 1 compute thread instead of 2 | CPU ×0.78 | latency ×1.32 |
| 160 or 128 tokens instead of 192 | latency ×0.89 / ×0.82, CPU ×0.86 / ×0.74 | one legitimate message (the same hard-ham message, `spamassassin-447ee29f72798d61`) in Junk |
| potion-multilingual-128M instead of e5 | latency ×0.25, CPU ×0.085 | quality (+18.6 per 1,000), memory ×4.9 (1.9 GB) |
| tier 0 only, no model | latency ×0.15, CPU ×0.04, memory 5 MB | quality (+209 per 1,000, a legitimate message in Junk) |

Two hard-ham messages (`spamassassin-447ee29f72798d61`, `spamassassin-1cdcb0c1e65a2fae`) are the
edge almost every more aggressive change ran into: shorter inputs, the cross-fitted
recalibration, a class-balanced head, a less regularised combiner. With 49 hard-ham messages in
dev, the false-positive side of every comparison rests on very few messages.
