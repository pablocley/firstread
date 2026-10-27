# ml/

Everything that learns or measures models. Python. The runtime never imports anything from here;
the hand-off is an ONNX model, its tokenizer, a calibration file, and a manifest with sha256 hashes.

```
bench/        latency and sanity benchmarks (the 2026-10-26 baseline lives here)
distill/      teacher runs: a decision model labels lab mail (teach.py)
train/        tier-1 heads and optional encoder fine-tuning                      (to build)
calibrate/    per-head temperature fitting, reliability reports                  (to build)
export/       ONNX export, int8 quantisation, parity checks against fp32         (to build)
eval/         the evaluation harness over fixtures/ and the private eval set     (to build)
```

## Sidecars, heads and their tests

`sidecar/server.py` serves tier-1 heads (a vector per `noul` question, a matrix per choice or
score question) over cached embeddings; `sidecar/decision_server.py` puts Mica 4B's own server behind
the same protocol as tier 2 (any question, by its text). `heads/train.py` trains heads for the questions in
`[heads] questions` that the lab's items label, and `train.py verdict <kind>` a verdict's combiner.
`distill/teach.py` has a decision model label lab messages with the whole catalogue (the teacher),
and `[heads] teacher` in `lab/experiment.toml` distils heads from its answers. Tests, with the lab's
Python: `python3 -I tests/test_sidecars.py`, `tests/test_train.py` and `tests/test_distill.py`.

## Running the existing benchmarks

```
pip install torch transformers tokenizers safetensors sentence-transformers model2vec
python3 -I bench/bench_encoders.py <empty cache dir>
python3 -I bench/bakeoff.py sample|mica|report ...   # decision-model bake-off (docs/measurements)
```

`sidecar/mica_serve.py` starts Mica's own server with a CPU thread count (its server leaves llama.cpp at
4); `bakeoff.py sidecar` measures through the tier-2 sidecar, as firstreadd calls it.

## Rules

- No customer mail in this directory, in notebooks, in model repositories, or in any external API.
- Every reported number states its hardware, runtime, precision and sample size.
- A model is accepted on the evaluation set in [`docs/07-evaluation.md`](../docs/07-evaluation.md),
  not on its model card.
