# ml/

Everything that learns or measures models. Python. The runtime never imports anything from here;
the hand-off is an ONNX model, its tokenizer, a calibration file, and a manifest with sha256 hashes.

```
bench/        latency and sanity benchmarks (the 2026-10-26 baseline lives here)
distill/      teacher runs (JEV-27B / 35B on a GPU) and dataset building          (to build)
train/        tier-1 heads and optional encoder fine-tuning                      (to build)
calibrate/    per-head temperature fitting, reliability reports                  (to build)
export/       ONNX export, int8 quantisation, parity checks against fp32         (to build)
eval/         the evaluation harness over fixtures/ and the private eval set     (to build)
```

## Running the existing benchmarks

```
pip install torch transformers tokenizers safetensors sentence-transformers model2vec
python3 -I bench/bench_encoders.py <empty cache dir>
python3 -I bench/bench_jev08.py <dir with chaoliangUNSW/Jev-Style-0.8B-Decision-v3 downloaded>
```

`bench_jev08.py` imports the model's own loader from the model directory; verify the download
against the model's `manifest.json` first.

## Rules

- No customer mail in this directory, in notebooks, in model repositories, or in any external API.
- Every reported number states its hardware, runtime, precision and sample size.
- A model is accepted on the evaluation set in [`docs/07-evaluation.md`](../docs/07-evaluation.md),
  not on its model card.
