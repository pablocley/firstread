# ADR-0001 · Rust for the runtime, Python for learning

Status: accepted

## Question

Is Rust actually the handy choice here, or a preference?

## Decision

The runtime (daemon, delivery filter, milter, CLI) is Rust. Everything that learns (distillation,
training, evaluation, ONNX export, benchmarks) is Python. The boundary is the ONNX file, its
tokenizer, and a calibration file.

## Why Rust fits this runtime on the merits

| need | Rust option (checked 2026-10-26) |
|---|---|
| parse hostile MIME on every message without memory-safety bugs | `mail-parser` (Stalwart Labs); memory safety is the strongest argument for Rust in this path |
| SPF, DKIM (1 and 2), DMARC, ARC, DMARC report parsing | [`mail-auth`](https://github.com/stalwartlabs/mail-auth) 0.11.x, Apache-2.0 or MIT, supports DKIM2, DKIM1, ARC, SPF, DMARC and aggregate report parsing |
| milter for Postfix | [`indymilter`](https://docs.rs/crate/indymilter/latest) 0.3.0: pure, safe, async (Tokio), no libmilter dependency |
| DNS with caching | `hickory-resolver` (what `mail-auth` uses) |
| model inference in-process | [`ort`](https://docs.rs/crate/ort/latest) 2.0.0-rc.13, wrapping ONNX Runtime 1.28; plus the `tokenizers` crate |
| predictable latency and memory under load | no GC pauses in the delivery path |

Go would also work (milter and DKIM / DMARC libraries exist), but the Stalwart crates are the most
complete mail-authentication stack found, and `ort` is mature. Rust is a good fit here, not only a
preference.

## Where Rust is not handy, and the mitigation

| weakness | mitigation |
|---|---|
| ML training, fine-tuning, the JEV loaders and evaluation tools are Python | all of that lives in `ml/`; Rust only runs exported models |
| `ort` is still a release candidate | pin the exact version; the decision-model tier runs as a separate service anyway |
| slower iteration on heuristics | thresholds, keyword names, reasons and rule lists are data files, not code |
| the tier-2 decision model (decoder, GGUF / vLLM) | runs as a separate local service over HTTP, not linked into the daemon |
