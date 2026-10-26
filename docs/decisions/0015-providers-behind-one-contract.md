# ADR-0015 · Every System 1 model is a provider behind one contract

Status: accepted

## Decision

- Two traits in `firstread-core::provider`: a **decider** (one rendered message, many typed
  questions, raw logits per question) and an **embedder** (text to a vector in a named space).
  Backends (ONNX Runtime, llama.cpp, vLLM, HTTP) live behind them.
- Each provider has a manifest: release id, weights hash, licence and commercial use, locality,
  measured languages, input limit, prompt template or space.
- Logits become decisions only through a calibration fitted per (release, question). No
  calibration, no decision.
- Data rules are checked before every call: customer mail only to in-process or local providers
  whose licence allows commercial use; remote providers only in the lab, on data whose terms allow it.
- Vectors carry their space; comparing across spaces is refused. An embedder swap dual-writes,
  re-embeds in the background and switches reads per mailbox.

## Consequences

- A better JEV-style or encoder model is a registry entry plus a lab run, not a code change.
- Thresholds keep their meaning across models because they act on calibrated probabilities, and
  are still re-checked per release.
- Details: [14 · Providers](../14-providers.md).
