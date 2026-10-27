//! Models, all speaking the typed-decision contract in [`firstread_core::decision`], each a
//! backend for the provider contract in [`firstread_core::provider`] (docs/14-providers.md).
//!
//! Responsibilities:
//! - load model releases by manifest (sha256-pinned ONNX file, tokenizer, calibration file)
//! - tier 0: static embedding for near-duplicate and campaign fingerprints
//! - tier 1: one contextual embedding per message, then small heads, each returning a calibrated
//!   `noul` / `choice` / `score` distribution
//! - tier 2: a client for the separate decision-model service (llama.cpp or vLLM), with a queue,
//!   batching and confidence-gated escalation; never called in the delivery path. Built for now in
//!   `firstreadd` over the sidecar protocol (`ml/sidecar/decision_server.py`, ADR-0020)
//! - record the model release in every decision
//!
//! Intended dependencies: `ort` (pinned exactly; a release candidate at design time) and
//! `tokenizers`. Models come from `ml/`; see docs/04-models.md.
//! Status: not implemented.
