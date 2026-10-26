# ADR-0004 · JEV-shaped typed decisions in two tiers

Status: accepted; the inline / async boundary for tier 1 is decided by measurement on production hardware

## Context

Measured on 2026-10-26 ([baseline](../measurements/2026-10-26-cpu-baseline.md)): an open 0.8B
JEV-style decision model costs ≈ 2.1 s per question in eager PyTorch on 2 vCPU and missed
impersonation and secrecy pressure in a Dutch CEO-fraud mail zero-shot; a multilingual encoder
embedding costs 177–778 ms; a static embedding 1.3 ms.

## Decision

1. Every decision uses one output contract: `noul`, `choice` or `score`, as a calibrated
   distribution. Tiers differ in cost, not in what they return.
2. Tier 1: embed each message once with a small multilingual encoder; fixed decisions are small
   calibrated heads on that embedding.
3. Tier 2: a JEV-style decision model, asynchronous, for low-confidence cases, user rules and
   campaign confirmation.
4. Identity and authentication are never delegated to a model.
5. Students are distilled from large JEV models plus behaviour labels, fine-tuned for Dutch, and
   accepted only on our evaluation set.

## Open

- Whether tier 1 runs inline (with a deadline) or right after delivery, once ONNX int8 latency is
  measured on production CPUs.
- Which embedder wins on the Dutch evaluation set.
