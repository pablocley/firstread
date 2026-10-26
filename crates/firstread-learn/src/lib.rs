//! Continuous learning (docs/08-learning.md, ADR-0008).
//!
//! Learners consume the event log and update state per scope, fastest first:
//! - reputation counters (Beta-binomial with decay) per key and scope
//! - exemplar memory per mailbox / organisation (labelled embeddings, nearest-neighbour vote)
//! - campaign memory (verdict on one copy reaches all copies, including delivered ones)
//! - personal residual heads, regularised towards the global head
//! - personal thresholds from rescue and report rates
//! - folder-habit miner (produces suggestions, never silent rules)
//! - daily platform heads and combiner, promoted only by champion / challenger on replay
//! - user rules promoted from tier 2 to tier-1 heads once they win on held-out labels
//!
//! Guardrails live here too: per-account trust weights and caps, the scope gates from
//! `firstread_core::scope`, never training on firstread's own verdicts, snapshots and rollback.
//! Status: not implemented. The core of it starts with the counters below.

pub mod counter;
