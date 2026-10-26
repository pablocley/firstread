//! The threat commons (docs/10-commons.md, ADR-0009). Optional; delivery never depends on it.
//!
//! - export: only bad, bulk or infrastructure indicators that passed the local gates in
//!   `firstread_core::scope` and a confirmation rule; never addresses of individuals, recipients,
//!   content of non-bulk mail, allowlists or behaviour
//! - signing and verification of indicator batches and hub aggregates
//! - client: pull signed deltas from one or more hubs; weight by independent corroboration and
//!   source track record; expire on TTL
//! - hub: ingest, deduplicate, aggregate corroboration, sign, serve deltas
//!
//! Status: not implemented.
