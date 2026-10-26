//! Memory across messages.
//!
//! Per mailbox:
//! - sender relationship: first contact, seen before, written to, regular correspondent
//! - vendors and the bank details they have used over time (bank-detail change detection)
//! - colleague names in the mailbox's own domain (impersonation)
//! - thread state, subscriptions with read rates, duplicates, storage insight
//!
//! Platform-wide (hashes, cluster ids and counts only, never another customer's content):
//! - campaign clustering from fingerprints and embeddings; campaign verdicts
//! - sender, domain, IP and URL reputation from our own traffic and feedback
//!
//! Lookups on the delivery path have deadlines; the store is behind a trait so the store
//! decision (docs/decisions/0006-central-store.md) stays open. Deletion follows the mailbox.
//! Status: not implemented.
