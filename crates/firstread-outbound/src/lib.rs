//! The sending side (docs/05-sending.md).
//!
//! Responsibilities:
//! - draft checks for the API: recipient domain typos, undeliverable domains, replies into
//!   lookalike-domain threads, first contact, missing attachments, sensitive data, reply-all fan-out
//! - submission checks: compromised-account scoring, adaptive rate limits, signing and alignment
//! - delivery diagnostics: DSN and log classification in plain language, per-domain delivery
//!   overview, the customer's own domain health (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
//!
//! Status: not implemented.
