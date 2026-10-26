//! Rendering a [`firstread_core::stamp::Stamp`] for clients (docs/03-client-contract.md).
//!
//! Responsibilities:
//! - strip incoming `X-Firstread-*` headers before adding ours
//! - render `X-Firstread` (one machine-parseable line) and the optional detail headers;
//!   reasons localised and RFC 2047-encoded; no extracted personal data in headers
//! - map verdicts to keywords and folders through per-action thresholds from a data file,
//!   stricter Junk filing for POP3 accounts
//! - optional Subject prefix and body banner, never on signed (S/MIME, PGP) messages
//! - the full record for the API, keyed by the stamp id
//!
//! Status: not implemented.
