//! Rendering a [`firstread_core::stamp::Stamp`] for clients (docs/03-client-contract.md).
//!
//! Responsibilities:
//! - build the [`firstread_core::directive::Directive`]; incoming `X-Firstread-*` headers are
//!   removed by the filter on every path, not here
//! - render `X-Firstread` (one machine-parseable line) and the optional detail headers;
//!   reasons localised and RFC 2047-encoded; no extracted personal data in headers
//! - map verdicts to keywords and folder keys through per-action thresholds from a data file,
//!   stricter Junk filing for POP3 accounts
//! - optional Subject prefix (a header edit); never anything in the body, so no banners: webmail
//!   renders those from the record (ADR-0013)
//! - the full record for the API, keyed by the stamp id
//!
//! Status: not implemented.
