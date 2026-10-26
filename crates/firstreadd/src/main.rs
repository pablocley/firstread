//! `firstreadd`: the daemon.
//!
//! Responsibilities:
//! - Unix socket for `firstread-filter` (delivery) and `firstread-milter`
//! - run tier 0 and tier 1 within the per-message deadline; queue what did not finish
//! - async worker for tier 2, post-delivery keyword updates (doveadm or IMAP), retroactive
//!   campaign verdicts, and feedback ingestion (IMAPSieve events)
//! - HTTP API (docs/03-client-contract.md)
//! - load shedding: inline tier 1 first, then tier 0 extras; parsing and auth last
//! - metrics, including the fail-open rate
//!
//! Status: not implemented.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("firstreadd: not implemented yet (design phase); see docs/01-architecture.md");
    ExitCode::FAILURE
}
