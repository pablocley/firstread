//! The digest (docs/09-experience.md): the one surface that works in every client, POP3 included.
//!
//! - sections only when non-empty: filtered (with a deliberate sample of borderline cases),
//!   suggestions, never-read newsletters, waiting on reply, invoices, security
//! - frequency per mode; asks on first send; off by default in Quiet mode
//! - every action is a signed, expiring, single-purpose token; the link opens a confirmation page
//!   and acts only on POST, so automated link scanners cannot trigger it
//! - plain language in the mailbox's language
//!
//! Status: not implemented.
