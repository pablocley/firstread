//! Static analysis of links and sender names. Nothing here fetches anything.
//!
//! Responsibilities:
//! - URL normalisation, registrable domain, IP-literal and shortener detection
//! - link text vs target mismatch
//! - lookalike domains: confusable characters, punycode, edit distance to domains this mailbox
//!   and the platform know (including the customer's own domain)
//! - display-name spoofing: a brand or colleague name that the address does not back up
//! - brand impersonation from a data file of brands and their legitimate sending domains
//! - extractors with checksums: IBAN (mod-97), BSN (11-proef; detected, never stored), payment
//!   cards (Luhn), OTP codes, tracking numbers, invoice numbers, dates and amounts
//!
//! Status: not implemented.
