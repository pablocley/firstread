//! Network facts about senders and recipients.
//!
//! Responsibilities:
//! - DNS with caching and per-lookup deadlines: MX, A/AAAA, PTR with forward confirmation, TXT
//! - DNSBL queries (when Rspamd has not already done them)
//! - MTA-STS, DANE and TLS-RPT discovery for outbound recipient domains
//! - RDAP domain registration date (domain age is a strong phishing signal), cached by domain
//!
//! Every lookup can time out; a timeout yields `SignalValue::Unavailable`, never "fine".
//! Status: not implemented.
