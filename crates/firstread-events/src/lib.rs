//! Getting events into the log (hooks D, F and G in docs/01-architecture.md).
//!
//! Adapters:
//! - IMAPSieve: copies into / out of Junk and the user's folders
//! - Dovecot push-notification Lua driver: `message_read`, `message_trash`, `message_expunge`,
//!   `flags_set` / `flags_clear` (with keyword lists), `message_new`; verify the event set on the
//!   deployed Dovecot version
//! - the API and digest confirmation pages (one-tap verdicts, POST only)
//! - the Sent folder and outbound submissions (replies, new correspondents)
//! - backfill of an existing mailbox when firstread is enabled for it
//!
//! Every adapter maps to `firstread_core::event::Event`, rate-limits per source, and drops
//! events it cannot attribute to a stamped message (with a counter, not silently).
//! Status: not implemented.
