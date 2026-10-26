//! MIME to a normalised [`firstread_core::mail::MailState`].
//!
//! Responsibilities:
//! - parse hostile input within hard limits (size, nesting depth, part count, header count,
//!   decompressed size); on failure return an error, never a guess
//! - decode headers and display names; extract plain text (from HTML when needed), separating
//!   quoted earlier messages from new text
//! - collect links in document order with their visible text; never fetch them
//! - collect attachment metadata with content sniffing; never execute or render them
//! - detect language when confident
//!
//! Intended dependency: `mail-parser` (Stalwart Labs). Fuzz targets live next to this crate.
//! Status: not implemented.
