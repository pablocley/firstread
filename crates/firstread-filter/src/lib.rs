//! The delivery-time client (hook A, docs/12-interfaces.md section 4.1).
//!
//! Dovecot's Sieve `vnd.dovecot.filter` runs this program with the message on stdin (CRLF by
//! default) and the delivery context in `USER`, `SENDER`, `RECIPIENT` and `ORIG_RECIPIENT`. A
//! global `sieve_before` script calls it as a test and, when the test is false, deletes the
//! directive headers; a `sieve_after` script reads them (docs/12-interfaces.md section 4.1.1).
//! The intended flow:
//!
//! 1. read the whole message, always to the end
//! 2. build the [`firstread_core::context::DeliveryContext`] from the environment
//! 3. ask `firstreadd` over a Unix socket for a directive, within a deadline well below
//!    `sieve_filter_exec_timeout`
//! 4. [`finish`]: apply the directive with [`edit::apply`] (header block only, body bytes
//!    untouched by construction and checked); without a usable directive, remove only the
//!    foreign firstread headers ([`edit::strip_foreign`])
//! 5. write the result and exit 0; if not even step 4's fallback is possible, write nothing and
//!    exit non-zero: Pigeonhole then keeps the message unchanged, the `filter` test is false, and
//!    the `sieve_before` script deletes any directive headers a sender put in it
//!
//! Steps 1, 2, 4 and 5 exist; step 3 waits for the daemon. Until then every message takes the
//! fallback, which is also the behaviour when the daemon is unreachable.

pub mod edit;

use firstread_core::directive::{Directive, DirectivePolicy};

/// What the filter does with one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Write these bytes and exit 0. Every firstread header in them is ours.
    Write(Vec<u8>),
    /// Write nothing and exit non-zero, so the message stays as it was and the Sieve `filter`
    /// test is false.
    Decline,
}

/// Decide the output from the original bytes and the daemon's directive, if one arrived in time.
/// An invalid directive is treated like a missing one: it is never partly applied.
pub fn finish(message: &[u8], directive: Option<&Directive>, policy: &DirectivePolicy) -> Outcome {
    if let Some(d) = directive
        && let Ok(out) = edit::apply(message, d, policy)
    {
        return Outcome::Write(out);
    }
    match edit::strip_foreign(message, policy) {
        Ok(out) => Outcome::Write(out),
        Err(_) => Outcome::Decline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firstread_core::directive::{AddHeader, FolderKey, HeaderName, HeaderValue};

    const FORGED: &[u8] =
        b"X-Firstread-Folder: inbox\r\nFrom: a@example.org\r\nSubject: test\r\n\r\nbody\xff\r\n";
    const CLEAN: &[u8] = b"From: a@example.org\r\nSubject: test\r\n\r\nbody\xff\r\n";

    #[test]
    fn no_directive_strips_forged_headers_only() {
        assert_eq!(
            finish(FORGED, None, &DirectivePolicy::default()),
            Outcome::Write(CLEAN.to_vec())
        );
    }

    #[test]
    fn invalid_directive_is_never_partly_applied() {
        let bad = Directive {
            add: vec![
                AddHeader {
                    name: HeaderName::new("X-Firstread").unwrap(),
                    value: HeaderValue::from_text("v=1"),
                },
                AddHeader {
                    name: HeaderName::new("Reply-To").unwrap(),
                    value: HeaderValue::from_text("x@example.org"),
                },
            ],
            ..Directive::default()
        };
        assert_eq!(
            finish(FORGED, Some(&bad), &DirectivePolicy::default()),
            Outcome::Write(CLEAN.to_vec())
        );
    }

    #[test]
    fn valid_directive_is_applied() {
        let d = Directive {
            folder: Some(FolderKey::new("junk").unwrap()),
            ..Directive::default()
        };
        let Outcome::Write(out) = finish(FORGED, Some(&d), &DirectivePolicy::default()) else {
            panic!("declined")
        };
        assert!(out.starts_with(b"X-Firstread-Folder: junk\r\nFrom:"));
    }

    #[test]
    fn unparseable_message_is_declined() {
        assert_eq!(
            finish(
                b"X-Firstread-Folder: inbox",
                None,
                &DirectivePolicy::default()
            ),
            Outcome::Decline
        );
    }
}
