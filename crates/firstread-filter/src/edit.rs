//! Apply a [`Directive`]'s header edits to the original message bytes.
//!
//! This is the only code in firstread that writes a message. It touches the header block and
//! nothing else: the body (everything from the empty line that ends the headers) is copied by
//! slice and checked before returning. Any ambiguity is an error, and the caller then falls back
//! (see `crate::finish`).
//!
//! Every header in firstread's namespace that arrived with the message is removed on every call,
//! whatever the directive says, so the folder and keyword headers the Sieve script reads can only
//! be ours. Header names are read the way Dovecot's own parser reads them (`message-header-parser.c`
//! skips whitespace before the colon), so `X-Firstread-Folder : junk` cannot slip past.

use firstread_core::directive::{
    AddHeader, Directive, DirectiveError, DirectivePolicy, HeaderValue, MAX_LINE, Which,
};

/// Why the edits were not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The message contains no line ending at all, so its structure is unknown.
    NoLineEnding,
    /// The directive does not satisfy the policy.
    Invalid(DirectiveError),
    /// Internal check failed: the body would have changed. Should be impossible; never ignored.
    BodyChanged,
}

/// One header field in the original message: its name as Dovecot reads it (bytes before the
/// colon, trailing whitespace removed; `None` without a colon) and its raw bytes, including
/// continuation lines and line endings.
struct Field<'a> {
    name: Option<&'a [u8]>,
    raw: &'a [u8],
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Split a message into (header fields, body). The body starts at the empty line that ends the
/// header block and includes that line; with no empty line the body is empty.
fn split(message: &[u8]) -> (Vec<Field<'_>>, &[u8]) {
    let mut fields: Vec<Field<'_>> = Vec::new();
    let mut pos = 0;
    while pos < message.len() {
        let end = message[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(message.len(), |i| pos + i + 1);
        let line = &message[pos..end];
        let content = line
            .strip_suffix(b"\n")
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .unwrap_or(line);
        if content.is_empty() {
            return (fields, &message[pos..]);
        }
        let continuation = is_wsp(line[0]);
        match fields.last_mut() {
            Some(last) if continuation => {
                let start = last.raw.as_ptr() as usize - message.as_ptr() as usize;
                last.raw = &message[start..end];
            }
            _ => {
                let name = content
                    .iter()
                    .position(|b| *b == b':')
                    .map(|i| {
                        let mut n = &content[..i];
                        while let Some((last, rest)) = n.split_last() {
                            if !is_wsp(*last) {
                                break;
                            }
                            n = rest;
                        }
                        n
                    })
                    .filter(|n| !n.is_empty());
                fields.push(Field { name, raw: line });
            }
        }
        pos = end;
    }
    (fields, &message[message.len()..])
}

/// The Subject field with `prefix` put in front of its value, once. Kept on one line when it
/// fits in RFC 5322's 998 characters, otherwise the original value moves to a continuation line.
fn prefixed_subject(raw: &[u8], prefix: &HeaderValue, eol: &[u8]) -> Vec<u8> {
    let colon = raw.iter().position(|b| *b == b':').unwrap_or(raw.len() - 1);
    let (head, rest) = raw.split_at(colon + 1);
    let value_start = rest.iter().position(|b| !is_wsp(*b)).unwrap_or(rest.len());
    let value = &rest[value_start..];
    let p = prefix.as_str().as_bytes();
    if value.len() >= p.len() && value[..p.len()].eq_ignore_ascii_case(p) {
        return raw.to_vec();
    }
    let mut out = head.to_vec();
    out.push(b' ');
    out.extend_from_slice(p);
    if value.is_empty() || value[0] == b'\r' || value[0] == b'\n' {
        out.extend_from_slice(value);
        return out;
    }
    let first_line = raw
        .iter()
        .position(|b| *b == b'\r' || *b == b'\n')
        .unwrap_or(raw.len());
    if first_line + 1 + p.len() > MAX_LINE {
        out.extend_from_slice(eol);
    }
    out.push(b' ');
    out.extend_from_slice(value);
    out
}

/// Apply the directive: drop every header in firstread's namespace that arrived with the message,
/// apply the directive's removals, add its headers and the derived folder and keyword headers at
/// the top, and prefix the Subject. Keywords and folder themselves are applied by the host (Sieve
/// reads them from the derived headers).
pub fn apply(
    message: &[u8],
    directive: &Directive,
    policy: &DirectivePolicy,
) -> Result<Vec<u8>, EditError> {
    directive.validate(policy).map_err(EditError::Invalid)?;
    let first_nl = message
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(EditError::NoLineEnding)?;
    let eol: &[u8] = if first_nl > 0 && message[first_nl - 1] == b'\r' {
        b"\r\n"
    } else {
        b"\n"
    };

    let (fields, body) = split(message);
    let mut keep: Vec<bool> = fields
        .iter()
        .map(|f| !f.name.is_some_and(|n| policy.owns(n)))
        .collect();
    for r in &directive.remove {
        let idx: Vec<usize> = fields
            .iter()
            .enumerate()
            .filter(|(_, f)| f.name.is_some_and(|n| r.name.matches(n)))
            .map(|(i, _)| i)
            .collect();
        let chosen: Vec<usize> = match r.which {
            Which::All => idx,
            Which::Nth(n) => idx
                .get(usize::from(n).wrapping_sub(1))
                .copied()
                .into_iter()
                .collect(),
            Which::NthFromEnd(n) => idx
                .len()
                .checked_sub(usize::from(n))
                .and_then(|i| idx.get(i))
                .copied()
                .into_iter()
                .collect(),
        };
        for i in chosen {
            keep[i] = false;
        }
    }

    let is_subject = |f: &Field<'_>| f.name.is_some_and(|n| n.eq_ignore_ascii_case(b"Subject"));
    let subject_at = fields
        .iter()
        .zip(&keep)
        .position(|(f, k)| *k && is_subject(f));

    let mut out = Vec::with_capacity(message.len() + directive.added_bytes(policy));
    let mut added: Vec<AddHeader> = directive.add.clone();
    added.extend(directive.derived_headers(policy));
    for h in &added {
        out.extend_from_slice(&h.render(eol));
    }
    if let (Some(prefix), None) = (&directive.subject_prefix, subject_at) {
        out.extend_from_slice(b"Subject: ");
        out.extend_from_slice(prefix.as_str().as_bytes());
        out.extend_from_slice(eol);
    }
    for (i, (f, k)) in fields.iter().zip(&keep).enumerate() {
        if !*k {
            continue;
        }
        match (&directive.subject_prefix, subject_at) {
            (Some(prefix), Some(at)) if at == i => {
                out.extend_from_slice(&prefixed_subject(f.raw, prefix, eol));
            }
            _ => out.extend_from_slice(f.raw),
        }
    }
    // A header block that ends without a line ending (message with no body) gets one before the
    // body would start; the body itself is copied verbatim.
    if body.is_empty() && !out.ends_with(b"\n") && !out.is_empty() {
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(body);

    if !out.ends_with(body) {
        return Err(EditError::BodyChanged);
    }
    Ok(out)
}

/// The fallback when there is no usable directive: remove only the headers in firstread's
/// namespace that arrived with the message, so nothing the Sieve script reads can be forged.
pub fn strip_foreign(message: &[u8], policy: &DirectivePolicy) -> Result<Vec<u8>, EditError> {
    apply(message, &Directive::default(), policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use firstread_core::directive::{FolderKey, HeaderName, ImapKeyword, RemoveHeader};

    fn add(name: &str, value: &str) -> AddHeader {
        AddHeader {
            name: HeaderName::new(name).unwrap(),
            value: HeaderValue::from_text(value),
        }
    }

    fn remove(name: &str, which: Which) -> RemoveHeader {
        RemoveHeader {
            name: HeaderName::new(name).unwrap(),
            which,
        }
    }

    fn body_of(m: &[u8]) -> &[u8] {
        split(m).1
    }

    fn head_of(m: &[u8]) -> String {
        String::from_utf8_lossy(&m[..m.len() - body_of(m).len()]).into_owned()
    }

    fn p() -> DirectivePolicy {
        DirectivePolicy::default()
    }

    const MSG: &[u8] = b"Received: from mx\r\n by us\r\nX-Firstread: v=1; forged\r\n\tcontinued\r\nFrom: a@example.org\r\nSubject: hi\r\n\r\nbody line 1\r\n\r\nX-Firstread: not a header, body text\r\n\xff\xfe binary\r\n";

    #[test]
    fn body_is_byte_identical_and_forged_stamp_removed() {
        let d = Directive {
            add: vec![add("X-Firstread", "v=1; id=st_1")],
            ..Directive::default()
        };
        let out = apply(MSG, &d, &p()).unwrap();
        assert_eq!(body_of(&out), body_of(MSG));
        let head = head_of(&out);
        assert!(head.starts_with("X-Firstread: v=1; id=st_1\r\n"));
        assert!(!head.contains("forged") && !head.contains("continued"));
        assert!(head.contains("Received: from mx\r\n by us\r\n"));
    }

    #[test]
    fn foreign_namespace_is_removed_in_every_spelling() {
        let m = b"x-FIRSTREAD-folder: inbox\r\nX-Firstread-Keywords : $IsTrusted\r\nX-Firstread-Folder\t: inbox\r\nX-FirstreadAnything: y\r\nFrom: a@example.org\r\n\r\nX-Firstread-Folder: junk\r\n";
        let out = strip_foreign(m, &p()).unwrap();
        assert_eq!(
            out,
            b"From: a@example.org\r\n\r\nX-Firstread-Folder: junk\r\n"
        );
    }

    #[test]
    fn strip_foreign_leaves_clean_messages_identical() {
        let m = b"Received: from mx\r\n by us\r\nFrom: a@example.org\r\n\r\nbody\r\n";
        assert_eq!(strip_foreign(m, &p()).unwrap(), m);
    }

    #[test]
    fn derived_folder_and_keyword_headers_are_written() {
        let d = Directive {
            keywords: vec![ImapKeyword::new("$Phishing").unwrap()],
            folder: Some(FolderKey::new("junk").unwrap()),
            ..Directive::default()
        };
        let out = apply(b"X-Firstread-Folder: inbox\nFrom: a\n\nb\n", &d, &p()).unwrap();
        assert_eq!(
            out,
            b"X-Firstread-Folder: junk\nX-Firstread-Keywords: $Phishing\nFrom: a\n\nb\n"
        );
    }

    #[test]
    fn invalid_directive_is_refused() {
        let d = Directive {
            add: vec![add("Bcc", "x@example.org")],
            ..Directive::default()
        };
        assert_eq!(
            apply(MSG, &d, &p()),
            Err(EditError::Invalid(DirectiveError::ForbiddenAddition(
                "Bcc".into()
            )))
        );
    }

    fn with_prefix(prefix: &str) -> Directive {
        Directive {
            subject_prefix: Some(HeaderValue::from_text(prefix)),
            ..Directive::default()
        }
    }

    #[test]
    fn subject_prefix_in_place_once() {
        let m = b"From: a\r\nSubject: =?UTF-8?B?w6lw?=\r\n folded\r\nTo: b\r\n\r\nx";
        let out = apply(m, &with_prefix("[Let op]"), &p()).unwrap();
        assert_eq!(
            out,
            b"From: a\r\nSubject: [Let op] =?UTF-8?B?w6lw?=\r\n folded\r\nTo: b\r\n\r\nx".to_vec()
        );
        assert_eq!(apply(&out, &with_prefix("[Let op]"), &p()).unwrap(), out);
    }

    #[test]
    fn subject_prefix_on_empty_missing_and_long_subjects() {
        let empty = apply(b"Subject:\r\n\r\nx", &with_prefix("[!]"), &p()).unwrap();
        assert_eq!(empty, b"Subject: [!]\r\n\r\nx");
        let missing = apply(b"From: a\r\n\r\nx", &with_prefix("[!]"), &p()).unwrap();
        assert_eq!(missing, b"Subject: [!]\r\nFrom: a\r\n\r\nx");
        let long = format!("Subject: {}\r\n\r\nx", "y".repeat(985));
        let out = apply(long.as_bytes(), &with_prefix("[Let op]"), &p()).unwrap();
        for line in out.split(|b| *b == b'\n') {
            assert!(line.len() <= MAX_LINE + 1);
        }
        assert!(out.starts_with(b"Subject: [Let op]\r\n y"));
    }

    #[test]
    fn lf_messages_stay_lf() {
        let m = b"From: a@example.org\nSubject: x\n\nbody\n";
        let out = apply(
            m,
            &Directive {
                add: vec![add("X-Firstread", "v=1")],
                ..Directive::default()
            },
            &p(),
        )
        .unwrap();
        assert_eq!(
            out,
            b"X-Firstread: v=1\nFrom: a@example.org\nSubject: x\n\nbody\n"
        );
    }

    #[test]
    fn nth_and_nth_from_end() {
        let m = b"Authentication-Results: a\r\nAuthentication-Results: b\r\nAuthentication-Results: c\r\n\r\nx";
        let first = apply(
            m,
            &Directive {
                remove: vec![remove("authentication-results", Which::Nth(1))],
                ..Directive::default()
            },
            &p(),
        )
        .unwrap();
        assert_eq!(
            first,
            b"Authentication-Results: b\r\nAuthentication-Results: c\r\n\r\nx"
        );
        let last = apply(
            m,
            &Directive {
                remove: vec![remove("Authentication-Results", Which::NthFromEnd(1))],
                ..Directive::default()
            },
            &p(),
        )
        .unwrap();
        assert_eq!(
            last,
            b"Authentication-Results: a\r\nAuthentication-Results: b\r\n\r\nx"
        );
        let none = apply(
            m,
            &Directive {
                remove: vec![remove("Authentication-Results", Which::Nth(9))],
                ..Directive::default()
            },
            &p(),
        )
        .unwrap();
        assert_eq!(none, m);
    }

    #[test]
    fn headers_only_message() {
        let m = b"From: a@example.org\r\nSubject: no body";
        let out = apply(
            m,
            &Directive {
                add: vec![add("X-Firstread", "v=1")],
                ..Directive::default()
            },
            &p(),
        )
        .unwrap();
        assert_eq!(
            out,
            b"X-Firstread: v=1\r\nFrom: a@example.org\r\nSubject: no body\r\n"
        );
    }

    #[test]
    fn no_line_ending_is_refused() {
        assert_eq!(
            apply(b"X-Firstread-Folder: inbox", &Directive::default(), &p()),
            Err(EditError::NoLineEnding)
        );
    }

    /// Deterministic pseudo-random messages and directives: the body must survive every time,
    /// nothing outside the directive may appear, and the only firstread headers left are ours.
    #[test]
    fn randomised_invariants() {
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let names = [
            "From",
            "To",
            "Subject",
            "X-Firstread",
            "x-firstread-scores",
            "X-Firstread-Folder ",
            "X-FIRSTREAD-KEYWORDS\t",
            "Received",
            "Authentication-Results",
        ];
        for _ in 0..2000 {
            let eol: &[u8] = if next() % 2 == 0 { b"\r\n" } else { b"\n" };
            let mut m = Vec::new();
            for _ in 0..(next() % 8) {
                m.extend_from_slice(names[(next() % names.len() as u64) as usize].as_bytes());
                m.extend_from_slice(b": v");
                if next() % 4 == 0 {
                    m.extend_from_slice(eol);
                    m.extend_from_slice(b"\tcontinued");
                }
                m.extend_from_slice(eol);
            }
            m.extend_from_slice(eol);
            for _ in 0..(next() % 64) {
                m.push((next() % 256) as u8);
            }
            let d = Directive {
                remove: vec![remove("Authentication-Results", Which::NthFromEnd(1))],
                add: vec![
                    add("X-Firstread", "v=1; id=st_x"),
                    add("X-Firstread-Reasons", "Let op\r\nBcc: evil@example.org"),
                ],
                subject_prefix: (next() % 2 == 0).then(|| HeaderValue::from_text("[Let op]")),
                keywords: vec![ImapKeyword::new("$Phishing").unwrap()],
                folder: Some(FolderKey::new("junk").unwrap()),
            };
            let out = apply(&m, &d, &p()).unwrap();
            assert_eq!(body_of(&out), body_of(&m), "body changed for {m:?}");
            let (fields, _) = split(&out);
            let mut ours = Vec::new();
            for f in &fields {
                if let Some(n) = f.name {
                    assert!(
                        !n.eq_ignore_ascii_case(b"Bcc"),
                        "injected header in {out:?}"
                    );
                    if p().owns(n) {
                        ours.push(String::from_utf8_lossy(f.raw).into_owned());
                    }
                }
            }
            assert_eq!(ours.len(), 4, "only our own four headers: {ours:?}");
            assert!(
                ours.iter()
                    .any(|h| h.starts_with("X-Firstread-Folder: junk"))
            );
        }
    }
}
