//! The wire between `firstread-filter` and `firstreadd` (docs/12-interfaces.md section 4.1).
//!
//! A request is one frame of JSON ([`Request`]) followed by the message bytes; the reply is one
//! frame of JSON ([`Reply`]). A frame is a 4-byte big-endian length and that many bytes. Nothing
//! here knows about sockets: it works on any `Read` / `Write`.
//!
//! The filter never trusts the daemon's reply: [`WireDirective::validate`] rebuilds the
//! [`Directive`] through the same validating constructors, so a daemon bug cannot produce an
//! unsafe header, a forbidden removal or an unknown folder.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::directive::{
    AddHeader, Directive, DirectiveError, FolderKey, HeaderName, HeaderValue, ImapKeyword,
    RemoveHeader, Which,
};

/// Largest JSON frame either side accepts.
pub const MAX_JSON_FRAME: u32 = 1 << 20;

/// Write one frame.
pub fn write_frame<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(bytes)
}

/// Read one frame of at most `max` bytes.
pub fn read_frame<R: Read>(r: &mut R, max: u32) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame larger than allowed",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// What the filter sends before the message bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Wire version.
    pub v: u8,
    /// `USER`.
    pub user: String,
    /// `SENDER`.
    pub sender: String,
    /// `RECIPIENT`.
    pub recipient: String,
    /// `ORIG_RECIPIENT`, when different.
    pub orig_recipient: Option<String>,
    /// Length of the message bytes that follow.
    pub message_len: u64,
}

/// One header removal on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRemove {
    /// Header name.
    pub name: String,
    /// 0 = all, n > 0 = n-th from the top, n < 0 = n-th from the end (Rspamd's convention).
    pub which: i32,
}

/// One header addition on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAdd {
    /// Header name.
    pub name: String,
    /// Header value, already encoded and unfolded.
    pub value: String,
}

/// The directive as it travels; plain strings until validated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDirective {
    /// Removals.
    pub remove: Vec<WireRemove>,
    /// Additions, in order.
    pub add: Vec<WireAdd>,
    /// Subject prefix.
    pub subject_prefix: Option<String>,
    /// Keywords.
    pub keywords: Vec<String>,
    /// Folder key.
    pub folder: Option<String>,
}

/// What the daemon replies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// Wire version.
    pub v: u8,
    /// The stamp id of this decision.
    pub stamp_id: String,
    /// The directive to apply.
    pub directive: WireDirective,
}

impl WireDirective {
    /// Rebuild a [`Directive`] through the validating constructors. Values use the strict
    /// constructor: the daemon must send values that are already safe.
    pub fn validate(&self) -> Result<Directive, DirectiveError> {
        let mut d = Directive::default();
        for r in &self.remove {
            let which = match r.which {
                0 => Which::All,
                n if n > 0 => Which::Nth(u16::try_from(n).unwrap_or(u16::MAX)),
                n => Which::NthFromEnd(u16::try_from(n.unsigned_abs()).unwrap_or(u16::MAX)),
            };
            d.remove.push(RemoveHeader {
                name: HeaderName::new(&r.name)?,
                which,
            });
        }
        for a in &self.add {
            d.add.push(AddHeader {
                name: HeaderName::new(&a.name)?,
                value: HeaderValue::new(&a.value)?,
            });
        }
        if let Some(p) = &self.subject_prefix {
            d.subject_prefix = Some(HeaderValue::new(p)?);
        }
        for k in &self.keywords {
            d.keywords.push(ImapKeyword::new(k)?);
        }
        if let Some(f) = &self.folder {
            d.folder = Some(FolderKey::new(f)?);
        }
        Ok(d)
    }

    /// The wire form of a directive.
    pub fn from_directive(d: &Directive) -> Self {
        Self {
            remove: d
                .remove
                .iter()
                .map(|r| WireRemove {
                    name: r.name.as_str().to_string(),
                    which: match r.which {
                        Which::All => 0,
                        Which::Nth(n) => i32::from(n),
                        Which::NthFromEnd(n) => -i32::from(n),
                    },
                })
                .collect(),
            add: d
                .add
                .iter()
                .map(|a| WireAdd {
                    name: a.name.as_str().to_string(),
                    value: a.value.as_str().to_string(),
                })
                .collect(),
            subject_prefix: d.subject_prefix.as_ref().map(|p| p.as_str().to_string()),
            keywords: d.keywords.iter().map(|k| k.as_str().to_string()).collect(),
            folder: d.folder.as_ref().map(|f| f.as_str().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_enforce_the_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(read_frame(&mut &buf[..], 16).unwrap(), b"hello");
        assert!(read_frame(&mut &buf[..], 4).is_err());
    }

    #[test]
    fn directive_round_trips_through_the_wire() {
        let d = Directive {
            remove: vec![RemoveHeader {
                name: HeaderName::new("Authentication-Results").unwrap(),
                which: Which::NthFromEnd(1),
            }],
            add: vec![AddHeader {
                name: HeaderName::new("X-Firstread").unwrap(),
                value: HeaderValue::from_text("v=1; verdict=junk"),
            }],
            subject_prefix: None,
            keywords: vec![ImapKeyword::new("$Junk").unwrap()],
            folder: Some(FolderKey::new("junk").unwrap()),
        };
        let w = WireDirective::from_directive(&d);
        let json = serde_json::to_string(&w).unwrap();
        let back: WireDirective = serde_json::from_str(&json).unwrap();
        assert_eq!(back.validate().unwrap(), d);
    }

    #[test]
    fn unsafe_wire_values_are_refused() {
        let bad = WireDirective {
            add: vec![WireAdd {
                name: "X-Firstread".into(),
                value: "x\r\nBcc: evil@example.org".into(),
            }],
            ..WireDirective::default()
        };
        assert_eq!(bad.validate(), Err(DirectiveError::ValueHasControl));
        let folder = WireDirective {
            folder: Some("../../etc".into()),
            ..WireDirective::default()
        };
        assert!(folder.validate().is_err());
    }
}
