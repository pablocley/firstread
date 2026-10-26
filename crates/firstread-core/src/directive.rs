//! The directive: firstread's only synchronous output (docs/12-interfaces.md, ADR-0011).
//!
//! A verdict is turned into a bounded list of edits that the host applies: remove headers in our own
//! namespace, add headers, prefix the Subject, set keywords, choose a folder key. Every piece is
//! validated on construction, so attacker-controlled text (display names, subjects) can never
//! become a new header line, and [`Directive::validate`] keeps the whole within a
//! [`DirectivePolicy`].
//!
//! The folder and keyword headers the Sieve script reads are never supplied as text: they are
//! rendered from the validated [`FolderKey`] and [`ImapKeyword`]s by [`Directive::derived_headers`].

use std::fmt;

/// RFC 5322: a line must not exceed 998 characters, excluding the line ending.
pub const MAX_LINE: usize = 998;
/// RFC 5322 recommends lines of at most 78 characters; we fold to this where whitespace allows.
pub const FOLD_AT: usize = 78;
/// Longest unbreakable token we will emit in a header value.
pub const MAX_TOKEN: usize = 200;
/// Default cap on the total size of headers firstread adds to one message.
pub const DEFAULT_MAX_ADDED_BYTES: usize = 4096;

/// Why a directive or one of its parts was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectiveError {
    /// Header name empty or longer than 76 characters.
    BadNameLength,
    /// Header name contains a byte outside RFC 5322 `ftext` (printable US-ASCII except `:`).
    BadNameChar(u8),
    /// Header value contains CR, LF or another control character.
    ValueHasControl,
    /// Header value contains non-ASCII text (use [`HeaderValue::from_text`] to encode it).
    ValueNotAscii,
    /// Header value contains a token longer than [`MAX_TOKEN`].
    ValueTokenTooLong,
    /// Not a valid IMAP keyword atom.
    BadKeyword(String),
    /// Not a valid folder key (`a`-`z` first, then `a`-`z`, `0`-`9`, `-`; at most 32).
    BadFolderKey(String),
    /// A removal targets a header firstread may not remove.
    ForbiddenRemoval(String),
    /// An addition targets a header outside firstread's namespace and the allowed list.
    ForbiddenAddition(String),
    /// An addition names a header that only [`Directive::derived_headers`] may write.
    ReservedHeader(String),
    /// The keyword belongs to the user (for example `$NotJunk`); firstread never sets it.
    ReservedKeyword(String),
    /// The folder key is not in the mailbox mode's allowed set.
    FolderNotAllowed(String),
    /// Subject prefix empty or longer than the policy allows.
    BadSubjectPrefix,
    /// Added headers exceed the configured size.
    TooLarge {
        /// Rendered size of the added headers.
        bytes: usize,
        /// Allowed maximum.
        max: usize,
    },
}

impl fmt::Display for DirectiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DirectiveError {}

/// A validated header field name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// Validate a header field name (RFC 5322 `ftext`, 1 to 76 characters).
    pub fn new(name: &str) -> Result<Self, DirectiveError> {
        if name.is_empty() || name.len() > 76 {
            return Err(DirectiveError::BadNameLength);
        }
        if let Some(b) = name.bytes().find(|b| !(33..=126).contains(b) || *b == b':') {
            return Err(DirectiveError::BadNameChar(b));
        }
        Ok(Self(name.to_string()))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive comparison with raw bytes from a message.
    pub fn matches(&self, raw: &[u8]) -> bool {
        self.0.as_bytes().eq_ignore_ascii_case(raw)
    }
}

/// A validated, unfolded header value: printable US-ASCII, spaces and tabs only, no long tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderValue(String);

impl HeaderValue {
    /// Strict constructor for values firstread builds itself. Rejects anything unsafe.
    pub fn new(value: &str) -> Result<Self, DirectiveError> {
        if value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || (b < 32 && b != b'\t') || b == 127)
        {
            return Err(DirectiveError::ValueHasControl);
        }
        if !value.is_ascii() {
            return Err(DirectiveError::ValueNotAscii);
        }
        if value.split([' ', '\t']).any(|t| t.len() > MAX_TOKEN) {
            return Err(DirectiveError::ValueTokenTooLong);
        }
        Ok(Self(value.to_string()))
    }

    /// Safe constructor for arbitrary text, including attacker-controlled text.
    ///
    /// Control characters (CR and LF included) become spaces, whitespace is collapsed, long tokens
    /// are cut, and anything non-ASCII is encoded as RFC 2047 encoded-words. The result can never
    /// contain a line break, so it can never start a new header.
    pub fn from_text(text: &str) -> Self {
        let cleaned: String = text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let mut words: Vec<String> = Vec::new();
        for token in cleaned.split_whitespace() {
            if token.is_ascii() {
                if token.len() > MAX_TOKEN {
                    words.push(format!("{}...", &token[..MAX_TOKEN - 3]));
                } else {
                    words.push(token.to_string());
                }
            } else {
                words.extend(encode_words(token));
            }
        }
        Self(words.join(" "))
    }

    /// The value as written (unfolded).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 2047 "B" encoded-words for one non-ASCII token, each at most 75 characters, split on
/// UTF-8 character boundaries.
fn encode_words(token: &str) -> Vec<String> {
    const PREFIX: &str = "=?UTF-8?B?";
    const SUFFIX: &str = "?=";
    // 75 - prefix - suffix = 63 base64 characters, i.e. at most 45 input bytes (multiple of 3).
    const MAX_CHUNK: usize = 45;
    let mut out = Vec::new();
    let mut chunk = String::new();
    for c in token.chars() {
        if chunk.len() + c.len_utf8() > MAX_CHUNK {
            out.push(format!("{PREFIX}{}{SUFFIX}", base64(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        out.push(format!("{PREFIX}{}{SUFFIX}", base64(chunk.as_bytes())));
    }
    out
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Which instances of a header to remove, in the same terms as Rspamd's `remove_headers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// Every instance.
    All,
    /// The n-th instance from the top, 1-based.
    Nth(u16),
    /// The n-th instance from the bottom, 1-based.
    NthFromEnd(u16),
}

/// Remove header instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveHeader {
    /// Header name.
    pub name: HeaderName,
    /// Which instances.
    pub which: Which,
}

/// Add one header at the top of the header block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddHeader {
    /// Header name.
    pub name: HeaderName,
    /// Header value.
    pub value: HeaderValue,
}

impl AddHeader {
    /// Render as one header field, folded at whitespace, ending in `eol`.
    pub fn render(&self, eol: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut line_len = self.name.0.len() + 1;
        out.extend_from_slice(self.name.0.as_bytes());
        out.push(b':');
        for word in self.value.0.split([' ', '\t']).filter(|w| !w.is_empty()) {
            if line_len + 1 + word.len() > FOLD_AT && line_len > self.name.0.len() + 1 {
                out.extend_from_slice(eol);
                line_len = 0;
            }
            out.push(b' ');
            out.extend_from_slice(word.as_bytes());
            line_len += 1 + word.len();
        }
        out.extend_from_slice(eol);
        out
    }
}

/// A validated IMAP keyword (an IMAP `atom`, not a system flag).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImapKeyword(String);

impl ImapKeyword {
    /// Validate: 1 to 100 printable ASCII characters, none of `( ) { % * " \ ]` or space.
    pub fn new(k: &str) -> Result<Self, DirectiveError> {
        let ok = !k.is_empty()
            && k.len() <= 100
            && k.bytes()
                .all(|b| (33..=126).contains(&b) && !b"(){%*\"\\]".contains(&b));
        if ok {
            Ok(Self(k.to_string()))
        } else {
            Err(DirectiveError::BadKeyword(k.to_string()))
        }
    }

    /// The keyword as sent to the IMAP server.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A folder key: a stable token for one of the mode's folders (`junk`, `later`, `orders`).
///
/// The Sieve script maps each allowed key to a real folder with a literal `fileinto`, so a folder
/// name never comes from a header or a variable, and localised folder names ("Ongewenst") live in
/// the script, not in firstread.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FolderKey(String);

impl FolderKey {
    /// Validate: 1 to 32 bytes, a lowercase letter first, then lowercase letters, digits or `-`.
    pub fn new(k: &str) -> Result<Self, DirectiveError> {
        let b = k.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 32
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
        if ok {
            Ok(Self(k.to_string()))
        } else {
            Err(DirectiveError::BadFolderKey(k.to_string()))
        }
    }

    /// The key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the host must do with one delivered message. Nothing here can change the body, discard
/// the message or change its recipients.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Directive {
    /// Headers to remove (own namespace and untrusted `Authentication-Results` only). Headers in
    /// the own namespace that arrived with the message are removed whether listed here or not.
    pub remove: Vec<RemoveHeader>,
    /// Headers to add at the top, in this order.
    pub add: Vec<AddHeader>,
    /// Text put in front of the Subject, once, in place (POP3 warnings, strict thresholds).
    pub subject_prefix: Option<HeaderValue>,
    /// Keywords to set.
    pub keywords: Vec<ImapKeyword>,
    /// Folder key to file into; `None` means firstread has no opinion (INBOX, or the user's rules).
    pub folder: Option<FolderKey>,
}

/// Deployment limits a directive must respect.
#[derive(Debug, Clone)]
pub struct DirectivePolicy {
    /// Header-name prefix firstread owns (case-insensitive), e.g. `X-Firstread`. Must itself be a
    /// valid header name.
    pub own_prefix: String,
    /// Other headers firstread may remove (e.g. `Authentication-Results` claiming our authserv-id).
    pub also_removable: Vec<HeaderName>,
    /// Other headers firstread may add (e.g. `Authentication-Results`; `X-Spam-*` in compatibility
    /// mode only).
    pub also_addable: Vec<HeaderName>,
    /// Keywords that belong to the user and are read as feedback; firstread never sets them.
    pub reserved_keywords: Vec<ImapKeyword>,
    /// Folder keys the mailbox mode allows; the Sieve script has one literal `fileinto` per key.
    pub allowed_folders: Vec<FolderKey>,
    /// Longest Subject prefix, in bytes as written (one RFC 2047 encoded-word fits in 75).
    pub max_subject_prefix: usize,
    /// Cap on the total rendered size of added headers.
    pub max_added_bytes: usize,
}

impl Default for DirectivePolicy {
    fn default() -> Self {
        Self {
            own_prefix: "X-Firstread".to_string(),
            also_removable: vec![HeaderName("Authentication-Results".to_string())],
            also_addable: vec![HeaderName("Authentication-Results".to_string())],
            reserved_keywords: vec![ImapKeyword("$NotJunk".to_string())],
            allowed_folders: vec![
                FolderKey("inbox".to_string()),
                FolderKey("junk".to_string()),
            ],
            max_subject_prefix: 75,
            max_added_bytes: DEFAULT_MAX_ADDED_BYTES,
        }
    }
}

impl DirectivePolicy {
    /// Whether a raw header name from a message is in firstread's namespace (case-insensitive
    /// prefix match, so every `X-Firstread-*` variant counts).
    pub fn owns(&self, raw: &[u8]) -> bool {
        let p = self.own_prefix.as_bytes();
        raw.len() >= p.len() && raw[..p.len()].eq_ignore_ascii_case(p)
    }

    /// The header the Sieve script reads the folder key from.
    pub fn folder_header(&self) -> HeaderName {
        HeaderName(format!("{}-Folder", self.own_prefix))
    }

    /// The header the Sieve script reads the keywords from.
    pub fn keywords_header(&self) -> HeaderName {
        HeaderName(format!("{}-Keywords", self.own_prefix))
    }
}

impl Directive {
    /// The folder and keyword headers, rendered from the validated fields. These are the only
    /// way those two headers are ever written.
    pub fn derived_headers(&self, policy: &DirectivePolicy) -> Vec<AddHeader> {
        let mut out = Vec::new();
        if let Some(f) = &self.folder {
            out.push(AddHeader {
                name: policy.folder_header(),
                value: HeaderValue(f.0.clone()),
            });
        }
        if !self.keywords.is_empty() {
            let list: Vec<&str> = self.keywords.iter().map(ImapKeyword::as_str).collect();
            out.push(AddHeader {
                name: policy.keywords_header(),
                value: HeaderValue(list.join(" ")),
            });
        }
        out
    }

    /// Total bytes the directive adds with CRLF line endings: added and derived headers, plus
    /// the Subject prefix and its separating space.
    pub fn added_bytes(&self, policy: &DirectivePolicy) -> usize {
        let headers: usize = self
            .add
            .iter()
            .chain(self.derived_headers(policy).iter())
            .map(|h| h.render(b"\r\n").len())
            .sum();
        headers + self.subject_prefix.as_ref().map_or(0, |p| p.0.len() + 1)
    }

    /// Check every part against the policy: removals and additions stay in the allowed names,
    /// derived headers are not supplied by hand, no user-owned keyword, an allowed folder key, a
    /// short Subject prefix, and the size cap.
    pub fn validate(&self, policy: &DirectivePolicy) -> Result<(), DirectiveError> {
        let listed =
            |list: &[HeaderName], n: &str| list.iter().any(|a| a.0.eq_ignore_ascii_case(n));
        for r in &self.remove {
            let n = r.name.as_str();
            if !policy.owns(n.as_bytes()) && !listed(&policy.also_removable, n) {
                return Err(DirectiveError::ForbiddenRemoval(n.to_string()));
            }
        }
        let derived = [policy.folder_header(), policy.keywords_header()];
        for a in &self.add {
            let n = a.name.as_str();
            if !policy.owns(n.as_bytes()) && !listed(&policy.also_addable, n) {
                return Err(DirectiveError::ForbiddenAddition(n.to_string()));
            }
            if listed(&derived, n) {
                return Err(DirectiveError::ReservedHeader(n.to_string()));
            }
        }
        for k in &self.keywords {
            if policy
                .reserved_keywords
                .iter()
                .any(|r| r.0.eq_ignore_ascii_case(&k.0))
            {
                return Err(DirectiveError::ReservedKeyword(k.0.clone()));
            }
        }
        if let Some(f) = &self.folder
            && !policy.allowed_folders.contains(f)
        {
            return Err(DirectiveError::FolderNotAllowed(f.0.clone()));
        }
        if let Some(p) = &self.subject_prefix
            && (p.0.is_empty() || p.0.len() > policy.max_subject_prefix)
        {
            return Err(DirectiveError::BadSubjectPrefix);
        }
        let bytes = self.added_bytes(policy);
        if bytes > policy.max_added_bytes {
            return Err(DirectiveError::TooLarge {
                bytes,
                max: policy.max_added_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_names_follow_rfc5322() {
        assert!(HeaderName::new("X-Firstread").is_ok());
        assert_eq!(
            HeaderName::new("Bad Name"),
            Err(DirectiveError::BadNameChar(b' '))
        );
        assert_eq!(
            HeaderName::new("Bad:Name"),
            Err(DirectiveError::BadNameChar(b':'))
        );
        assert_eq!(HeaderName::new(""), Err(DirectiveError::BadNameLength));
    }

    #[test]
    fn strict_values_reject_line_breaks_and_non_ascii() {
        assert_eq!(
            HeaderValue::new("a\r\nBcc: x@example.org"),
            Err(DirectiveError::ValueHasControl)
        );
        assert_eq!(HeaderValue::new("café"), Err(DirectiveError::ValueNotAscii));
    }

    #[test]
    fn untrusted_text_cannot_inject_a_header() {
        let v = HeaderValue::from_text("Maarten\r\nBcc: attacker@example.org\n\tX: y");
        assert!(!v.as_str().contains('\r') && !v.as_str().contains('\n'));
        let rendered = AddHeader {
            name: HeaderName::new("X-Firstread-Reasons").unwrap(),
            value: v,
        }
        .render(b"\r\n");
        // Every continuation line must start with whitespace: no new field can begin.
        for line in rendered.split(|b| *b == b'\n').skip(1) {
            assert!(line.is_empty() || line[0] == b' ' || line[0] == b'\t');
        }
    }

    #[test]
    fn non_ascii_is_encoded_and_round_trips() {
        let v = HeaderValue::from_text("Eerste keer dat je mail krijgt van dit adres — let op");
        assert!(v.as_str().is_ascii());
        assert!(v.as_str().contains("=?UTF-8?B?"));
        for w in v.as_str().split(' ') {
            assert!(w.len() <= 75);
        }
    }

    #[test]
    fn long_values_fold_and_never_exceed_998() {
        let text = "woord ".repeat(400);
        let h = AddHeader {
            name: HeaderName::new("X-Firstread-Reasons").unwrap(),
            value: HeaderValue::from_text(&text),
        };
        let r = h.render(b"\r\n");
        for line in r.split(|b| *b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(line.len() <= FOLD_AT, "line of {} bytes", line.len());
            assert!(line.len() <= MAX_LINE);
        }
    }

    #[test]
    fn keywords_are_atoms() {
        assert!(ImapKeyword::new("$Phishing").is_ok());
        assert!(ImapKeyword::new("fr-money").is_ok());
        assert!(ImapKeyword::new("two words").is_err());
        assert!(ImapKeyword::new("\\Seen").is_err());
        assert!(ImapKeyword::new("a]b").is_err());
    }

    #[test]
    fn removals_limited_to_own_namespace() {
        let p = DirectivePolicy::default();
        let ok = Directive {
            remove: vec![
                RemoveHeader {
                    name: HeaderName::new("x-firstread-scores").unwrap(),
                    which: Which::All,
                },
                RemoveHeader {
                    name: HeaderName::new("Authentication-Results").unwrap(),
                    which: Which::Nth(1),
                },
            ],
            ..Directive::default()
        };
        assert!(ok.validate(&p).is_ok());
        let bad = Directive {
            remove: vec![RemoveHeader {
                name: HeaderName::new("DKIM-Signature").unwrap(),
                which: Which::All,
            }],
            ..Directive::default()
        };
        assert_eq!(
            bad.validate(&p),
            Err(DirectiveError::ForbiddenRemoval("DKIM-Signature".into()))
        );
    }

    #[test]
    fn size_cap_enforced() {
        let p = DirectivePolicy {
            max_added_bytes: 64,
            ..DirectivePolicy::default()
        };
        let d = Directive {
            add: vec![AddHeader {
                name: HeaderName::new("X-Firstread").unwrap(),
                value: HeaderValue::from_text(&"x ".repeat(100)),
            }],
            ..Directive::default()
        };
        assert!(matches!(
            d.validate(&p),
            Err(DirectiveError::TooLarge { .. })
        ));
    }

    fn header(name: &str, value: &str) -> AddHeader {
        AddHeader {
            name: HeaderName::new(name).unwrap(),
            value: HeaderValue::from_text(value),
        }
    }

    #[test]
    fn additions_limited_to_own_namespace_and_list() {
        let p = DirectivePolicy::default();
        let ok = Directive {
            add: vec![
                header("X-Firstread", "v=1"),
                header("Authentication-Results", "mx.example.nl; spf=pass"),
            ],
            ..Directive::default()
        };
        assert!(ok.validate(&p).is_ok());
        for name in ["Bcc", "Reply-To", "Subject", "X-Spam-Flag"] {
            let bad = Directive {
                add: vec![header(name, "x")],
                ..Directive::default()
            };
            assert_eq!(
                bad.validate(&p),
                Err(DirectiveError::ForbiddenAddition(name.into()))
            );
        }
    }

    #[test]
    fn folder_and_keyword_headers_cannot_be_supplied_by_hand() {
        let p = DirectivePolicy::default();
        for name in ["X-Firstread-Folder", "x-firstread-keywords"] {
            let d = Directive {
                add: vec![header(name, "junk")],
                ..Directive::default()
            };
            assert_eq!(
                d.validate(&p),
                Err(DirectiveError::ReservedHeader(name.into()))
            );
        }
    }

    #[test]
    fn derived_headers_come_from_validated_fields() {
        let p = DirectivePolicy::default();
        let d = Directive {
            keywords: vec![
                ImapKeyword::new("$Phishing").unwrap(),
                ImapKeyword::new("fr-money").unwrap(),
            ],
            folder: Some(FolderKey::new("junk").unwrap()),
            ..Directive::default()
        };
        let rendered: Vec<Vec<u8>> = d
            .derived_headers(&p)
            .iter()
            .map(|h| h.render(b"\r\n"))
            .collect();
        assert_eq!(
            rendered,
            vec![
                b"X-Firstread-Folder: junk\r\n".to_vec(),
                b"X-Firstread-Keywords: $Phishing fr-money\r\n".to_vec()
            ]
        );
    }

    #[test]
    fn user_owned_keywords_are_never_set() {
        let p = DirectivePolicy::default();
        let d = Directive {
            keywords: vec![ImapKeyword::new("$notjunk").unwrap()],
            ..Directive::default()
        };
        assert_eq!(
            d.validate(&p),
            Err(DirectiveError::ReservedKeyword("$notjunk".into()))
        );
    }

    #[test]
    fn folder_keys_are_tokens_from_the_allowed_set() {
        assert!(FolderKey::new("junk").is_ok());
        assert!(FolderKey::new("cat-orders2").is_ok());
        for bad in [
            "",
            "Junk",
            "2later",
            "a b",
            "INBOX/../x",
            "x\r\ny",
            &"a".repeat(33),
        ] {
            assert!(FolderKey::new(bad).is_err(), "{bad:?} accepted");
        }
        let p = DirectivePolicy::default();
        let d = Directive {
            folder: Some(FolderKey::new("later").unwrap()),
            ..Directive::default()
        };
        assert_eq!(
            d.validate(&p),
            Err(DirectiveError::FolderNotAllowed("later".into()))
        );
    }

    #[test]
    fn subject_prefix_is_short_and_non_empty() {
        let p = DirectivePolicy::default();
        let ok = Directive {
            subject_prefix: Some(HeaderValue::from_text("[Let op]")),
            ..Directive::default()
        };
        assert!(ok.validate(&p).is_ok());
        for bad in ["", &"x".repeat(76)] {
            let d = Directive {
                subject_prefix: Some(HeaderValue::from_text(bad)),
                ..Directive::default()
            };
            assert_eq!(d.validate(&p), Err(DirectiveError::BadSubjectPrefix));
        }
    }
}
