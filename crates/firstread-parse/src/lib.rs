//! MIME to a normalised [`firstread_core::mail::MailState`], plus the structural facts tier 0
//! needs.
//!
//! - hostile input within hard limits: messages above [`MAX_MESSAGE_BYTES`] are parsed only up to
//!   the limit and marked truncated; text is capped at [`MAX_TEXT_CHARS`]
//! - headers and display names decoded by `mail-parser` (Stalwart Labs, pinned `=0.11.9`);
//!   plain text from the text part, or from HTML when there is none
//! - quoted earlier messages (lines starting with `>`) kept apart from new text
//! - links in document order, from HTML anchors (with their visible text) and from plain text;
//!   never fetched
//! - attachment metadata only; nothing is executed or rendered
//!
//! On a message `mail-parser` cannot parse at all this returns an error, never a guess.

use firstread_core::mail::{Attachment, Link, MailState, NamedAddress};
use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders, PartType};

/// Largest number of message bytes parsed; the rest is ignored and the result says so.
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
/// Largest number of characters of new text kept.
pub const MAX_TEXT_CHARS: usize = 100_000;
/// Largest number of links kept.
pub const MAX_LINKS: usize = 500;

/// Why a message could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The parser found no message at all.
    NotAMessage,
}

/// Everything parsing found out.
#[derive(Debug, Clone, Default)]
pub struct Parsed {
    /// The normalised view shared by every signal.
    pub state: MailState,
    /// The first HTML body, if any (raw HTML text, decoded).
    pub html: Option<String>,
    /// Whether a text/plain body exists.
    pub has_text_part: bool,
    /// Whether a text/html body exists.
    pub has_html_part: bool,
    /// `List-Id`, if present.
    pub list_id: Option<String>,
    /// Whether `List-Unsubscribe` is present.
    pub list_unsubscribe: bool,
    /// Whether `List-Unsubscribe-Post` (RFC 8058 one-click) is present.
    pub list_unsubscribe_post: bool,
    /// Raw `Authentication-Results` values, top first.
    pub auth_results: Vec<String>,
    /// Number of `Received` fields.
    pub received_count: usize,
    /// `Date`, as Unix seconds, if parseable.
    pub date: Option<i64>,
    /// Number of header fields.
    pub header_count: usize,
    /// Whether `In-Reply-To` or `References` is present.
    pub is_reply: bool,
    /// Message-IDs named in `In-Reply-To` and `References`, without angle brackets, at most
    /// [`MAX_THREAD_IDS`].
    pub thread_ids: Vec<String>,
    /// `To`, `Cc` and `Bcc` addresses, lowercased, at most [`MAX_RECIPIENTS`] (a Sent copy's
    /// recipients are who the mailbox owner wrote to).
    pub recipients: Vec<NamedAddress>,
    /// Whether the input was longer than [`MAX_MESSAGE_BYTES`].
    pub truncated: bool,
}

fn first_address(a: Option<&Address<'_>>) -> Option<NamedAddress> {
    let addr = a?.first()?;
    Some(NamedAddress {
        name: addr.name().map(str::to_string),
        address: addr.address().unwrap_or_default().to_ascii_lowercase(),
    })
}

fn all_addresses(a: Option<&Address<'_>>) -> Vec<NamedAddress> {
    a.map(|a| {
        a.iter()
            .map(|addr| NamedAddress {
                name: addr.name().map(str::to_string),
                address: addr.address().unwrap_or_default().to_ascii_lowercase(),
            })
            .collect()
    })
    .unwrap_or_default()
}

/// Most Message-IDs kept from `In-Reply-To` and `References`.
pub const MAX_THREAD_IDS: usize = 50;
/// Most recipient addresses kept.
pub const MAX_RECIPIENTS: usize = 100;

fn ids(v: &HeaderValue<'_>) -> Vec<String> {
    v.as_text_list()
        .map(|l| {
            l.iter()
                .map(|s| s.trim().trim_matches(['<', '>']).to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn header_present(v: &HeaderValue<'_>) -> bool {
    !matches!(v, HeaderValue::Empty)
}

fn header_text(v: &HeaderValue<'_>) -> Option<String> {
    match v {
        HeaderValue::Text(t) => Some(t.to_string()),
        HeaderValue::TextList(l) => l.first().map(|t| t.to_string()),
        _ => None,
    }
}

/// Split plain text into new text and quoted earlier messages.
fn split_quoted(text: &str) -> (String, String) {
    let mut new = String::new();
    let mut quoted = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with('>') {
            quoted.push_str(line);
            quoted.push('\n');
        } else {
            new.push_str(line);
            new.push('\n');
        }
    }
    (new, quoted)
}

fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s.to_string(),
    }
}

fn is_url_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}'
        )
}

/// URLs written in plain text, in order.
pub fn text_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut i = 0;
    while let Some(off) = lower[i..].find("http") {
        let start = i + off;
        let rest = &lower[start..];
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let end = text[start..]
                .char_indices()
                .find(|(_, c)| !is_url_char(*c))
                .map_or(text.len(), |(j, _)| start + j);
            let url = text[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?']);
            if url.len() > "https://".len() {
                out.push(url.to_string());
            }
            i = end.max(start + 1);
        } else {
            i = start + 4;
        }
        if out.len() >= MAX_LINKS {
            break;
        }
    }
    out
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Anchors in HTML: target and visible text, in order. A small scanner, not a full HTML parser:
/// it reads `href` from `<a` tags and the text up to the next `</a`.
pub fn html_links(html: &str) -> Vec<Link> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = lower[i..].find("<a") {
        let tag_start = i + off;
        let Some(tag_len) = lower[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + tag_len;
        let tag = &html[tag_start..tag_end];
        let tag_lower = &lower[tag_start..tag_end];
        let href = tag_lower.find("href").and_then(|h| {
            let after = &tag[h + 4..];
            let after = after.trim_start().strip_prefix('=')?.trim_start();
            let (q, body) = match after.chars().next()? {
                '"' => ('"', &after[1..]),
                '\'' => ('\'', &after[1..]),
                _ => (' ', after),
            };
            let end = body.find(q).unwrap_or(body.len());
            Some(body[..end].trim().to_string())
        });
        let close = lower[tag_end..]
            .find("</a")
            .map_or(html.len(), |c| tag_end + c);
        let text = strip_tags(&html[(tag_end + 1).min(close)..close]);
        if let Some(href) = href.filter(|h| !h.is_empty()) {
            out.push(Link {
                href,
                text: Some(text).filter(|t| !t.is_empty()),
            });
        }
        i = close.max(tag_end + 1);
        if out.len() >= MAX_LINKS {
            break;
        }
    }
    out
}

/// Parse one message.
pub fn parse(raw: &[u8]) -> Result<Parsed, ParseError> {
    let truncated = raw.len() > MAX_MESSAGE_BYTES;
    let raw = &raw[..raw.len().min(MAX_MESSAGE_BYTES)];
    let msg = MessageParser::default()
        .parse(raw)
        .ok_or(ParseError::NotAMessage)?;
    if msg.headers().is_empty() {
        return Err(ParseError::NotAMessage);
    }

    let mut text = String::new();
    for i in 0..msg
        .text_body_count()
        .max(usize::from(msg.html_body_count() > 0))
    {
        if let Some(t) = msg.body_text(i) {
            text.push_str(&t);
            text.push('\n');
        }
        if text.len() > MAX_TEXT_CHARS * 4 {
            break;
        }
    }
    let html = msg.body_html(0).map(|h| h.to_string());
    let (new_text, quoted) = split_quoted(&text);

    let mut links: Vec<Link> = html.as_deref().map(html_links).unwrap_or_default();
    if links.is_empty() {
        links = text_urls(&new_text)
            .into_iter()
            .map(|href| Link { href, text: None })
            .collect();
    }

    let attachments = msg
        .attachments()
        .map(|p| {
            let declared_type = p
                .content_type()
                .map(|ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_string(),
                })
                .unwrap_or_default()
                .to_ascii_lowercase();
            Attachment {
                filename: p.attachment_name().map(str::to_string),
                declared_type,
                sniffed_type: None,
                size: p.contents().len() as u64,
            }
        })
        .collect();

    let has_html_part = msg
        .html_bodies()
        .any(|p| matches!(p.body, PartType::Html(_)));
    let has_text_part = msg
        .text_bodies()
        .any(|p| matches!(p.body, PartType::Text(_)));

    let state = MailState {
        from: first_address(msg.from()),
        reply_to: all_addresses(msg.reply_to()),
        subject: msg.subject().map(str::to_string),
        message_id: msg.message_id().map(str::to_string),
        text: truncate_chars(&new_text, MAX_TEXT_CHARS),
        quoted_text: truncate_chars(&quoted, MAX_TEXT_CHARS),
        links,
        attachments,
        language: None,
        size: raw.len() as u64,
    };

    let auth_results = msg
        .headers()
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case("Authentication-Results"))
        .filter_map(|h| header_text(h.value()))
        .collect();

    Ok(Parsed {
        html,
        has_text_part,
        has_html_part,
        // mail-parser reads List-Id as an address list, so take the raw value (RFC 2919:
        // an optional phrase and the list id in angle brackets).
        list_id: msg
            .header_raw("List-Id")
            .map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|v| !v.is_empty()),
        list_unsubscribe: header_present(msg.list_unsubscribe()),
        list_unsubscribe_post: msg
            .headers()
            .iter()
            .any(|h| h.name().eq_ignore_ascii_case("List-Unsubscribe-Post")),
        auth_results,
        received_count: msg.received_all().count(),
        date: msg.date().map(|d| d.to_timestamp()),
        header_count: msg.headers().len(),
        is_reply: header_present(msg.in_reply_to()) || header_present(msg.references()),
        thread_ids: {
            let mut t = ids(msg.in_reply_to());
            for r in ids(msg.references()) {
                if !t.contains(&r) {
                    t.push(r);
                }
            }
            t.truncate(MAX_THREAD_IDS);
            t
        },
        recipients: {
            let mut r = all_addresses(msg.to());
            r.extend(all_addresses(msg.cc()));
            r.extend(all_addresses(msg.bcc()));
            r.retain(|a| !a.address.is_empty());
            r.truncate(MAX_RECIPIENTS);
            r
        },
        truncated,
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &[u8] = b"From: \"Jan de Vries\" <Jan@Example.NL>\r\nReply-To: other@free.example\r\nTo: you@example.org\r\nSubject: =?UTF-8?Q?Factuur_m=C3=A4rz?=\r\nDate: Thu, 22 Oct 2026 10:45:15 +0200\r\nMessage-ID: <a@b>\r\nAuthentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.nl\r\n\r\nHallo,\r\nzie https://example.nl/factuur?id=1.\r\n> oud bericht\r\n";

    #[test]
    fn list_id_is_read() {
        let p = parse(b"From: a@x.example\r\nList-Id: Dev list <dev.lists.example>\r\nSubject: x\r\n\r\nx\r\n").unwrap();
        assert_eq!(p.list_id.as_deref(), Some("Dev list <dev.lists.example>"));
        let q = parse(b"From: a@x.example\r\nList-Id: <dev.lists.example>\r\n\r\nx\r\n").unwrap();
        assert_eq!(q.list_id.as_deref(), Some("<dev.lists.example>"));
        assert!(
            parse(b"From: a@x.example\r\n\r\nx\r\n")
                .unwrap()
                .list_id
                .is_none()
        );
    }

    #[test]
    fn thread_ids_and_recipients() {
        let p = parse(b"From: a@x.example\r\nTo: B <b@Y.example>, c@z.example\r\nCc: d@z.example\r\nIn-Reply-To: <m1@x.example>\r\nReferences: <m0@x.example> <m1@x.example>\r\nSubject: Re: hoi\r\n\r\nja\r\n").unwrap();
        assert_eq!(p.thread_ids, vec!["m1@x.example", "m0@x.example"]);
        let r: Vec<&str> = p.recipients.iter().map(|a| a.address.as_str()).collect();
        assert_eq!(r, vec!["b@y.example", "c@z.example", "d@z.example"]);
        let q = parse(b"From: a@x.example\r\nSubject: nieuw\r\n\r\nja\r\n").unwrap();
        assert!(q.thread_ids.is_empty() && q.recipients.is_empty() && !q.is_reply);
    }

    #[test]
    fn plain_message_fields() {
        let p = parse(PLAIN).unwrap();
        let from = p.state.from.unwrap();
        assert_eq!(from.address, "jan@example.nl");
        assert_eq!(from.name.as_deref(), Some("Jan de Vries"));
        assert_eq!(p.state.reply_to[0].address, "other@free.example");
        assert_eq!(p.state.subject.as_deref(), Some("Factuur märz"));
        assert!(p.state.text.contains("zie https://example.nl"));
        assert!(p.state.quoted_text.contains("oud bericht"));
        assert!(!p.state.text.contains("oud bericht"));
        assert_eq!(p.state.links[0].href, "https://example.nl/factuur?id=1");
        assert_eq!(p.auth_results.len(), 1);
        assert!(p.date.is_some());
    }

    #[test]
    fn html_links_keep_their_visible_text() {
        let links = html_links(
            r#"<p>Log in: <a class="x" href="https://evil.example/login">https://www.ing.nl</a> or <A HREF='http://t.co/x'>hier</A></p>"#,
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].href, "https://evil.example/login");
        assert_eq!(links[0].text.as_deref(), Some("https://www.ing.nl"));
        assert_eq!(links[1].text.as_deref(), Some("hier"));
    }

    #[test]
    fn html_only_message_gets_text() {
        let m = b"From: a@example.org\r\nSubject: x\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>Uw pakket <b>wacht</b></p><a href=\"https://x.example\">klik</a></body></html>\r\n";
        let p = parse(m).unwrap();
        assert!(p.has_html_part);
        assert!(p.state.text.contains("pakket"));
        assert_eq!(p.state.links.len(), 1);
    }

    #[test]
    fn garbage_is_an_error_not_a_guess() {
        assert!(parse(b"").is_err());
    }

    #[test]
    fn text_urls_stop_at_delimiters() {
        assert_eq!(
            text_urls("see <https://a.example/x>, and http://b.example."),
            vec!["https://a.example/x", "http://b.example"]
        );
    }
}
