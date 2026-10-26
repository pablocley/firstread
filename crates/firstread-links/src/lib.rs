//! Static analysis of links and sender names. Nothing here fetches anything.
//!
//! Implemented so far:
//! - URL host and registrable domain (Mozilla's Public Suffix List via the `psl` crate)
//! - IP-literal, shortener (from `data/shorteners.txt`) and punycode detection
//! - link text vs target mismatch: the visible text names a domain other than the target's
//! - display-name spoofing of the simplest kind: an address in the display name that is not the
//!   sender's address
//! - IBAN detection with the mod-97 check (ISO 13616)
//!
//! Still to build (docs/02-signals.md): lookalike domains against known domains, brand
//! impersonation from a brand data file, BSN, payment cards, OTP codes, dates and amounts.

use std::collections::BTreeSet;

use firstread_core::mail::{Link, NamedAddress};

const SHORTENERS: &str = include_str!("../data/shorteners.txt");

fn shorteners() -> impl Iterator<Item = &'static str> {
    SHORTENERS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The host of a URL, lowercased, without port, userinfo or a trailing dot.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| h.trim_start_matches('['))?
    } else {
        host.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// The registrable domain of a host, or the host itself when the list has no answer.
pub fn registrable(host: &str) -> String {
    psl::domain_str(host).unwrap_or(host).to_string()
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// A domain-looking token in visible link text (`www.ing.nl`, `https://ing.nl/x`).
fn domain_in_text(text: &str) -> Option<String> {
    let t = text.trim();
    let candidate = if t.contains("://") {
        url_host(t)?
    } else {
        let first = t.split_whitespace().next()?;
        let first = first.trim_end_matches(['.', ',', ';', ':', '/']);
        if first.contains('.')
            && !first.contains('@')
            && first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            first.to_ascii_lowercase()
        } else {
            return None;
        }
    };
    let reg = registrable(&candidate);
    psl::suffix_str(&candidate).filter(|s| s.contains('.') || s.len() >= 2)?;
    Some(reg)
}

/// Facts about the links of one message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkFacts {
    /// Number of links.
    pub count: usize,
    /// Number of distinct registrable domains.
    pub domains: usize,
    /// Links whose host is an IP address.
    pub ip_literals: usize,
    /// Links to a known shortener.
    pub shorteners: usize,
    /// Links whose host contains a punycode label.
    pub punycode: usize,
    /// Links whose visible text names another registrable domain than the target.
    pub text_target_mismatch: usize,
    /// Links whose registrable domain differs from the sender's.
    pub foreign_to_sender: usize,
    /// Links using plain `http`.
    pub plain_http: usize,
}

/// Analyse links against the sender's registrable domain.
pub fn analyse(links: &[Link], sender_domain: Option<&str>) -> LinkFacts {
    let mut f = LinkFacts::default();
    let mut domains = BTreeSet::new();
    let sender_reg = sender_domain.map(registrable);
    for l in links {
        let href = l.href.trim();
        let lower = href.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            continue;
        }
        let Some(host) = url_host(href) else { continue };
        f.count += 1;
        if lower.starts_with("http://") {
            f.plain_http += 1;
        }
        let ip = is_ip_literal(&host);
        let reg = if ip { host.clone() } else { registrable(&host) };
        if ip {
            f.ip_literals += 1;
        } else {
            if host.split('.').any(|label| label.starts_with("xn--")) {
                f.punycode += 1;
            }
            if shorteners().any(|s| s == reg) {
                f.shorteners += 1;
            }
        }
        if let Some(text_domain) = l.text.as_deref().and_then(domain_in_text)
            && text_domain != reg
        {
            f.text_target_mismatch += 1;
        }
        if sender_reg.as_deref().is_some_and(|s| s != reg) {
            f.foreign_to_sender += 1;
        }
        domains.insert(reg);
    }
    f.domains = domains.len();
    f
}

/// The display name carries an address that is not the sender's own address.
pub fn display_name_address_mismatch(from: &NamedAddress) -> bool {
    let Some(name) = from.name.as_deref() else {
        return false;
    };
    name.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '(' | ')' | '"' | '\''))
        .filter(|t| t.contains('@') && t.contains('.'))
        .any(|t| !t.eq_ignore_ascii_case(&from.address))
}

const IBAN_LENGTHS: &str = include_str!("../data/iban_lengths.txt");

fn iban_length(country: &str) -> Option<usize> {
    IBAN_LENGTHS
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(' '))
        .find(|(cc, _)| *cc == country)
        .and_then(|(_, n)| n.trim().parse().ok())
}

/// Valid IBANs written in the text, in order, without spaces: a known country code, exactly that
/// country's length (spaces between groups allowed), a word boundary after it, and the mod-97
/// check (ISO 13616).
pub fn ibans(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let boundary_before = i == 0 || !chars[i - 1].is_ascii_alphanumeric();
        if boundary_before && chars[i].is_ascii_uppercase() && chars[i + 1].is_ascii_uppercase() {
            let cc: String = chars[i..i + 2].iter().collect();
            if let Some(len) = iban_length(&cc) {
                let mut compact = String::new();
                let mut j = i;
                while j < chars.len() && compact.len() < len {
                    let c = chars[j];
                    if c.is_ascii_alphanumeric() {
                        compact.push(c.to_ascii_uppercase());
                    } else if !(c == ' ' && j + 1 < chars.len() && chars[j + 1] != ' ') {
                        break;
                    }
                    j += 1;
                }
                let boundary_after = j >= chars.len() || !chars[j].is_ascii_alphanumeric();
                if compact.len() == len
                    && boundary_after
                    && compact[2..4].chars().all(|c| c.is_ascii_digit())
                    && mod97(&compact)
                {
                    out.push(compact);
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn mod97(iban: &str) -> bool {
    let rearranged = iban[4..].chars().chain(iban[..4].chars());
    let mut rem: u32 = 0;
    for c in rearranged {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        let digits = if v >= 10 { 100 } else { 10 };
        rem = (rem * digits + v) % 97;
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(href: &str, text: Option<&str>) -> Link {
        Link {
            href: href.into(),
            text: text.map(str::to_string),
        }
    }

    #[test]
    fn hosts_and_registrable_domains() {
        assert_eq!(
            url_host("https://user@Login.ING.nl:443/x?y").as_deref(),
            Some("login.ing.nl")
        );
        assert_eq!(registrable("login.ing.nl"), "ing.nl");
        assert_eq!(registrable("www.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn link_facts() {
        let links = [
            link("https://evil.example/login", Some("https://www.ing.nl")),
            link("http://192.0.2.7/x", None),
            link("https://bit.ly/abc", Some("hier")),
            link("https://xn--ng-wia.example/", None),
            link("https://mail.ing.nl/a", Some("www.ing.nl")),
            link("mailto:a@b.example", None),
        ];
        let f = analyse(&links, Some("ing.nl"));
        assert_eq!(f.count, 5);
        assert_eq!(f.text_target_mismatch, 1);
        assert_eq!(f.ip_literals, 1);
        let ip_behind_brand = analyse(&[link("http://192.0.2.7/x", Some("www.ing.nl"))], None);
        assert_eq!(ip_behind_brand.text_target_mismatch, 1);
        assert_eq!(f.shorteners, 1);
        assert_eq!(f.punycode, 1);
        assert_eq!(f.plain_http, 1);
        assert_eq!(f.foreign_to_sender, 4);
    }

    #[test]
    fn display_name_spoofing() {
        let spoof = NamedAddress {
            name: Some("info@ing.nl".into()),
            address: "x@evil.example".into(),
        };
        let fine = NamedAddress {
            name: Some("Jan <jan@example.nl>".into()),
            address: "jan@example.nl".into(),
        };
        assert!(display_name_address_mismatch(&spoof));
        assert!(!display_name_address_mismatch(&fine));
    }

    #[test]
    fn iban_mod97() {
        assert_eq!(
            ibans("Graag naar NL91 ABNA 0417 1643 00 overmaken."),
            vec!["NL91ABNA0417164300"]
        );
        assert!(ibans("NL92 ABNA 0417 1643 00").is_empty());
        assert!(ibans("Factuur 2026-10 voor NLX").is_empty());
        assert_eq!(
            ibans("IBAN: NL91ABNA0417164300."),
            vec!["NL91ABNA0417164300"]
        );
        // Longer alphanumeric runs and unknown country codes are not IBANs.
        assert!(ibans("NL91ABNA04171643007").is_empty());
        assert!(ibans("ZZ91 ABNA 0417 1643 00").is_empty());
        assert!(ibans("GB82 WEST 1234 5698 7654 32 and DE89 3704 0044 0532 0130 00").len() == 2);
    }
}
