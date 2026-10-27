//! DMARC (RFC 7489): the From domain's policy, and whether a passing DKIM signature is aligned
//! with the From domain. Alignment is what turns a DKIM pass into a verified sender identity.
//!
//! SPF is not evaluated here (it needs the client IP from our own border MTA). So a message
//! without an aligned DKIM pass is `Unaligned`, never `Fail`: SPF might have passed.

use firstread_net::{Answer, Dns, RecordType};

use crate::dkim::{Signature, Status};

/// A DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// `p=none`.
    None,
    /// `p=quarantine`.
    Quarantine,
    /// `p=reject`.
    Reject,
}

impl Policy {
    fn parse(v: &str) -> Option<Self> {
        match v.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }

    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

/// A parsed DMARC record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `p=`.
    pub p: Policy,
    /// `sp=`, for subdomains of the organisational domain.
    pub sp: Option<Policy>,
    /// `adkim=s`.
    pub adkim_strict: bool,
}

/// Parse a DMARC record; `None` if it is not one.
pub fn parse_record(txt: &str) -> Option<Record> {
    let mut parts = txt.split(';').map(str::trim).filter(|p| !p.is_empty());
    let first = parts.next()?;
    let (k, v) = first.split_once('=')?;
    if k.trim() != "v" || v.trim() != "DMARC1" {
        return None;
    }
    let mut p = None;
    let mut sp = None;
    let mut adkim_strict = false;
    let mut rua = false;
    for part in parts {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "p" => p = Some(Policy::parse(v)),
            "sp" => sp = Policy::parse(v),
            "adkim" => adkim_strict = v.trim().eq_ignore_ascii_case("s"),
            "rua" => rua = true,
            _ => {}
        }
    }
    let p = match p {
        Some(Some(p)) => p,
        // RFC 7489 6.6.3: an invalid or missing p= with a valid rua= is treated as p=none.
        _ if rua => Policy::None,
        _ => return None,
    };
    Some(Record {
        p,
        sp,
        adkim_strict,
    })
}

/// The outcome for one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A DKIM signature aligned with the From domain passed.
    Pass,
    /// No aligned DKIM pass; SPF was not evaluated, so this is not a DMARC fail.
    Unaligned,
    /// No From domain to evaluate: no From field, several, or several addresses in it.
    Unusable,
    /// The policy or a key could not be fetched now.
    TempError,
}

impl Outcome {
    /// Lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Unaligned => "unaligned",
            Self::Unusable => "unusable",
            Self::TempError => "temperror",
        }
    }
}

/// What DMARC evaluation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dmarc {
    /// The outcome.
    pub outcome: Outcome,
    /// The From domain, lowercase.
    pub from_domain: Option<String>,
    /// The policy that applies to the From domain, if it publishes one.
    pub policy: Option<Policy>,
    /// `d=` of the aligned passing signature: the verified sender domain.
    pub aligned_domain: Option<String>,
}

/// Number of addresses in a From value, not counting `@` inside quotes or comments.
fn address_count(value: &str) -> usize {
    let (mut quoted, mut depth, mut escaped, mut n) = (false, 0usize, false, 0);
    for c in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' if depth == 0 => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            '@' if !quoted && depth == 0 => n += 1,
            _ => {}
        }
    }
    n
}

fn org(domain: &str) -> String {
    firstread_links::registrable(domain)
}

fn lookup_record(dns: &dyn Dns, domain: &str) -> Result<Option<Record>, ()> {
    match dns.lookup(RecordType::Txt, &format!("_dmarc.{domain}")) {
        Answer::Records { records } => {
            let found: Vec<Record> = records.iter().filter_map(|r| parse_record(r)).collect();
            // RFC 7489 6.6.3: more than one record means none.
            Ok(if found.len() == 1 {
                found.into_iter().next()
            } else {
                None
            })
        }
        Answer::NoRecords => Ok(None),
        Answer::TempError { .. } => Err(()),
    }
}

/// Evaluate DMARC for a message, given the values of its From fields, the From address that
/// parsing found, and the DKIM results.
pub fn evaluate(
    from_values: &[String],
    from_address: Option<&str>,
    dkim: &[Signature],
    dns: &dyn Dns,
) -> Dmarc {
    let from_domain = from_address
        .and_then(|a| a.rsplit_once('@'))
        .map(|(_, d)| d.trim().trim_end_matches('>').to_ascii_lowercase())
        .filter(|d| !d.is_empty());
    let unusable = Dmarc {
        outcome: Outcome::Unusable,
        from_domain: from_domain.clone(),
        policy: None,
        aligned_domain: None,
    };
    let Some(fd) = from_domain.clone() else {
        return unusable;
    };
    if from_values.len() != 1 || address_count(&from_values[0]) != 1 {
        return unusable;
    }
    let org_fd = org(&fd);
    let record = match lookup_record(dns, &fd) {
        Ok(Some(r)) => Ok(Some((r, false))),
        Ok(None) if org_fd != fd => lookup_record(dns, &org_fd).map(|r| r.map(|r| (r, true))),
        Ok(None) => Ok(None),
        Err(()) => Err(()),
    };
    let strict = matches!(&record, Ok(Some((r, _))) if r.adkim_strict);
    let policy = match &record {
        Ok(Some((r, from_org))) => Some(if *from_org { r.sp.unwrap_or(r.p) } else { r.p }),
        _ => None,
    };
    let aligned_domain = dkim
        .iter()
        .filter(|s| s.status == Status::Pass && s.whole_body)
        .filter_map(|s| s.domain.clone())
        .find(|d| if strict { *d == fd } else { org(d) == org_fd });
    let outcome = match (&aligned_domain, &record) {
        (Some(_), Ok(_)) => Outcome::Pass,
        // An aligned pass verifies the identity even when the policy lookup failed.
        (Some(_), Err(())) => Outcome::Pass,
        (None, Err(())) => Outcome::TempError,
        (None, Ok(_)) if dkim.iter().any(|s| s.status == Status::TempError) => Outcome::TempError,
        (None, Ok(_)) => Outcome::Unaligned,
    };
    Dmarc {
        outcome,
        from_domain,
        policy,
        aligned_domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firstread_net::{Lookup, RecordedDns};

    fn pass(d: &str, whole: bool) -> Signature {
        Signature {
            status: Status::Pass,
            reason: None,
            domain: Some(d.into()),
            selector: Some("s".into()),
            algorithm: Some("rsa-sha256".into()),
            whole_body: whole,
        }
    }

    fn dns(entries: &[(&str, Answer)]) -> RecordedDns {
        let mut r = RecordedDns::new();
        for (n, a) in entries {
            r.insert(Lookup {
                rtype: RecordType::Txt,
                name: (*n).into(),
                answer: a.clone(),
            });
        }
        r
    }

    fn txt(s: &str) -> Answer {
        Answer::Records {
            records: vec![s.into()],
        }
    }

    #[test]
    fn records_parse_and_bad_ones_do_not() {
        let r = parse_record("v=DMARC1; p=reject; sp=none; adkim=s; rua=mailto:x@y").unwrap();
        assert_eq!(r.p, Policy::Reject);
        assert_eq!(r.sp, Some(Policy::None));
        assert!(r.adkim_strict);
        assert!(
            parse_record("p=reject; v=DMARC1").is_none(),
            "v= must come first"
        );
        assert!(parse_record("v=spf1 -all").is_none());
        assert_eq!(
            parse_record("v=DMARC1; p=bogus; rua=mailto:x@y").unwrap().p,
            Policy::None
        );
        assert!(parse_record("v=DMARC1; p=bogus").is_none());
    }

    #[test]
    fn relaxed_alignment_uses_the_organisational_domain() {
        let d = dns(&[
            ("_dmarc.mail.example.com", Answer::NoRecords),
            (
                "_dmarc.example.com",
                txt("v=DMARC1; p=reject; sp=quarantine"),
            ),
        ]);
        let r = evaluate(
            &["Bob <bob@mail.example.com>".into()],
            Some("bob@mail.example.com"),
            &[pass("example.com", true)],
            &d,
        );
        assert_eq!(r.outcome, Outcome::Pass);
        assert_eq!(r.aligned_domain.as_deref(), Some("example.com"));
        assert_eq!(r.policy, Some(Policy::Quarantine), "sp= for a subdomain");
    }

    #[test]
    fn strict_alignment_and_partial_bodies_do_not_verify() {
        let d = dns(&[("_dmarc.example.com", txt("v=DMARC1; p=reject; adkim=s"))]);
        let r = evaluate(
            &["bob@example.com".into()],
            Some("bob@example.com"),
            &[pass("mail.example.com", true)],
            &d,
        );
        assert_eq!(r.outcome, Outcome::Unaligned);
        let e = dns(&[("_dmarc.example.com", txt("v=DMARC1; p=none"))]);
        let r = evaluate(
            &["bob@example.com".into()],
            Some("bob@example.com"),
            &[pass("example.com", false)],
            &e,
        );
        assert_eq!(
            r.outcome,
            Outcome::Unaligned,
            "an l= signature verifies no identity"
        );
    }

    #[test]
    fn a_third_party_signature_is_not_alignment() {
        let d = dns(&[("_dmarc.bank.example", txt("v=DMARC1; p=reject"))]);
        let r = evaluate(
            &["Bank <alert@bank.example>".into()],
            Some("alert@bank.example"),
            &[pass("mailer.example", true)],
            &d,
        );
        assert_eq!(r.outcome, Outcome::Unaligned);
        assert_eq!(r.policy, Some(Policy::Reject));
    }

    #[test]
    fn several_from_fields_or_addresses_are_unusable() {
        let d = dns(&[]);
        let two = evaluate(
            &["a@x.example".into(), "b@y.example".into()],
            Some("a@x.example"),
            &[pass("x.example", true)],
            &d,
        );
        assert_eq!(two.outcome, Outcome::Unusable);
        let list = evaluate(
            &["a@x.example, b@y.example".into()],
            Some("a@x.example"),
            &[pass("x.example", true)],
            &d,
        );
        assert_eq!(list.outcome, Outcome::Unusable);
        assert_eq!(address_count("\"a@b\" <c@x.example> (d@e)"), 1);
    }

    #[test]
    fn an_unrecorded_policy_does_not_hide_an_aligned_pass_but_is_temperror_otherwise() {
        let d = dns(&[]);
        let r = evaluate(
            &["a@x.example".into()],
            Some("a@x.example"),
            &[pass("x.example", true)],
            &d,
        );
        assert_eq!(r.outcome, Outcome::Pass);
        let q = evaluate(&["a@x.example".into()], Some("a@x.example"), &[], &d);
        assert_eq!(q.outcome, Outcome::TempError);
    }
}
