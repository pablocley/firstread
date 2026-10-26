//! Message authentication.
//!
//! Implemented so far: reading `Authentication-Results` (RFC 8601) added inside our own trust
//! boundary, identified by configured authserv-ids. Results from any other authserv-id are
//! ignored, and a message without trusted results has every method `Unavailable`, never "fine".
//!
//! Still to build (docs/02-signals.md): SPF, DKIM (v1 and v2), DMARC and ARC evaluation with
//! recorded DNS answers (`mail-auth`, Stalwart Labs), removal of foreign results claiming our
//! authserv-id, and our own `Authentication-Results` header.
//!
//! Identity is decided here, deterministically. No model output may override it.

/// One method's result, as RFC 8601 names them, plus `Unavailable` for "not checked by us".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// `pass`.
    Pass,
    /// `fail` or `hardfail`.
    Fail,
    /// `softfail`.
    SoftFail,
    /// `neutral`.
    Neutral,
    /// `none`.
    None,
    /// `temperror`.
    TempError,
    /// `permerror`.
    PermError,
    /// Any other result keyword.
    Other,
    /// No trusted result for this method.
    Unavailable,
}

impl AuthResult {
    fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "pass" => Self::Pass,
            "fail" | "hardfail" => Self::Fail,
            "softfail" => Self::SoftFail,
            "neutral" => Self::Neutral,
            "none" => Self::None,
            "temperror" => Self::TempError,
            "permerror" => Self::PermError,
            _ => Self::Other,
        }
    }

    /// Lowercase name, for records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
            Self::Other => "other",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The trusted results for one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSummary {
    /// SPF.
    pub spf: AuthResult,
    /// DKIM: `Pass` if any signature passed, else the first result seen.
    pub dkim: AuthResult,
    /// DMARC.
    pub dmarc: AuthResult,
    /// Whether a trusted `Authentication-Results` was found at all.
    pub trusted: bool,
}

impl Default for AuthSummary {
    fn default() -> Self {
        Self {
            spf: AuthResult::Unavailable,
            dkim: AuthResult::Unavailable,
            dmarc: AuthResult::Unavailable,
            trusted: false,
        }
    }
}

/// The authserv-id: the first token of the value, before `;` or whitespace (RFC 8601 section 2.2).
fn authserv_id(value: &str) -> &str {
    let v = value.trim_start();
    let end = v
        .find(|c: char| c == ';' || c.is_whitespace())
        .unwrap_or(v.len());
    &v[..end]
}

/// Read the results from every trusted `Authentication-Results` value (top first). Several
/// trusted fields are merged: the first result per method wins, except that any DKIM `pass` wins.
pub fn summarise(values: &[String], trusted_ids: &[String]) -> AuthSummary {
    let mut s = AuthSummary::default();
    for value in values {
        let id = authserv_id(value);
        if !trusted_ids.iter().any(|t| t.eq_ignore_ascii_case(id)) {
            continue;
        }
        s.trusted = true;
        for clause in value.split(';').skip(1) {
            let clause = clause.trim();
            let Some((method, rest)) = clause.split_once('=') else {
                continue;
            };
            let result = rest
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or_default();
            let r = AuthResult::parse(result);
            match method.trim().to_ascii_lowercase().as_str() {
                "spf" if s.spf == AuthResult::Unavailable => s.spf = r,
                "dkim" if s.dkim == AuthResult::Unavailable || r == AuthResult::Pass => s.dkim = r,
                "dmarc" if s.dmarc == AuthResult::Unavailable => s.dmarc = r,
                _ => {}
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<String> {
        vec!["mx.example.org".into()]
    }

    #[test]
    fn trusted_results_are_read() {
        let v = vec![
            "mx.example.org; spf=pass smtp.mailfrom=a.example; dkim=fail header.d=a.example; dkim=pass header.d=b.example; dmarc=pass (p=none) header.from=a.example".to_string(),
        ];
        let s = summarise(&v, &ids());
        assert!(s.trusted);
        assert_eq!(s.spf, AuthResult::Pass);
        assert_eq!(s.dkim, AuthResult::Pass);
        assert_eq!(s.dmarc, AuthResult::Pass);
    }

    #[test]
    fn foreign_authserv_ids_are_ignored() {
        let v = vec!["evil.example; spf=pass; dkim=pass; dmarc=pass".to_string()];
        let s = summarise(&v, &ids());
        assert_eq!(s, AuthSummary::default());
        assert_eq!(s.dmarc, AuthResult::Unavailable);
    }

    #[test]
    fn multiple_trusted_fields_merge() {
        let v = vec![
            "mx.example.org; arc=none smtp.remote-ip=192.0.2.1".to_string(),
            "mx.example.org; dmarc=fail (p=reject) header.from=x.example".to_string(),
            "mx.example.org; spf=softfail smtp.mailfrom=x.example".to_string(),
        ];
        let s = summarise(&v, &ids());
        assert_eq!(s.dmarc, AuthResult::Fail);
        assert_eq!(s.spf, AuthResult::SoftFail);
        assert_eq!(s.dkim, AuthResult::Unavailable);
    }
}
