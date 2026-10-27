//! DKIM signature verification (RFC 6376), with the algorithm rules of RFC 8301 and Ed25519 of
//! RFC 8463.
//!
//! Deterministic: the time a signature's expiry is judged against is a parameter (the delivery
//! time, recorded with the decision), and every key comes through [`firstread_net::Dns`], so a
//! recorded decision verifies the same way on replay.
//!
//! Accepted: `rsa-sha256` with keys of 1024 to 8192 bits, `ed25519-sha256`. Not accepted:
//! `rsa-sha1` (RFC 8301: verifiers must not consider it valid), keys in testing mode (`t=y`, which
//! RFC 6376 says must not be treated differently from unsigned mail), expired signatures.
//! A signature with `l=` shorter than the body passes, but is marked as not covering the whole
//! body; identity is never taken from such a signature.

use base64::Engine;
use firstread_net::{Answer, Dns, RecordType};
use ring::signature::{ED25519, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// Outcome of one signature, in RFC 8601 terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The signature verified.
    Pass,
    /// It did not verify (body hash or signature mismatch).
    Fail,
    /// It cannot be judged: malformed, unsupported, expired, revoked or testing key.
    PermError,
    /// The key could not be fetched now.
    TempError,
}

impl Status {
    /// Lowercase name, as in `Authentication-Results`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::PermError => "permerror",
            Self::TempError => "temperror",
        }
    }
}

/// One verified (or not) DKIM-Signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The outcome.
    pub status: Status,
    /// Why, when not `Pass`.
    pub reason: Option<&'static str>,
    /// `d=`, lowercase.
    pub domain: Option<String>,
    /// `s=`.
    pub selector: Option<String>,
    /// `a=`.
    pub algorithm: Option<String>,
    /// Whether the signature covers the whole body (no `l=`, or `l=` equal to its length).
    pub whole_body: bool,
}

impl Signature {
    fn err(status: Status, reason: &'static str) -> Self {
        Self {
            status,
            reason: Some(reason),
            domain: None,
            selector: None,
            algorithm: None,
            whole_body: false,
        }
    }
}

/// A header field as it appears in the message.
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    /// The name, without surrounding whitespace.
    pub name: &'a [u8],
    /// The whole field: name, colon, value and folding, without the final CRLF.
    pub raw: &'a [u8],
    /// The bytes after the colon.
    pub value: &'a [u8],
}

/// The message with every line ending as CRLF (a bare LF becomes CRLF; CRLF stays).
pub fn crlf(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let bare = raw
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || raw[i - 1] != b'\r'));
    if !bare {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 32);
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\n' && (i == 0 || raw[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    std::borrow::Cow::Owned(out)
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Split a CRLF message into header fields and body. Lines without a colon are not fields.
pub fn split(msg: &[u8]) -> (Vec<Field<'_>>, &[u8]) {
    let mut fields = Vec::new();
    let mut i = 0;
    let mut cur: Option<usize> = None;
    while i < msg.len() {
        let end = msg[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map_or(msg.len(), |p| i + p);
        let line = &msg[i..end];
        if line.is_empty() {
            if let Some(s) = cur.take() {
                push_field(&mut fields, &msg[s..i - 2]);
            }
            return (fields, &msg[(end + 2).min(msg.len())..]);
        }
        if !(is_wsp(line[0]) && cur.is_some()) {
            if let Some(s) = cur.take() {
                push_field(&mut fields, &msg[s..i - 2]);
            }
            cur = Some(i);
        }
        if end >= msg.len() {
            if let Some(s) = cur.take() {
                push_field(&mut fields, &msg[s..end]);
            }
            return (fields, &msg[msg.len()..]);
        }
        i = end + 2;
    }
    if let Some(s) = cur.take() {
        push_field(&mut fields, &msg[s..i - 2]);
    }
    (fields, &msg[msg.len()..])
}

fn push_field<'a>(fields: &mut Vec<Field<'a>>, raw: &'a [u8]) {
    if let Some(c) = raw.iter().position(|&b| b == b':') {
        fields.push(Field {
            name: trim(&raw[..c]),
            raw,
            value: &raw[c + 1..],
        });
    }
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Relaxed header canonicalisation (RFC 6376 3.4.2), without the final CRLF.
fn relaxed_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = name.to_ascii_lowercase();
    out.push(b':');
    let mut pending_space = false;
    let mut started = false;
    for &b in value {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        if is_wsp(b) {
            pending_space = true;
            continue;
        }
        if pending_space && started {
            out.push(b' ');
        }
        pending_space = false;
        started = true;
        out.push(b);
    }
    out
}

/// Canonical body (RFC 6376 3.4.3 and 3.4.4).
fn canonical_body(body: &[u8], relaxed: bool) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut rest = body;
    loop {
        match rest.windows(2).position(|w| w == b"\r\n") {
            Some(p) => {
                lines.push(rest[..p].to_vec());
                rest = &rest[p + 2..];
            }
            None => {
                if !rest.is_empty() {
                    lines.push(rest.to_vec());
                }
                break;
            }
        }
    }
    if relaxed {
        for l in &mut lines {
            let mut out = Vec::with_capacity(l.len());
            let mut ws = false;
            for &b in l.iter() {
                if is_wsp(b) {
                    ws = true;
                } else {
                    if ws {
                        out.push(b' ');
                    }
                    ws = false;
                    out.push(b);
                }
            }
            *l = out;
        }
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return if relaxed {
            Vec::new()
        } else {
            b"\r\n".to_vec()
        };
    }
    let mut out = Vec::with_capacity(body.len());
    for l in lines {
        out.extend_from_slice(&l);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A tag list (RFC 6376 3.2): names and values, values with surrounding whitespace removed.
/// `None` when a tag appears twice or a part has no `=`.
fn tags(value: &[u8]) -> Option<Vec<(String, String)>> {
    let text = String::from_utf8_lossy(value);
    let mut out: Vec<(String, String)> = Vec::new();
    for part in text.split(';') {
        let part = part.trim_matches(|c: char| c.is_ascii_whitespace());
        if part.is_empty() {
            continue;
        }
        let (n, v) = part.split_once('=')?;
        let n = n.trim_matches(|c: char| c.is_ascii_whitespace());
        if n.is_empty() || n.contains(|c: char| c.is_ascii_whitespace()) {
            return None;
        }
        if out.iter().any(|(k, _)| k == n) {
            return None;
        }
        out.push((
            n.to_string(),
            v.trim_matches(|c: char| c.is_ascii_whitespace())
                .to_string(),
        ));
    }
    Some(out)
}

fn tag<'a>(t: &'a [(String, String)], name: &str) -> Option<&'a str> {
    t.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn b64(v: &str) -> Option<Vec<u8>> {
    let clean: String = v.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(clean).ok()
}

/// The DKIM-Signature field with the value of its `b=` tag removed (RFC 6376 3.7).
fn without_b(raw: &[u8]) -> Vec<u8> {
    let colon = raw.iter().position(|&b| b == b':').unwrap_or(0);
    let mut out = raw[..=colon].to_vec();
    let v = &raw[colon + 1..];
    let mut i = 0;
    while i < v.len() {
        let seg_end = v[i..]
            .iter()
            .position(|&b| b == b';')
            .map_or(v.len(), |p| i + p);
        let seg = &v[i..seg_end];
        let eq = seg.iter().position(|&b| b == b'=');
        match eq {
            Some(e) if trim(&seg[..e]) == b"b" => {
                out.extend_from_slice(&seg[..=e]);
            }
            _ => out.extend_from_slice(seg),
        }
        if seg_end < v.len() {
            out.push(b';');
        }
        i = seg_end + 1;
    }
    out
}

/// Read one DER element: (tag, content, rest).
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, b) = b.split_first()?;
    let (len, b) = if l0 < 0x80 {
        (usize::from(l0), b)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let len = b[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, &b[n..])
    };
    if b.len() < len {
        return None;
    }
    Some((tag, &b[..len], &b[len..]))
}

const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Bits in the modulus of a PKCS#1 `RSAPublicKey`.
fn rsa_bits(pkcs1: &[u8]) -> Option<usize> {
    let (tag, seq, _) = der(pkcs1)?;
    let (itag, n, _) = der(seq)?;
    if tag != 0x30 || itag != 0x02 {
        return None;
    }
    let n = match n {
        [0, rest @ ..] => rest,
        n => n,
    };
    let first = *n.first()?;
    Some(n.len() * 8 - first.leading_zeros() as usize)
}

/// An RSA key as PKCS#1 `RSAPublicKey` DER, from SubjectPublicKeyInfo or from PKCS#1 itself.
fn rsa_public_key(p: &[u8]) -> Option<&[u8]> {
    let (tag, seq, _) = der(p)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, c1, rest) = der(seq)?;
    if t1 == 0x02 {
        return Some(p); // already RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
    }
    if t1 != 0x30 {
        return None;
    }
    let (oid_tag, oid, _) = der(c1)?;
    if oid_tag != 0x06 || oid != RSA_OID {
        return None;
    }
    let (bt, bits, _) = der(rest)?;
    if bt != 0x03 || bits.first() != Some(&0) {
        return None;
    }
    Some(&bits[1..])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alg {
    RsaSha256,
    Ed25519Sha256,
}

struct Key {
    alg: Alg,
    material: Vec<u8>,
    strict: bool,
    testing: bool,
}

fn parse_key(record: &str) -> Result<Key, &'static str> {
    let t = tags(record.as_bytes()).ok_or("key record malformed")?;
    if let Some(v) = tag(&t, "v")
        && v != "DKIM1"
    {
        return Err("key record version");
    }
    if let Some(h) = tag(&t, "h")
        && !h
            .split(':')
            .any(|x| x.trim().eq_ignore_ascii_case("sha256"))
    {
        return Err("key does not allow sha256");
    }
    if let Some(s) = tag(&t, "s")
        && !s
            .split(':')
            .any(|x| x.trim() == "*" || x.trim().eq_ignore_ascii_case("email"))
    {
        return Err("key not for email");
    }
    let flags: Vec<String> = tag(&t, "t")
        .map(|v| {
            v.split(':')
                .map(|x| x.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let p = tag(&t, "p").ok_or("key record without p=")?;
    if p.trim().is_empty() {
        return Err("key revoked");
    }
    let raw = b64(p).ok_or("key not base64")?;
    let alg = match tag(&t, "k").map(str::to_ascii_lowercase).as_deref() {
        None | Some("rsa") => Alg::RsaSha256,
        Some("ed25519") => Alg::Ed25519Sha256,
        Some(_) => return Err("key type unsupported"),
    };
    let material = match alg {
        Alg::RsaSha256 => {
            let k = rsa_public_key(&raw).ok_or("rsa key unreadable")?;
            // RFC 8301: keys under 1024 bits must not be considered valid.
            if rsa_bits(k).ok_or("rsa key unreadable")? < 1024 {
                return Err("rsa key under 1024 bits");
            }
            k.to_vec()
        }
        Alg::Ed25519Sha256 => {
            if raw.len() != 32 {
                return Err("ed25519 key length");
            }
            raw
        }
    };
    Ok(Key {
        alg,
        material,
        strict: flags.iter().any(|f| f == "s"),
        testing: flags.iter().any(|f| f == "y"),
    })
}

fn subdomain_of(child: &str, parent: &str) -> bool {
    child == parent || child.ends_with(&format!(".{parent}"))
}

/// Verify every DKIM-Signature of a message (CRLF or LF line endings), judging expiry at `at`
/// (Unix seconds). Signatures are returned top first.
pub fn verify(raw: &[u8], at: u64, dns: &dyn Dns) -> Vec<Signature> {
    let msg = crlf(raw);
    let (fields, body) = split(&msg);
    let mut out = Vec::new();
    for (idx, f) in fields.iter().enumerate() {
        if f.name.eq_ignore_ascii_case(b"DKIM-Signature") {
            out.push(verify_one(&fields, idx, body, at, dns));
        }
    }
    out
}

fn verify_one(fields: &[Field<'_>], idx: usize, body: &[u8], at: u64, dns: &dyn Dns) -> Signature {
    let f = fields[idx];
    let Some(t) = tags(f.value) else {
        return Signature::err(Status::PermError, "signature malformed");
    };
    let mut sig = Signature {
        status: Status::PermError,
        reason: None,
        domain: tag(&t, "d").map(str::to_ascii_lowercase),
        selector: tag(&t, "s").map(str::to_string),
        algorithm: tag(&t, "a").map(str::to_ascii_lowercase),
        whole_body: false,
    };
    let fail = |mut s: Signature, st: Status, r: &'static str| {
        s.status = st;
        s.reason = Some(r);
        s
    };
    if tag(&t, "v") != Some("1") {
        return fail(sig, Status::PermError, "version");
    }
    let (Some(d), Some(s), Some(a), Some(b), Some(bh), Some(h)) = (
        sig.domain.clone(),
        sig.selector.clone(),
        sig.algorithm.clone(),
        tag(&t, "b").and_then(b64),
        tag(&t, "bh").and_then(b64),
        tag(&t, "h"),
    ) else {
        return fail(sig, Status::PermError, "required tag missing");
    };
    let alg = match a.as_str() {
        "rsa-sha256" => Alg::RsaSha256,
        "ed25519-sha256" => Alg::Ed25519Sha256,
        "rsa-sha1" => return fail(sig, Status::PermError, "rsa-sha1 not accepted"),
        _ => return fail(sig, Status::PermError, "algorithm unsupported"),
    };
    let signed: Vec<String> = h
        .split(':')
        .map(|x| x.trim().to_ascii_lowercase())
        .filter(|x| !x.is_empty())
        .collect();
    if !signed.iter().any(|x| x == "from") {
        return fail(sig, Status::PermError, "From not signed");
    }
    let auid = tag(&t, "i").map_or_else(|| format!("@{d}"), str::to_ascii_lowercase);
    let auid_domain = auid.rsplit_once('@').map_or("", |(_, dom)| dom).to_string();
    if !subdomain_of(&auid_domain, &d) {
        return fail(sig, Status::PermError, "i= not within d=");
    }
    if let Some(q) = tag(&t, "q")
        && !q
            .split(':')
            .any(|x| x.trim().eq_ignore_ascii_case("dns/txt"))
    {
        return fail(sig, Status::PermError, "query method unsupported");
    }
    let ts = tag(&t, "t").and_then(|v| v.parse::<u64>().ok());
    if let Some(x) = tag(&t, "x") {
        let Ok(x) = x.parse::<u64>() else {
            return fail(sig, Status::PermError, "x= malformed");
        };
        if ts.is_some_and(|ts| x < ts) {
            return fail(sig, Status::PermError, "x= before t=");
        }
        if x < at {
            return fail(sig, Status::PermError, "signature expired");
        }
    }
    let (hc, bc) = match tag(&t, "c").map(str::to_ascii_lowercase) {
        None => (false, false),
        Some(c) => {
            let (hp, bp) = c.split_once('/').unwrap_or((c.as_str(), "simple"));
            let canon = |v: &str| match v {
                "simple" => Some(false),
                "relaxed" => Some(true),
                _ => None,
            };
            match (canon(hp), canon(bp)) {
                (Some(x), Some(y)) => (x, y),
                _ => return fail(sig, Status::PermError, "canonicalisation unsupported"),
            }
        }
    };

    // Body hash.
    let canon_body = canonical_body(body, bc);
    let hashed_body: &[u8] = match tag(&t, "l") {
        None => {
            sig.whole_body = true;
            &canon_body
        }
        Some(l) => {
            let Ok(l) = l.parse::<usize>() else {
                return fail(sig, Status::PermError, "l= malformed");
            };
            if l > canon_body.len() {
                return fail(sig, Status::PermError, "l= longer than the body");
            }
            sig.whole_body = l == canon_body.len();
            &canon_body[..l]
        }
    };
    if Sha256::digest(hashed_body).as_slice() != bh.as_slice() {
        return fail(sig, Status::Fail, "body hash");
    }

    // Key.
    let key = match dns.lookup(RecordType::Txt, &format!("{s}._domainkey.{d}")) {
        Answer::Records { records } => {
            let mut found = Err("no usable key record");
            for r in &records {
                found = parse_key(r);
                if found.is_ok() {
                    break;
                }
            }
            match found {
                Ok(k) => k,
                Err(e) => return fail(sig, Status::PermError, e),
            }
        }
        Answer::NoRecords => return fail(sig, Status::PermError, "no key"),
        Answer::TempError { .. } => return fail(sig, Status::TempError, "key lookup"),
    };
    if key.alg != alg {
        return fail(sig, Status::PermError, "key type does not match a=");
    }
    if key.strict && auid_domain != d {
        return fail(sig, Status::PermError, "key requires i= domain equal to d=");
    }

    // Header hash input: the signed fields, bottom-up per name, then this field without b=.
    let mut used = vec![false; fields.len()];
    used[idx] = true;
    let mut input = Vec::new();
    for name in &signed {
        if let Some(j) = (0..fields.len())
            .rev()
            .find(|&j| !used[j] && fields[j].name.eq_ignore_ascii_case(name.as_bytes()))
        {
            used[j] = true;
            let fj = fields[j];
            if hc {
                input.extend_from_slice(&relaxed_header(fj.name, fj.value));
            } else {
                input.extend_from_slice(fj.raw);
            }
            input.extend_from_slice(b"\r\n");
        }
    }
    let stripped = without_b(f.raw);
    if hc {
        let colon = stripped.iter().position(|&b| b == b':').unwrap_or(0);
        input.extend_from_slice(&relaxed_header(
            trim(&stripped[..colon]),
            &stripped[colon + 1..],
        ));
    } else {
        input.extend_from_slice(&stripped);
    }

    let ok = match alg {
        Alg::RsaSha256 => UnparsedPublicKey::new(
            &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            &key.material,
        )
        .verify(&input, &b)
        .is_ok(),
        Alg::Ed25519Sha256 => UnparsedPublicKey::new(&ED25519, &key.material)
            .verify(Sha256::digest(&input).as_slice(), &b)
            .is_ok(),
    };
    if !ok {
        return fail(sig, Status::Fail, "signature");
    }
    if key.testing {
        return fail(sig, Status::PermError, "key in testing mode");
    }
    sig.status = Status::Pass;
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_keeps_folding_and_finds_the_body() {
        let m = b"From: a@x.example\r\nSubject: one\r\n two\r\nX: y\r\n\r\nbody\r\n";
        let (f, body) = split(m);
        assert_eq!(f.len(), 3);
        assert_eq!(f[1].raw, b"Subject: one\r\n two");
        assert_eq!(f[1].name, b"Subject");
        assert_eq!(body, b"body\r\n");
        let (g, b2) = split(b"From: a@x.example\r\nX: y");
        assert_eq!(g.len(), 2);
        assert!(b2.is_empty());
        let (h, b3) = split(b"From: a@x.example\r\n\r\n");
        assert_eq!(h.len(), 1);
        assert!(b3.is_empty());
    }

    #[test]
    fn body_canonicalisation_follows_rfc_6376() {
        // RFC 6376 section 3.4.5 example.
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(canonical_body(body, true), b" C\r\nD E\r\n");
        assert_eq!(canonical_body(body, false), b" C \r\nD \t E\r\n");
        assert_eq!(canonical_body(b"", false), b"\r\n");
        assert_eq!(canonical_body(b"", true), b"");
        assert_eq!(canonical_body(b"x", false), b"x\r\n");
    }

    #[test]
    fn header_canonicalisation_follows_rfc_6376() {
        // RFC 6376 section 3.4.5 example: "A: X" and "B : Y\t\r\n\tZ  ".
        assert_eq!(relaxed_header(b"A", b" X"), b"a:X");
        assert_eq!(relaxed_header(b"B", b" Y\t\r\n\tZ  "), b"b:Y Z");
    }

    #[test]
    fn b_value_is_removed_and_bh_is_kept() {
        let raw = b"DKIM-Signature: v=1; bh=abc=; b=AAAA\r\n BBBB; d=x.example";
        assert_eq!(
            without_b(raw),
            b"DKIM-Signature: v=1; bh=abc=; b=; d=x.example".to_vec()
        );
        assert_eq!(
            without_b(b"DKIM-Signature: v=1; b=AAAA"),
            b"DKIM-Signature: v=1; b=".to_vec()
        );
    }

    #[test]
    fn duplicate_tags_are_malformed() {
        assert!(tags(b"v=1; d=a; d=b").is_none());
        assert_eq!(tags(b" v = 1 ;d=a;").unwrap().len(), 2);
    }

    #[test]
    fn bare_lf_becomes_crlf() {
        assert_eq!(&*crlf(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
        assert!(matches!(crlf(b"a\r\nb"), std::borrow::Cow::Borrowed(_)));
    }
}
