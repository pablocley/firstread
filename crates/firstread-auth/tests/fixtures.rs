//! Every message in fixtures/auth/ (signed by dkimpy, an independent implementation, with keys
//! published in fixtures/auth/dns.jsonl) verifies as fixtures/auth/expected.json says.

use std::path::PathBuf;

use firstread_net::RecordedDns;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/auth")
}

#[test]
fn every_fixture_verifies_as_expected() {
    let dns = RecordedDns::load(&dir().join("dns.jsonl")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir().join("expected.json")).unwrap())
            .unwrap();
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let raw = std::fs::read(dir().join(format!("{name}.eml"))).unwrap();
        let from = firstread_parse::parse(&raw)
            .unwrap()
            .state
            .from
            .map(|f| f.address);
        let at = want["at"].as_u64().unwrap();
        let v = firstread_auth::verify(&raw, from.as_deref(), at, &dns);
        let dkim: Vec<&str> = v.dkim.iter().map(|s| s.status.as_str()).collect();
        let want_dkim: Vec<&str> = want["dkim"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(dkim, want_dkim, "{name}: dkim {:?}", v.dkim);
        assert_eq!(
            v.dmarc.outcome.as_str(),
            want["dmarc"].as_str().unwrap(),
            "{name}: dmarc {:?}",
            v.dmarc
        );
        assert_eq!(
            v.identity_verified(),
            want["identity"].as_bool().unwrap(),
            "{name}"
        );
        assert!(
            !v.lookups.is_empty() || want_dkim.is_empty(),
            "{name}: lookups recorded"
        );
        checked += 1;
    }
    assert_eq!(checked, 20);
}

#[test]
fn the_policy_of_the_from_domain_is_found_even_without_alignment() {
    let dns = RecordedDns::load(&dir().join("dns.jsonl")).unwrap();
    let raw = std::fs::read(dir().join("third-party-signer.eml")).unwrap();
    let v = firstread_auth::verify(&raw, Some("alice@signer.example"), u64::MAX / 2, &dns);
    assert_eq!(v.dmarc.policy, Some(firstread_auth::dmarc::Policy::Reject));
    assert_eq!(v.dkim[0].domain.as_deref(), Some("other.example"));
}

#[test]
fn a_recording_gives_no_answers_for_mail_from_before_its_window() {
    let mut dns = RecordedDns::load(&dir().join("dns.jsonl")).unwrap();
    let raw = std::fs::read(dir().join("rsa2048-relaxed.eml")).unwrap();
    let at = 1_793_087_035;
    dns.set_window(at - 400 * 86_400, at + 86_400);
    let inside = firstread_auth::verify(&raw, Some("alice@signer.example"), at, &dns);
    assert!(inside.identity_verified());
    // The same message judged as if it had arrived years before the recording: today's key and
    // policy must not stand in for the answers of then.
    let old = at - 20 * 365 * 86_400;
    let v = firstread_auth::verify(&raw, Some("alice@signer.example"), old, &dns);
    assert!(!v.identity_verified());
    assert_eq!(v.dmarc.outcome, firstread_auth::dmarc::Outcome::TempError);
    assert_eq!(v.dmarc.policy, None);
    assert!(!v.lookups.is_empty());
    for l in &v.lookups {
        assert_eq!(
            l.answer,
            firstread_net::Answer::TempError {
                reason: "outside the recording".into()
            },
            "{l:?}"
        );
    }
}
