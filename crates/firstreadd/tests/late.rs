//! The daemon end to end with a decision model behind the sidecar protocol: delivery replies at
//! once; tier 2 answers afterwards from the queue; the update lands in the records under the same
//! id; hook C calls doveadm with the additions; the API serves the latest record to its own
//! mailbox only. The decision model and doveadm are stand-ins written here.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use firstread_core::wire::{MAX_JSON_FRAME, Reply, Request, read_frame, write_frame};

const PHISH: &[u8] = b"From: \"Noorderbank\" <service@noorderbank-veilig.example>\r\nTo: alice@lab.invalid\r\nSubject: Uw rekening is geblokkeerd\r\nMessage-ID: <p1@noorderbank-veilig.example>\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p><a href=\"http://192.0.2.7/login\">https://www.noorderbank.example</a></p>\r\n";

/// A decision model that says "true" to every question it is asked, and records the specs.
fn fake_tier2(path: &Path, asked: PathBuf) {
    let l = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let req: serde_json::Value =
                serde_json::from_slice(&read_frame(&mut c, MAX_JSON_FRAME).unwrap()).unwrap();
            let reply = if req["op"] == "manifest" {
                serde_json::json!({"release": "fake-decoder@1", "licence": "Apache-2.0",
                    "commercial_use": true, "max_input_tokens": 4096, "supported": ["*"]})
            } else {
                std::fs::write(&asked, serde_json::to_vec(&req["specs"]).unwrap()).unwrap();
                let n = req["questions"].as_array().unwrap().len();
                serde_json::json!({"logits": vec![[0.0, 4.0]; n]})
            };
            write_frame(&mut c, &serde_json::to_vec(&reply).unwrap()).unwrap();
        }
    });
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn http_get(sock: &Path, path: &str, user: &str) -> (u16, serde_json::Value) {
    let mut s = UnixStream::connect(sock).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: firstread\r\nX-Firstread-User: {user}\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let code = out[9..12].parse().unwrap();
    let body = out.split_once("\r\n\r\n").unwrap().1;
    (code, serde_json::from_str(body).unwrap())
}

#[test]
fn tier2_updates_the_record_calls_hook_c_and_the_api_serves_it() {
    let dir = std::env::temp_dir().join(format!("fr-late-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).unwrap();
    let w = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    w(
        "rules/alice@lab.invalid.json",
        r#"{"rules":[{"id":"bank","text":"Mail that claims to come from my bank","tag":"bank"}]}"#,
    );
    let phishing = w(
        "phishing.json",
        r#"{"release":"phishing@test","bias":-1.0,"weights":{"links.ip_literal":1.0,"head.risk_phishing.logit":1.0}}"#,
    );
    let cal = w(
        "tier2-cal.json",
        r#"{"release":"fake-decoder@1","temperatures":{"risk_phishing":1.0,"rule:*":1.0}}"#,
    );
    let log = dir.join("doveadm.log");
    let doveadm = w(
        "doveadm",
        &format!(
            "#!/bin/sh\nprintf '%s|' \"$@\" >> {}\necho >> {}\n",
            log.display(),
            log.display()
        ),
    );
    std::fs::set_permissions(&doveadm, std::fs::Permissions::from_mode(0o755)).unwrap();
    let asked = dir.join("asked.json");
    fake_tier2(&dir.join("t2.sock"), asked.clone());

    let records = dir.join("records.jsonl");
    let daemon = Kill(
        Command::new(env!("CARGO_BIN_EXE_firstreadd"))
            .args(["--socket", dir.join("f.sock").to_str().unwrap()])
            .args(["--mac-key", "test", "--data-class", "synthetic"])
            .args(["--records", records.to_str().unwrap()])
            .args([
                "--verdict-combiner",
                &format!("phishing={}", phishing.display()),
            ])
            .args(["--tier2", dir.join("t2.sock").to_str().unwrap()])
            .args(["--tier2-calibration", cal.to_str().unwrap()])
            .args(["--rules", dir.join("rules").to_str().unwrap()])
            .args([
                "--hook-c",
                doveadm.to_str().unwrap(),
                "--hook-c-folders",
                "junk=Junk",
            ])
            .args(["--api-socket", dir.join("api.sock").to_str().unwrap()])
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for("the daemon", || dir.join("api.sock").exists());

    let mut s = UnixStream::connect(dir.join("f.sock")).unwrap();
    let req = Request {
        v: 1,
        user: "alice@lab.invalid".into(),
        sender: "service@noorderbank-veilig.example".into(),
        recipient: "alice@lab.invalid".into(),
        orig_recipient: None,
        message_len: PHISH.len() as u64,
    };
    write_frame(&mut s, &serde_json::to_vec(&req).unwrap()).unwrap();
    s.write_all(PHISH).unwrap();
    let reply: Reply =
        serde_json::from_slice(&read_frame(&mut s, MAX_JSON_FRAME).unwrap()).unwrap();
    // At delivery the phishing combiner lacks tier 2's answer: no verdict, no folder.
    assert_eq!(reply.directive.folder, None);
    assert!(!reply.directive.keywords.contains(&"$Phishing".to_string()));

    wait_for("hook C", || {
        log.exists() && std::fs::read_to_string(&log).unwrap().lines().count() == 2
    });
    let calls = std::fs::read_to_string(&log).unwrap();
    let calls: Vec<&str> = calls.lines().collect();
    assert_eq!(
        calls[0],
        "flags|add|-u|alice@lab.invalid|$Phishing fr-bank|header|Message-ID|<p1@noorderbank-veilig.example>|"
    );
    assert_eq!(
        calls[1],
        "move|-u|alice@lab.invalid|Junk|mailbox|INBOX|header|Message-ID|<p1@noorderbank-veilig.example>|NOT|KEYWORD|$NotJunk|"
    );
    let specs: serde_json::Value = serde_json::from_slice(&std::fs::read(&asked).unwrap()).unwrap();
    let ids: Vec<&str> = specs
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["risk_phishing", "rule:bank"],
        "only what tier 2 has a calibration for"
    );
    assert_eq!(specs[1]["text"], "Mail that claims to come from my bank");

    let lines = std::fs::read_to_string(&records).unwrap();
    assert_eq!(
        lines.lines().count(),
        2,
        "the delivery and its tier-2 update"
    );
    let (code, rec) = http_get(
        &dir.join("api.sock"),
        &format!("/v1/messages/{}", reply.stamp_id),
        "Alice@lab.invalid",
    );
    assert_eq!(code, 200);
    assert_eq!(rec["provenance"]["tiers"], serde_json::json!([0, 2]));
    assert_eq!(rec["verdicts"][0]["kind"], "phishing");
    assert_eq!(rec["directive"]["folder"], "junk");
    assert_eq!(rec["tags"], serde_json::json!(["bank"]));
    let (code, _) = http_get(
        &dir.join("api.sock"),
        &format!("/v1/messages/{}", reply.stamp_id),
        "bob@lab.invalid",
    );
    assert_eq!(code, 404, "another mailbox gets nothing");
    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}
