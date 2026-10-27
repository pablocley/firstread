//! The daemon with mailbox memory, end to end over its two sockets: a delivery is decided from
//! what the mailbox remembers, the owner's action teaches the next decision, firstread's own
//! actions are never learned, one mailbox never teaches another, and forgetting erases.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use firstread_core::wire::{MAX_JSON_FRAME, Reply, Request, read_frame, write_frame};

struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_for(p: &Path) {
    let t = Instant::now();
    while !p.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "{} never appeared",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn(dir: &Path) -> Child {
    let _ = std::fs::remove_file(dir.join("d.sock"));
    let _ = std::fs::remove_file(dir.join("f.sock"));
    let child = Command::new(env!("CARGO_BIN_EXE_firstreadd"))
        .args(["--socket", dir.join("d.sock").to_str().unwrap()])
        .args(["--feedback-socket", dir.join("f.sock").to_str().unwrap()])
        .args(["--memory", dir.join("mem").to_str().unwrap()])
        .args(["--combiner", dir.join("combiner.json").to_str().unwrap()])
        .args(["--records", dir.join("records.jsonl").to_str().unwrap()])
        .args(["--mac-key", "memtest", "--junk-threshold", "0.99"])
        .args(["--own-actors", "firstread-hookc"])
        .spawn()
        .unwrap();
    wait_for(&dir.join("d.sock"));
    wait_for(&dir.join("f.sock"));
    child
}

fn start(name: &str) -> Daemon {
    let dir = std::env::temp_dir().join(format!("frd-mem-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Unknown senders go to Junk; a sender the owner rescued before does not.
    std::fs::write(
        dir.join("combiner.json"),
        r#"{"release": "combiner@memtest", "bias": 6.0,
            "weights": {"mailbox.sender_ok_log": -20.0, "mailbox.sender_junk_log": 20.0}}"#,
    )
    .unwrap();
    let child = spawn(&dir);
    Daemon { child, dir }
}

fn msg(from: &str, id: &str) -> Vec<u8> {
    format!("From: {from}\r\nTo: x@lab.invalid\r\nMessage-ID: <{id}>\r\nSubject: Aanbieding\r\n\r\nBekijk onze aanbiedingen.\r\n")
        .into_bytes()
}

fn deliver(d: &Daemon, user: &str, m: &[u8]) -> Option<String> {
    let mut s = UnixStream::connect(d.dir.join("d.sock")).unwrap();
    let req = Request {
        v: 1,
        user: user.into(),
        sender: "s@x.example".into(),
        recipient: user.into(),
        orig_recipient: None,
        message_len: m.len() as u64,
    };
    write_frame(&mut s, &serde_json::to_vec(&req).unwrap()).unwrap();
    s.write_all(m).unwrap();
    let r: Reply = serde_json::from_slice(&read_frame(&mut s, MAX_JSON_FRAME).unwrap()).unwrap();
    // The delivery is applied to memory after the reply; wait until it is logged.
    std::thread::sleep(Duration::from_millis(100));
    r.directive.folder
}

fn feedback(d: &Daemon, user: &str, op: &str, actor: Option<&str>, m: &[u8]) -> String {
    let mut s = UnixStream::connect(d.dir.join("f.sock")).unwrap();
    let req = serde_json::json!({"v": 1, "op": op, "mailbox": user, "actor": actor, "message_len": m.len()});
    write_frame(&mut s, &serde_json::to_vec(&req).unwrap()).unwrap();
    s.write_all(m).unwrap();
    let r: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut s, MAX_JSON_FRAME).unwrap()).unwrap();
    r["result"].as_str().unwrap().to_string()
}

#[test]
fn the_owners_rescue_teaches_the_next_delivery_and_nothing_else() {
    let d = start("rescue");
    let first = msg("news@shop.example", "n1@shop.example");
    assert_eq!(
        deliver(&d, "alice@lab.invalid", &first).as_deref(),
        Some("junk")
    );

    // firstread's own move is dropped, never learned.
    assert_eq!(
        feedback(
            &d,
            "alice@lab.invalid",
            "not_junk",
            Some("firstread-hookc"),
            &first
        ),
        "dropped"
    );
    let second = msg("news@shop.example", "n2@shop.example");
    assert_eq!(
        deliver(&d, "alice@lab.invalid", &second).as_deref(),
        Some("junk")
    );

    // The owner moves the first one out of Junk: the next one from that sender stays in the inbox.
    assert_eq!(
        feedback(
            &d,
            "alice@lab.invalid",
            "not_junk",
            Some("alice@lab.invalid"),
            &first
        ),
        "applied"
    );
    assert_eq!(
        feedback(&d, "alice@lab.invalid", "not_junk", None, &first),
        "duplicate"
    );
    let third = msg("news@shop.example", "n3@shop.example");
    assert_eq!(deliver(&d, "alice@lab.invalid", &third), None);

    // Another mailbox learned nothing from alice.
    assert_eq!(
        deliver(
            &d,
            "bob@lab.invalid",
            &msg("news@shop.example", "n4@shop.example")
        )
        .as_deref(),
        Some("junk")
    );

    // The record names the snapshot that decided.
    let records = std::fs::read_to_string(d.dir.join("records.jsonl")).unwrap();
    let snaps: Vec<String> = records
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["provenance"]["snapshot"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(snaps, vec!["mem/0", "mem/1", "mem/3", "mem/0"]);
    for l in records.lines() {
        assert!(!l.contains("\"errors\":[\"memory"), "{l}");
    }

    // Erasure: alice's memory goes, and the sender is unknown again.
    assert_eq!(
        feedback(&d, "alice@lab.invalid", "forget", None, b""),
        "forgotten"
    );
    assert_eq!(
        deliver(
            &d,
            "alice@lab.invalid",
            &msg("news@shop.example", "n5@shop.example")
        )
        .as_deref(),
        Some("junk")
    );
}

#[test]
fn a_judged_junk_sender_stays_junk_and_the_state_is_hashed_on_disk() {
    let d = start("junk");
    let a = msg("deals@spam.example", "s1@spam.example");
    deliver(&d, "carol@lab.invalid", &a);
    assert_eq!(
        feedback(&d, "carol@lab.invalid", "junk", None, &a),
        "applied"
    );
    let mut found = 0;
    for e in std::fs::read_dir(d.dir.join("mem")).unwrap() {
        let p = e.unwrap().path();
        let text = std::fs::read_to_string(&p).unwrap();
        for clear in ["carol", "deals@", "spam.example", "s1@"] {
            assert!(!text.contains(clear), "{} holds {clear}", p.display());
            assert!(!p.to_string_lossy().contains(clear));
        }
        found += 1;
    }
    assert!(found >= 1, "at least the event log");
}

#[test]
fn memory_survives_a_restart_between_state_saves() {
    let mut d = start("restart");
    let a = msg("news@shop.example", "r1@shop.example");
    assert_eq!(deliver(&d, "erin@lab.invalid", &a).as_deref(), Some("junk"));
    assert_eq!(
        feedback(&d, "erin@lab.invalid", "not_junk", None, &a),
        "applied"
    );
    // Killed before any state save (every 50 events): the event log alone carries the rescue.
    d.child.kill().unwrap();
    d.child.wait().unwrap();
    d.child = spawn(&d.dir);
    assert_eq!(
        deliver(
            &d,
            "erin@lab.invalid",
            &msg("news@shop.example", "r2@shop.example")
        ),
        None
    );
}
