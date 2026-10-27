//! `firstread`: the development CLI.
//!
//! Implemented:
//! - `firstread inspect <file.eml> [--trusted-authserv ID,ID]`: parse one message and print the
//!   tier-0 facts and the provider text as JSON
//! - `firstread render-batch <items.jsonl> [--render-max-chars N]`: for each line `{"id", "path"}`
//!   print `{"id", "text_sha256", "text"}` with exactly the text the daemon sends to tier-1
//!   providers, so the lab can embed in bulk without a second renderer
//!
//! - `firstread auth-batch <items.jsonl> [--dns FILE ... [--dns-window FROM,TO]] [--clock message|now]`:
//!   for each line `{"id", "path"}` print our own DKIM and DMARC verdict and every DNS lookup it
//!   made, against DNS recordings (one lookup per line; names they do not hold are temporary
//!   errors; on a clash the earlier file's answer is kept; a message judged outside
//!   `--dns-window`, Unix seconds, gets no answers). `--clock
//!   message` judges signature expiry at the message's Date (the lab's stand-in for its arrival);
//!   `now` at the current time. The lab records DNS with it (`lab/harness/record_dns.py`).
//!
//! - `firstread feedback --socket PATH --mailbox USER (--junk|--not-junk|--sent|--forget)
//!   [--actor NAME] [--at UNIX]`: report one action of the mailbox owner to `firstreadd`'s feedback
//!   socket, the message on stdin (not for `--forget`). Dovecot IMAPSieve scripts call it when
//!   the owner moves mail into or out of Junk or a copy reaches Sent (hook D, lab/l2/).
//!
//! Planned (docs/13-lab.md, docs/07-evaluation.md): `stamp`, `check-draft`, `eval`, `replay`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use firstread_core::wire::{MAX_JSON_FRAME, read_frame, write_frame};

use serde::Deserialize;

#[derive(Deserialize)]
struct Item {
    id: String,
    path: String,
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn flag_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

fn inspect(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("usage: firstread inspect <file.eml>")?;
    let raw = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let trusted: Vec<String> = flag_value(args, "--trusted-authserv")
        .map(|v| v.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let p = firstread_parse::parse(&raw).map_err(|e| format!("parse: {e:?}"))?;
    let auth = firstread_auth::summarise(&p.auth_results, &trusted);
    let out = serde_json::json!({
        "features": firstread_pipeline::features(&p, &auth),
        "auth": {"spf": auth.spf.as_str(), "dkim": auth.dkim.as_str(), "dmarc": auth.dmarc.as_str()},
        "links": p.state.links.iter().map(|l| (&l.href, &l.text)).collect::<Vec<_>>(),
        "text": firstread_pipeline::render(&p, 2000),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn render_batch(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("usage: firstread render-batch <items.jsonl>")?;
    let max: usize = flag_value(args, "--render-max-chars")
        .map(|v| v.parse().map_err(|e| format!("{e}")))
        .transpose()?
        .unwrap_or(2000);
    let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let item: Item = serde_json::from_str(&line).map_err(|e| format!("{e}: {line}"))?;
        let raw = std::fs::read(&item.path).map_err(|e| format!("{}: {e}", item.path))?;
        let rec = match firstread_parse::parse(&raw) {
            Ok(p) => {
                let text = firstread_pipeline::render(&p, max);
                serde_json::json!({
                    "id": item.id,
                    "text_sha256": firstread_pipeline::sha256_hex(text.as_bytes()),
                    "text": text,
                })
            }
            Err(e) => serde_json::json!({"id": item.id, "error": format!("{e:?}")}),
        };
        writeln!(out, "{rec}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn verification_json(id: &str, at: u64, v: &firstread_auth::Verification) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "at": at,
        "dkim": v.dkim.iter().map(|s| serde_json::json!({
            "result": s.status.as_str(), "reason": s.reason, "d": s.domain, "s": s.selector,
            "a": s.algorithm, "whole_body": s.whole_body,
        })).collect::<Vec<_>>(),
        "dmarc": v.dmarc.outcome.as_str(),
        "policy": v.dmarc.policy.map(|p| p.as_str()),
        "from_domain": v.dmarc.from_domain,
        "aligned": v.dmarc.aligned_domain,
        "identity_verified": v.identity_verified(),
        "lookups": v.lookups,
    })
}

fn auth_batch(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("usage: firstread auth-batch <items.jsonl> [--dns FILE ... [--dns-window FROM,TO]] [--clock message|now]")?;
    let mut dns = firstread_net::RecordedDns::new();
    for p in flag_values(args, "--dns") {
        dns.extend(
            firstread_net::RecordedDns::load(std::path::Path::new(&p))
                .map_err(|e| format!("{p}: {e}"))?,
        );
    }
    if let Some(w) = flag_value(args, "--dns-window") {
        let (from, to) = firstread_net::parse_window(&w)?;
        dns.set_window(from, to);
    }
    let clock = flag_value(args, "--clock").unwrap_or_else(|| "message".into());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let item: Item = serde_json::from_str(&line).map_err(|e| format!("{e}: {line}"))?;
        let raw = std::fs::read(&item.path).map_err(|e| format!("{}: {e}", item.path))?;
        let parsed = firstread_parse::parse(&raw).ok();
        let from = parsed
            .as_ref()
            .and_then(|p| p.state.from.as_ref().map(|f| f.address.clone()));
        let at = match clock.as_str() {
            "now" => now,
            "message" => parsed
                .as_ref()
                .and_then(|p| p.date)
                .and_then(|d| u64::try_from(d).ok())
                .unwrap_or(0),
            other => return Err(format!("unknown clock {other}")),
        };
        let v = firstread_auth::verify(&raw, from.as_deref(), at, &dns);
        writeln!(out, "{}", verification_json(&item.id, at, &v)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

const FEEDBACK_USAGE: &str = "usage: firstread feedback --socket PATH --mailbox USER \
(--junk|--not-junk|--sent|--forget) [--actor NAME] [--at UNIX] < message";

fn feedback(args: &[String]) -> Result<(), String> {
    let socket = flag_value(args, "--socket").ok_or(FEEDBACK_USAGE)?;
    let mailbox = flag_value(args, "--mailbox").ok_or(FEEDBACK_USAGE)?;
    let has = |f: &str| args.iter().any(|a| a == f);
    let ops: Vec<&str> = [
        ("--junk", "junk"),
        ("--not-junk", "not_junk"),
        ("--sent", "sent"),
        ("--forget", "forget"),
    ]
    .iter()
    .filter(|(f, _)| has(f))
    .map(|(_, o)| *o)
    .collect();
    let [op] = ops.as_slice() else {
        return Err(FEEDBACK_USAGE.into());
    };
    let at: Option<i64> = flag_value(args, "--at")
        .map(|v| v.parse().map_err(|e| format!("--at: {e}")))
        .transpose()?;
    let mut message = Vec::new();
    if *op != "forget" {
        std::io::stdin()
            .read_to_end(&mut message)
            .map_err(|e| format!("stdin: {e}"))?;
    }
    let mut s = UnixStream::connect(&socket).map_err(|e| format!("{socket}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let req = serde_json::json!({
        "v": 1,
        "op": op,
        "mailbox": mailbox,
        "actor": flag_value(args, "--actor"),
        "at": at,
        "message_len": message.len(),
    });
    write_frame(
        &mut s,
        &serde_json::to_vec(&req).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write: {e}"))?;
    s.write_all(&message).map_err(|e| format!("write: {e}"))?;
    let reply = read_frame(&mut s, MAX_JSON_FRAME).map_err(|e| format!("read reply: {e}"))?;
    println!("{}", String::from_utf8_lossy(&reply));
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = args
        .split_first()
        .map_or(("", &[][..]), |(c, r)| (c.as_str(), r));
    let result = match cmd {
        "inspect" => inspect(rest),
        "render-batch" => render_batch(rest),
        "auth-batch" => auth_batch(rest),
        "feedback" => feedback(rest),
        "stamp" | "check-draft" | "eval" | "replay" => {
            Err(format!("firstread {cmd}: not implemented yet"))
        }
        _ => Err("usage: firstread <inspect|render-batch|auth-batch|feedback> ...".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
