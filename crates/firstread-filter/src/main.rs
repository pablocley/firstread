//! `firstread-filter`: see the library docs.
//!
//! Asks `firstreadd` for a directive over the Unix socket in `FIRSTREAD_SOCKET` (default
//! `/run/firstread/filter.sock`) within `FIRSTREAD_DEADLINE_MS` (default 2000), re-validates the
//! reply, and applies it. Any failure on the way (socket missing, deadline, malformed or invalid
//! reply) takes the fallback: foreign firstread headers removed, nothing else changed.
//!
//! The deadline is absolute: the daemon is asked on a separate thread and the main thread stops
//! waiting when the deadline passes, however the socket behaves. The filter must never reach
//! Pigeonhole's `sieve_filter_exec_timeout`: on Dovecot 2.3.21 a filter killed at that timeout
//! made the LMTP process panic and nothing was delivered (docs/measurements/2026-10-26-lab-v0.md).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use firstread_core::context::DeliveryContext;
use firstread_core::directive::{Directive, DirectivePolicy};
use firstread_core::wire::{MAX_JSON_FRAME, Reply, Request, read_frame, write_frame};
use firstread_filter::{Outcome, finish};

fn deadline() -> Duration {
    let ms = std::env::var("FIRSTREAD_DEADLINE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2000);
    Duration::from_millis(ms.max(1))
}

fn ask_daemon(message: &[u8], deadline: Duration) -> Result<Directive, String> {
    let ctx = DeliveryContext::from_dovecot_env(|k| std::env::var(k).ok())
        .map_err(|e| format!("context: {e:?}"))?;
    let socket = std::env::var("FIRSTREAD_SOCKET")
        .unwrap_or_else(|_| "/run/firstread/filter.sock".to_string());
    let timeout = Some(deadline);
    let mut s = UnixStream::connect(&socket).map_err(|e| format!("connect {socket}: {e}"))?;
    s.set_read_timeout(timeout).map_err(|e| e.to_string())?;
    s.set_write_timeout(timeout).map_err(|e| e.to_string())?;
    let req = Request {
        v: 1,
        user: ctx.user,
        sender: ctx.sender,
        recipient: ctx.recipient,
        orig_recipient: ctx.orig_recipient,
        message_len: message.len() as u64,
    };
    let head = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    write_frame(&mut s, &head).map_err(|e| format!("send: {e}"))?;
    s.write_all(message).map_err(|e| format!("send: {e}"))?;
    let raw = read_frame(&mut s, MAX_JSON_FRAME).map_err(|e| format!("reply: {e}"))?;
    let reply: Reply = serde_json::from_slice(&raw).map_err(|e| format!("reply: {e}"))?;
    reply
        .directive
        .validate()
        .map_err(|e| format!("invalid directive: {e:?}"))
}

fn main() -> ExitCode {
    // Read to the end in every case: a program that leaves input unread fails the action.
    let mut message = Vec::new();
    if let Err(e) = io::stdin().lock().read_to_end(&mut message) {
        eprintln!("firstread-filter: reading the message failed: {e}");
        return ExitCode::FAILURE;
    }
    let policy = DirectivePolicy::default();
    let limit = deadline();
    let (tx, rx) = mpsc::channel();
    let copy = message.clone();
    std::thread::spawn(move || {
        let _ = tx.send(ask_daemon(&copy, limit));
    });
    let directive = match rx.recv_timeout(limit) {
        Ok(Ok(d)) => Some(d),
        Ok(Err(e)) => {
            eprintln!("firstread-filter: fallback: {e}");
            None
        }
        Err(_) => {
            eprintln!(
                "firstread-filter: fallback: deadline of {} ms passed",
                limit.as_millis()
            );
            None
        }
    };
    match finish(&message, directive.as_ref(), &policy) {
        Outcome::Write(out) => {
            let mut stdout = io::stdout().lock();
            match stdout.write_all(&out).and_then(|()| stdout.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("firstread-filter: writing the message failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        // Pigeonhole keeps the message unchanged and the `filter` test is false
        // (cmd-filter.c: a failed program "indicated false result").
        Outcome::Decline => ExitCode::FAILURE,
    }
}
