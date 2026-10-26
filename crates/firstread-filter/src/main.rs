//! `firstread-filter`: see the library docs. Until the daemon exists, every message takes the
//! fallback (foreign firstread headers removed, nothing else changed), which is the same
//! behaviour it will have when the daemon is unreachable.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use firstread_core::directive::DirectivePolicy;
use firstread_filter::{Outcome, finish};

fn main() -> ExitCode {
    // Read to the end in every case: a program that leaves input unread fails the action.
    let mut message = Vec::new();
    if let Err(e) = io::stdin().lock().read_to_end(&mut message) {
        eprintln!("firstread-filter: reading the message failed: {e}");
        return ExitCode::FAILURE;
    }
    match finish(&message, None, &DirectivePolicy::default()) {
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
