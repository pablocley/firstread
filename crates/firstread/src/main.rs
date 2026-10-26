//! `firstread`: the development CLI.
//!
//! Planned commands:
//! - `firstread inspect <file.eml> [--rcpt <address>]`: run every tier locally and print each
//!   signal, decision, verdict and the stamp that would be written, with timings
//! - `firstread stamp <file.eml>`: print the stamped message as delivery would write it
//! - `firstread check-draft <file.eml>`: run the outbound pre-send checks
//! - `firstread eval <fixtures dir>`: compare results against the `.labels.toml` files
//! - `firstread replay <event log> --from <snapshot>`: re-run learners over recorded events; the
//!   week-one, promotion and poisoning tests in docs/07-evaluation.md are built on this
//!
//! Status: not implemented.

use std::process::ExitCode;

const COMMANDS: [&str; 5] = ["inspect", "stamp", "check-draft", "eval", "replay"];

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if COMMANDS.contains(&cmd.as_str()) {
        eprintln!("firstread {cmd}: not implemented yet (design phase)");
    } else {
        eprintln!("usage: firstread <{}> ...", COMMANDS.join("|"));
    }
    ExitCode::from(2)
}
