//! `firstread-filter`: see the library docs. Until the daemon exists, it passes mail through
//! unchanged, which is the same behaviour it will have when the daemon is unreachable.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let stdin = io::stdin().lock();
    let stdout = io::stdout().lock();
    match firstread_filter::pass_through(stdin, stdout) {
        Ok(_) => ExitCode::SUCCESS,
        // Only reachable on an I/O error. How the deployed Dovecot treats a failing filter
        // program (keep the original, or a Sieve runtime error) must be verified there; report
        // on stderr so it shows in the delivery log.
        Err(e) => {
            eprintln!("firstread-filter: pass-through failed: {e}");
            ExitCode::FAILURE
        }
    }
}
