//! `firstread-milter`: Postfix milter front-end (hooks B and E in docs/01-architecture.md).
//!
//! - inbound, optional: reject during SMTP only for overwhelming, authenticated-evidence cases
//! - outbound submission: compromised-account scoring and hard rules; everything else is a signal
//! - Exim has no milter support; Exim stacks use delivery-time filtering inbound and an ACL
//!   integration outbound
//!
//! Intended dependency: `indymilter` (pure Rust, async). Fails open: on any internal error the
//! milter answers "continue".
//! Status: not implemented.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("firstread-milter: not implemented yet (design phase); see docs/05-sending.md");
    ExitCode::FAILURE
}
