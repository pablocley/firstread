//! The delivery-time client.
//!
//! Dovecot's Sieve `vnd.dovecot.filter` runs this program with the message on stdin and
//! replaces the message with whatever it writes to stdout. The intended flow:
//!
//! 1. read the message (bounded size)
//! 2. send it, with the recipient, to `firstreadd` over a Unix socket, with a hard deadline
//! 3. write the stamped message the daemon returns
//! 4. on **any** failure (socket missing, deadline, malformed reply), write the original message
//!    unchanged and exit 0, so delivery always continues
//!
//! Only step 4 exists today: [`pass_through`], which is also the correct fail-open behaviour.

use std::io::{self, Read, Write};

/// Copy the message unchanged. Used as the fail-open path.
pub fn pass_through<R: Read, W: Write>(mut input: R, mut output: W) -> io::Result<u64> {
    let n = io::copy(&mut input, &mut output)?;
    output.flush()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_bytes_through_unchanged() {
        let msg = b"From: a@example.org\r\nSubject: test\r\n\r\nbody\xff\r\n";
        let mut out = Vec::new();
        let n = pass_through(&msg[..], &mut out).unwrap();
        assert_eq!(n as usize, msg.len());
        assert_eq!(out, msg);
    }
}
