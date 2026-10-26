# ADR-0013 · Sieve acts only on headers the filter vouched for, after the user's own rules

Status: accepted

## Context

The directive reaches Dovecot as headers (`X-Firstread-Folder`, `X-Firstread-Keywords`) that a
Sieve script turns into `fileinto` and `addflag`. A sender can put headers with the same names in
any message. If the filter is down, declines or crashes and the message passes unchanged, a
script that reads those headers unconditionally would act on the sender's choice. Header names
are also not always spelled the obvious way: Dovecot's parser skips whitespace before the colon.

Pigeonhole's source (`main`, October 2026) settles how the pieces behave: used as a test,
`filter` is true only when the program exits successfully, and on a non-zero exit the message is
kept unchanged and the script continues (`cmd-filter.c`); scripts in a `sieve_before` / user /
`sieve_after` sequence share one message context, so the filtered message is what later scripts
and the final keep see; the sequence ends as soon as a script leaves no keep, for example after a
`fileinto` (`sieve.c`). Details and links: [12 · Interfaces](../12-interfaces.md) section 4.1.1.

## Decision

- The filter removes every header in firstread's namespace that arrived with the message, on every
  path that writes output, matching names as Dovecot reads them. Without a usable directive it
  writes the message with only those headers removed and exits 0. When even that is impossible it
  exits non-zero and writes nothing.
- The folder and keyword headers are rendered only from the validated directive: a folder **key**
  from the mode's allowed set and IMAP keyword atoms, never user-owned keywords.
- A global `sieve_before` script runs the filter as a test and, when it is false, deletes the two
  directive headers (`editheader`, enabled for global scripts only through `sieve_global_extensions`).
- The user's own script runs next and sees every firstread header.
- A global `sieve_after` script, which runs only for messages the user's rules left in place, sets
  the keywords and maps each folder key to a literal `fileinto`.
- Keywords for messages the user's rules filed are set right after delivery through hook C.
- No body banners: firstread never writes the body. Webmail renders banners from the API record.

## Consequences

- Nothing a sender writes can choose a folder, set a keyword or pass as a firstread stamp.
- The user's rules always win, and one message ends in exactly one folder.
- Platforms that cannot enable `editheader` for global scripts put everything inside
  `if filter … { }` in `sieve_before`: equally safe, but messages firstread files away then skip
  the user's own rules. The client contract says which mode a platform runs.
- The predicted behaviour is confirmed per deployed Dovecot version with one `sieve-test` run per
  case (section 7 of the interfaces document).
