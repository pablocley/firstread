# ADR-0002 · Integrate at final delivery, not as an IMAP / POP3 proxy

Status: accepted

## Options

| option | for | against |
|---|---|---|
| proxy between clients and the IMAP / POP3 server | sees exactly what clients fetch | TLS termination, IDLE, every client's quirks, work repeated on every fetch, a new single point of failure for reading mail |
| SMTP milter only | can reject before acceptance | Postfix only (Exim has no milter, per [Rspamd's integration table](https://docs.rspamd.com/tutorials/integration)); no per-mailbox context at that point for multi-recipient mail |
| **Dovecot delivery (LMTP / LDA) via Sieve `vnd.dovecot.filter`** | runs once per mailbox copy with the recipient known; works under any MTA; Sieve can set keywords and folders in the same step | a process per delivery (kept tiny; the daemon does the work); needs the sieve_extprograms plugin |

## Decision

Primary inbound integration is at Dovecot delivery. The milter is optional for pre-acceptance
actions on Postfix stacks and is the main hook for outbound submission. Post-delivery updates go
through `doveadm flags` or IMAP. No proxy.

## Consequences

- The "between IMAP and POP" position is met where both protocols read from: the mailbox.
- Results are written into the message, so they cost nothing per fetch and survive firstread
  being turned off ([ADR-0005](0005-results-live-in-the-message.md)).
- Recipient-specific signals (sender relationship, vendor IBAN history) are possible, because
  delivery happens per mailbox.
