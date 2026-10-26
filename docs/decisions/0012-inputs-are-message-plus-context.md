# ADR-0012 · Inputs are the message plus its delivery context, and every decision is replayable

Status: accepted

## Decision

- Every decision is `decide(message bytes, delivery context, state snapshot, recorded lookups,
  config version)`. Nothing else may influence it.
- The delivery context comes from the host, never from the message: at Dovecot delivery from the
  `USER`, `SENDER`, `RECIPIENT` and `ORIG_RECIPIENT` environment variables extprograms receive,
  plus our own border MTA's `Received` line and our authserv-id's results, located by configured
  hostnames (the trust boundary), never by position alone.
- An idempotency key (message bytes plus recipient) gives redelivered messages the same stamp and
  stops learners from counting them twice.
- External lookups (DNS, RDAP) are cached and the values used are recorded with the decision, so a
  replay sees the same world.
- Mail that enters the store without delivery (IMAP APPEND, imports) is not stamped; firstread
  headers inside it are treated as foreign.

## Why

An `.eml` alone cannot tell who it is for, how it arrived or what the mailbox already knows, and
a decision that cannot be replayed cannot be tested, audited or rolled back.
