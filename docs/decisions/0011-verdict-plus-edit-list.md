# ADR-0011 · Output is a verdict plus an edit list, never a new message

Status: accepted

## Context

Milter returns a code plus modification calls; Rspamd returns an action, a score, symbols and a
`milter` block of headers to add and remove; SpamAssassin's `HEADERS` method returns only the
changed headers; Sieve applies `fileinto`, `addflag`, `addheader`. In all of them the original
message stays authoritative and the host applies a bounded set of changes
([12 · Interfaces](../12-interfaces.md)).

## Decision

- firstread's synchronous output is a **directive**: header removals (own namespace and
  untrusted `Authentication-Results` only), header additions, keywords, a folder, and at SMTP hooks
  a return code. Nothing else.
- No firstread output may change the body, strip attachments, change recipients, discard or
  redirect mail.
- At Dovecot delivery, `firstread-filter` applies the header edits to the original bytes itself,
  touching only the header block, and Sieve reads the derived folder and keyword headers for
  `addflag` and `fileinto` (how, and how forged copies are kept out: ADR-0013). Sieve variable size
  limits do not apply. Hosts that forbid external rewriting can use `execute :pipe :output` plus
  `editheader` instead.
- The full result is a separate, versioned **record** (JSON) for the store, the API and events.
- Stamp headers carry a per-deployment MAC so a stamp inside imported or appended mail cannot pass
  as a real one.

## Consequences

- The highest-risk code in the delivery path, the function that writes the message back, is
  small, fuzzed, and has one property test that matters: body out equals body in.
- Clients see standard keywords and folders; machines see one parseable header and the API.
- Compatibility headers in SpamAssassin format are possible for platforms without another scanner,
  but are off by default and never overwrite a scanner's headers.
