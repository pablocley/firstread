# ADR-0005 · Results live in the message

Status: accepted

The stamp (headers) is written into the message at delivery and the keywords are set on it.
The central store holds the rich record, keyed by an opaque id that the stamp carries.

- Every client gets the basics with no plugin; POP3 clients get headers.
- Work happens once per message, not per fetch.
- Removing firstread leaves every mailbox readable and every past decision visible.
- Later improvements (tier 2, campaign verdicts) update keywords post-delivery; headers are never
  rewritten after delivery, so the header reflects the decision at delivery time and the API
  reflects the latest one.
