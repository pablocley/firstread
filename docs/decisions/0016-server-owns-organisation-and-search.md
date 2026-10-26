# ADR-0016 · The server owns organisation and search; clients read, post-process and draft

Status: accepted

## Decision

- Safety verdicts, views, tags, priority, entities and search (lexical, semantic, facets; received
  and sent mail; attachment text) are computed on the server, once per message, and exposed
  through firstread's API and an MCP server over it.
- The API uses JMAP's shapes so it can become a vendor capability on a JMAP mail server; on Dovecot,
  which does not serve JMAP, mail content stays on IMAP.
- Every message carries a safety block for AI clients (sender trust, injection probability,
  model-safe text), and compatible clients follow five rules that keep mail content from acting
  as instructions.
- Clients do not classify. Disagreement is sent back as feedback.

## Consequences

- AI-native clients and IMAP / POP3 clients see the same decisions, as API fields or as headers,
  keywords and folders.
- Search and drafting context need the server, and inherit its access control, retention and
  deletion rules.
- Details: [15 · AI-native clients](../15-ai-native-clients.md).
