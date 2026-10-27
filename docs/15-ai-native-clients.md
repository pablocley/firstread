# 15 · AI-native clients: the server organises, the client reads and writes

An AI-native client has an AI layer for what happens after a message is understood: explaining,
summarising, translating, drafting. It does no spam filtering, no folder management, no tagging and
no search indexing of its own. All of that is decided once, at delivery, on the server, and the
client receives it ready to use.

## 1 · Who does what

| server (firstread with the mail server) | client |
|---|---|
| safety verdicts, junk, phishing, fraud | shows them |
| organisation: views, tags, priority, "needs you", "waiting on them" | renders the views |
| search: lexical, semantic, facets, over received **and** sent mail and attachment text | sends the query, shows results |
| entities: amounts, due dates, order numbers, bank-detail changes | uses them in summaries and drafts |
| thread context and pre-send checks | its AI layer drafts with them |
| learning from every correction | sends corrections as feedback |
| a model-safe view of every message (section 5) | gives its AI layer only that view |

Why the server: it is computed once per message instead of once per device, it is identical on
phone, laptop and webmail, nothing has to download the whole mailbox to search it, corrections
land where the learning is, and IMAP and POP3 clients get the same decisions as headers, keywords
and folders ([03](03-client-contract.md)). One record, two projections.

## 2 · Views instead of folders

A view is a saved query over the record, defined on the server: *needs you*, *waiting on them*,
*money*, *later*, *blocked*, *everything*, plus views the user describes in words (a rule answered by
the tier-2 model until a head takes over, [04](04-models.md)). For IMAP clients the same facets
drive the Sieve folders. An AI client never moves mail between folders to organise it; when the
user says "this isn't junk" or "this belongs with the Acme project", that is a feedback call, which
is the strongest label there is ([08](08-learning.md)).

## 3 · Search belongs to the server

Yes: the vectors already exist, because every unique message is embedded at delivery. Search adds:

- **Hybrid ranking**: the lexical index (the mail server's own full-text index where it has one),
  the dense vectors, and filters on the record's facets (sender relationship, category, amounts,
  dates, attachments).
- **Coverage**: Sent mail (indexed from the mailbox events, so drafts can find what the user
  promised) and text extracted from attachments such as PDF invoices.
- **Access control identical to IMAP**: a search never returns a message the same credentials could
  not open over IMAP, shared mailboxes included.
- **Deletion**: an expunged message's vectors and record go with it ([06](06-security-privacy.md)).
- **Measured, not assumed**: embeddings chosen for classification are not automatically good for
  retrieval, so the lab keeps a retrieval set (queries with the messages that answer them, built
  from our own consenting mailboxes) and scores search quality for every embedder
  ([13](13-lab.md), [14](14-providers.md)).

Embeddings are as sensitive as the text. Vec2Text recovered 92% of 32-token inputs exactly from
their embeddings and 89% of full names from clinical notes
([Morris et al., 2023](https://arxiv.org/pdf/2310.06816)). Vectors are encrypted at rest, kept
per mailbox and never shared beyond it, except bulk-content vectors under the k-threshold.

The one thing that stays on the device: a lexical index over what the client has cached, for
offline use. Semantic search needs the server's space and stays there.

## 4 · Protocol

- Dovecot does not serve JMAP: it is not on [jmap.io's list of server implementations](https://jmap.io/software/index.html)
  (checked 2026-10-26), which does list Cyrus, Stalwart and Apache James. On a Dovecot stack the
  client reads messages over IMAP and reads firstread over firstread's API.
- That API uses JMAP's shapes (RFC 8620): a session object whose capabilities are keyed by URI,
  `/get`, `/query` and `/changes` methods, and push for changes. RFC 8620 allows vendor-specific
  capabilities whose identifier "MUST be a URL with a domain owned by the vendor", and extensions
  may add "extra properties on existing data types" ([RFC 8620](https://www.rfc-editor.org/rfc/inline-errata/rfc8620.html),
  sections 1.8 and 2). On a JMAP server, firstread therefore becomes one capability with extra
  properties on `Email`, and an AI client written against it does not change.
- **An MCP server over the same API**, for AI layers that work with tools: search, message facts,
  thread context, views, feedback, pre-send check. It authenticates as the user, its tools are
  read-only by default, and every tool that changes something needs the user's confirmation in
  the client.
- Message ids map to the IMAP message (mailbox, UIDVALIDITY, UID) and survive moves. Which
  Dovecot identifier carries that best is to be verified on the deployed version.

Built ([ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)): `GET /v1/messages/{id}`, the record
with its safety block, read-only on a local socket, only for the record's own mailbox; the front end
that authenticates the user, `model_safe_text`, views, search, feedback over HTTP, check-draft and
MCP are not built.

| endpoint | returns |
|---|---|
| `GET /v1/views`, `GET /v1/views/{id}/messages` | the server's views and their messages, with record summaries |
| `GET /v1/messages/{id}` | the full record, including the safety block of section 5 |
| `GET /v1/messages/{id}/context` | the thread context for drafting (section 6) |
| `GET /v1/search` | hybrid search with facets |
| `POST /v1/feedback` | corrections from the user |
| `POST /v1/check-draft` | pre-send findings ([05](05-sending.md)) |

## 5 · Mail is untrusted input to an AI

EchoLeak (CVE-2025-32711) showed the failure mode: an email with hidden instructions made Microsoft
365 Copilot put internal data into a link or image URL, and the client's automatic image fetch sent
it out with no click; it got past the injection classifier and link redaction (reference-style
Markdown, a URL the content security policy allowed). Microsoft fixed it server-side in May 2025
([paper](https://arxiv.org/html/2509.10540v1)).

firstread gives every message a safety block:

- `sender_trust`: whether the sender's identity is authenticated and known to this mailbox;
- `injection`: P(the message contains instructions addressed to an AI assistant or agent), with
  the spans, as a typed `noul` decision;
- `model_safe_text`: only the text a person would see; hidden text (CSS-hidden, zero-width, same
  colour as the background, tiny fonts) removed and counted; quoted history delimited; links
  replaced by numbered references with their risk.

A detector lowers the risk; only these client rules remove it. A client is firstread-compatible
when its AI layer:

1. receives mail only as `model_safe_text`, inside a block marked as untrusted data, never as instructions;
2. never loads remote content on its own: no automatic images, no URLs assembled from mail content;
3. never calls a tool that sends, forwards, moves, deletes, pays or unsubscribes because a message
   asked for it; every such action is the user's explicit choice;
4. reads only the structured record of a message with a high `injection` probability, unless the
   user opens the message itself;
5. sends every draft through the pre-send check before it leaves.

## 6 · Drafting context

`/context` for a message returns what a draft needs and nothing it should not leak:

- the participants and their relationship to this mailbox (first contact, known supplier, colleague);
- the recent exchanges in the thread, as model-safe text;
- open questions addressed to the user, and commitments the user made in Sent mail;
- facts on file, masked: "this supplier's IBAN on file ends in 1234", "changed since the last invoice";
- with the user's consent, samples of their own sent mail for tone.

The pre-send check closes the loop: replying to a lookalike of a known domain, a recipient typo, a
promised attachment that is missing, a bank detail that differs from the one on file.

## 7 · Corrections

The client never runs its own classification. When its AI layer or its user disagrees with
firstread, it says so through `POST /v1/feedback`, and the scoped learners decide what that teaches
([08](08-learning.md)). Two classifiers that silently disagree would teach nobody anything.
