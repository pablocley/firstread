# 01 · Architecture

## Where it sits

"Between IMAP and POP" exists on every mail stack: **final delivery into the mailbox** (Dovecot
LMTP or LDA). Both protocols read from there. firstread hooks in at delivery, listens to what
happens to mail afterwards, and optionally hooks the SMTP side. Exactly what goes in and what comes
out, and how that matches milter, Rspamd and SpamAssassin conventions, is in
[12 · Interfaces](12-interfaces.md): the input is the message plus its delivery context; the output
is a verdict and a bounded edit list, never a new message.

```
 inbound                                                                               clients
 internet ─► MTA ─► [Rspamd, if present] ─► Dovecot LMTP ─(A)─► mailbox ─► IMAP · POP3 · webmail
              │                                    │              │  ▲            │
              (B) milter, optional                 │     (G) events│  │(C) keyword  │(D) Junk moves
              │                                    ▼              ▼  │   updates    ▼
              └────────────────────────────────► firstreadd ◄────────┴──────────────┘
                                                  │  ▲   │
                         stamp at delivery ◄──────┘  │   └──► (F) API ─► webmail, digest, admin
                                                     │
                     event log ◄── every delivery, every feedback event, every model release
                         │
                         ├─► learners (counters · exemplar memory · personal heads · platform heads)
                         ├─► platform loop (campaigns, retroactive verdicts, digests)
                         └─► commons client ◄──► commons hub(s) ◄──► other deployments   (optional)
 outbound
 client ─► submission ─(E) milter / Exim ACL─► MTA ─► internet
```

| hook | mechanism | role |
|---|---|---|
| **A** delivery | a global `sieve_before` script runs `firstread-filter` as a Sieve `filter` test with the message on stdin and the context in `USER`, `SENDER`, `RECIPIENT`, `ORIG_RECIPIENT`; the filter gets a directive from the daemon over a Unix socket and applies the header edits to the original bytes itself (body untouched); the user's own rules run next; a global `sieve_after` script files and flags from the derived headers ([12 · Interfaces](12-interfaces.md), section 4.1.1) | primary inbound path; MTA-agnostic |
| **B** SMTP milter | `firstread-milter` on Postfix | optional pre-acceptance action; Exim has no milter ([Rspamd's integration table](https://docs.rspamd.com/tutorials/integration)) |
| **C** post-delivery | `doveadm flags add -u <user> <keyword> <search query>` ([doveadm-flags(1)](https://doc.dovecot.org/main/core/man/doveadm-flags.1.html)) or IMAP with a master user; built for tier-2 updates (adds keywords; moves only from INBOX, never for `$NotJunk`; [ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)) | late results and retroactive verdicts on mail already delivered |
| **D** moves | Dovecot IMAPSieve (RFC 6785) on copies into and out of Junk and other folders, and copies reaching Sent; built for Junk and Sent ([12](12-interfaces.md) section 4.6) | strongest implicit feedback |
| **E** outbound | submission milter (Postfix) or Exim ACL | [05-sending.md](05-sending.md) |
| **F** API | HTTP on the daemon; built: the record, read-only, on a local socket, per mailbox ([ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)) | webmail, digest actions, admin, support |
| **G** mailbox events | Dovecot push-notification Lua driver: `message_new`, `message_read`, `message_trash`, `message_expunge`, `flags_set` / `flags_clear` with keyword lists ([plugin docs](https://doc.dovecot.org/main/core/plugins/push_notification_lua.html)) | implicit feedback: read, deleted, flagged, tags removed or added |

To verify on the deployed Dovecot version (the push-notification Lua page is the `main` branch
documentation; 2.4 changed configuration syntax): the event list, and the Sieve behaviour that
[12 · Interfaces](12-interfaces.md) section 7 lists, with one `sieve-test` run per case.

## Three tiers at delivery

| tier | when | what | cost so far (2 vCPU cloud VM; [CPU baseline](measurements/2026-10-26-cpu-baseline.md), [lab loop](measurements/2026-10-26-lab-pareto-loop.md)) |
|---|---|---|---|
| **0 · deterministic** | every message, inline | parse, authenticate, extract, look up sender relationship and reputation counters, fingerprint content, check the content cache | whole delivery path with tier 0 only (filter process, daemon): 5.3 ms per email, 2.3 ms CPU, 5 MB; with recorded DNS lookups not yet measured |
| **1 · small models** | once per *unique content* (cache hit for copies), inline with a deadline, else completed after delivery | one multilingual embedding, then calibrated heads (global plus personal residuals) and the mailbox's exemplar memory | whole path with multilingual-e5-small, ONNX Runtime int8, 192 tokens, no cache: 33 ms mean (p99 56 ms) per email, 53 ms CPU, 385 MB; eager PyTorch fp32 was 92 ms; production CPUs not yet measured |
| **2 · decision model** | asynchronous only | JEV-style typed decisions for unsure cases, user rules, campaign confirmation, OCR of image-only lures | ≈ 2.1 s per question for a 0.8B model eager; GGUF / GPU not yet measured |

The stamp records which tiers completed (`tiers=0,1`). Anything late arrives through hook C.

## The event log

Everything that happens is an append-only event: a delivery (features and decisions, not content),
a feedback event (explicit, implicit, inferred), a learner update, a model release. The log is the
backbone for three things:

- **learning**: learners consume it and update state continuously ([08-learning.md](08-learning.md))
- **replay**: any past day can be re-run through any learner state, which is how "better after a
  week" is measured and how a bad model release is caught before promotion
- **scale**: delivery nodes write events and read state; learners and the platform loop scale
  independently ([11-scale.md](11-scale.md))

Events carry identifiers, features, decisions and versions. Message content stays in the mailbox;
embeddings are stored per unique content under the privacy rules of [06](06-security-privacy.md).

## State per scope

| scope | state | updated |
|---|---|---|
| mailbox | correspondent graph, vendors and bank details seen, exemplar memory, personal head residuals, personal thresholds, folder habits, subscriptions, settings | in real time from events |
| organisation | colleague names and addresses, organisation domains, shared vendors, shared exemplars (admin opt-in) | in real time |
| platform | reputation counters per infrastructure key, campaign clusters and verdicts, content cache, global heads, combiner | counters in real time; heads daily with champion / challenger |
| commons | received indicators with source and corroboration counts | pulled every few minutes |

Store choice: [ADR-0006](decisions/0006-central-store.md).

## Failure modes

| failure | behaviour |
|---|---|
| daemon unreachable, deadline exceeded, malformed or invalid reply | `firstread-filter` writes the original message with only foreign firstread headers removed and exits 0 |
| filter cannot parse the message at all, declines or crashes | exits non-zero; Pigeonhole keeps the message unchanged and the `filter` test is false; the `sieve_before` script deletes any directive headers a sender put in it (verified on Dovecot 2.3.21 for exit 1) |
| filter killed at `sieve_filter_exec_timeout` | on Dovecot 2.3.21 the LMTP process panics and the message is not stored; the filter's own deadline (default 2 s) exists so this never happens |
| state store slow or down | deliver on tier 0 with local caches; mark `degraded`; finish later through hook C |
| a learner produces a worse model | not promoted (champion / challenger on replay); if promoted and alarms fire, roll back to the previous snapshot |
| model file missing or hash mismatch | that tier is skipped and the stamp says so |
| overload | shed in order: inline tier 1, tier 0 extras, backfill, digests; never parsing and authentication |
| commons hub unreachable | no effect on delivery; indicators expire on their own TTL |
| firstread headers that arrived with the message (any spelling, including `Name : value`), or `Authentication-Results` with our authserv-id not added inside our trust boundary | removed before stamping (RFC 8601 section 5); results from our own MTA or Rspamd are kept |
| unparseable MIME | stamp `parse=failed`; body unchanged |

The fail-open rate, degraded rate and per-tier deadline misses are first-class metrics with alerts.

## Crates

| crate | responsibility |
|---|---|
| `firstread-core` | the contract: mail state, delivery context, scopes, signals, typed decisions, providers, the directive, verdicts, feedback, events, the stamp |
| `firstread-parse` | hostile MIME to a normalised `MailState`, visible text, links, attachments, QR codes |
| `firstread-auth` | built: trusted `Authentication-Results`, DKIM (RFC 6376 / 8301 / 8463) and DMARC alignment judged at the delivery time ([ADR-0019](decisions/0019-own-dkim-dmarc-and-memory-v1.md)); to come: SPF, ARC |
| `firstread-net` | built: the DNS contract, every lookup kept for the record, a recorded resolver for replay, a live stub resolver with deadlines, a per-message budget and a cache; to come: DNSBL, MTA-STS / DANE / TLS-RPT, RDAP |
| `firstread-links` | static URL analysis, lookalikes, brand impersonation, checksummed extractors |
| `firstread-ml` | embeddings, heads, calibration, content cache keys in Rust (to come; today the sidecars in `ml/sidecar/` serve tier 1 and tier 2 over the sidecar protocol, and `firstreadd` is their client) |
| `firstread-graph` | mailbox memory (built: senders and domains split by authentication, correspondents, threads the owner started, IBANs per verified domain, the owner's labels; [ADR-0018](decisions/0018-mailbox-memory-v0.md), [ADR-0019](decisions/0019-own-dkim-dmarc-and-memory-v1.md)); organisation memory, sender profiles and folders to come |
| `firstread-learn` | learners over the event log: counters, exemplars, residual heads, platform heads, promotion |
| `firstread-events` | event schema and adapters: delivery, IMAPSieve, push-notification Lua, digest and API feedback |
| `firstread-commons` | indicator export with privacy gates, signing, hub client, and the hub itself |
| `firstread-stamp` | built: the question registry, verdicts to keywords and a folder key by threshold, the detail headers with reasons per language, keywords from facts, user rules, all from data files ([ADR-0020](decisions/0020-verdicts-tier2-hook-c-api.md)); to come: Subject prefix, POP3 thresholds |
| `firstread-digest` | the periodic digest mail and its signed one-tap actions |
| `firstread-outbound` | pre-send checks, submission checks, delivery diagnostics, domain health |
| `firstreadd` | the daemon: sockets, records; built: tier 2 from a bounded queue, hook C, the record API; to come: load shedding, metrics, hook G |
| `firstread-filter` | the delivery-time client Dovecot runs; fails open |
| `firstread-milter` | Postfix milter front-end |
| `firstread` | CLI: inspect, stamp (built), replay, evaluate, and the lab ([13](13-lab.md)) |

Library crates know nothing about sockets, Dovecot or Postfix. Every signal is testable on one
`.eml`; every learner is testable on a recorded event log.
