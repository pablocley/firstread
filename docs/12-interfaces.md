# 12 · Interfaces: exactly what goes in and what comes out

The short version: **the message is the payload, not the whole input; and the output is never a
new message.** firstread returns a decision plus a small list of edits, and the mail system that
called it applies them. That is how every established mail filter works, and firstread follows it.

## 1 · Where firstread sits in the mail architecture

RFC 5598 (Internet Mail Architecture) names the roles a message passes through: the author's
client (MUA), submission (MSA), relays (MTA), delivery (MDA), the message store (MS) and the
recipient's client (MUA). firstread is not a new role. It attaches to existing ones:

| role | what already runs there | what firstread does there |
|---|---|---|
| MSA (submission) | Postfix / Exim on port 587 | outbound checks (hook E): accept, defer, alert |
| MTA (border relay) | Postfix / Exim, Rspamd | nothing by default; optional milter for overwhelming cases (hook B). Spam scoring before acceptance stays with Rspamd |
| **MDA (final delivery)** | Dovecot LMTP / LDA running Sieve | **the main decision point** (hook A): one decision per recipient mailbox, with that mailbox's memory |
| MS (message store) | Dovecot mailboxes | reads events (hooks D, G); applies late results (hook C) |
| MUA (clients, webmail) | Thunderbird, Apple Mail, Outlook, webmail | nothing installed; clients read headers, keywords and folders; webmail may use the API (hook F) |

Why the MDA and not the MTA: one SMTP transaction can carry one message to fifty recipients.
At the MTA there is one decision for all fifty; only at delivery does each copy meet its own
mailbox, so only there can "you have never written to this sender" or "this supplier's IBAN
changed" be computed.

## 2 · What filters in this space return (the de facto standards)

| system | input | output | applied by |
|---|---|---|---|
| **milter** (Sendmail / Postfix filter protocol) | SMTP stages, headers, body | a return code (`SMFIS_CONTINUE`, `SMFIS_ACCEPT`, `SMFIS_REJECT`, `SMFIS_TEMPFAIL`, `SMFIS_DISCARD`, …) plus modification calls (`smfi_addheader`, `smfi_chgheader`, `smfi_insheader`, `smfi_replacebody`, recipient changes, `smfi_quarantine`), all at end of message ([Milter API](https://web.mit.edu/freebsd/head/contrib/sendmail/libmilter/docs/api.html)) | the MTA |
| **Rspamd** `/checkv2` | the message, with envelope and context in request headers (`From`, `Rcpt`, `IP`, `Helo`, `Hostname`, `Queue-Id`, `Deliver-To`, `User`, TLS fields) | JSON: `action` (`no action`, `greylist`, `add header`, `rewrite subject`, `soft reject`, `reject`), `score`, `required_score`, `symbols` (name, score, options), `messages`, and a `milter` block with `add_headers` (value, order) and `remove_headers` (name, which instance) ([Rspamd protocol](https://docs.rspamd.com/developers/protocol/)) | the MTA or the Rspamd proxy |
| **SpamAssassin** `spamd` | the message, optional `User` | per method: `CHECK` (verdict only), `HEADERS` (changed headers only), `PROCESS` (the whole rewritten message), `SYMBOLS`, `REPORT`, and `TELL` for learning ([spamd protocol](https://aiospamc.readthedocs.io/en/main/protocol.html)); headers `X-Spam-Flag: YES` (spam only), `X-Spam-Status: Yes|No, score=… required=… tests=… autolearn=…`, `X-Spam-Level`, `X-Spam-Checker-Version` ([spamassassin(1p)](https://man.archlinux.org/man/spamassassin.1p.en)) | the caller |
| **Dovecot Sieve programs** | `filter`: the message on stdin; `execute :pipe :output "var"`: the message on stdin, stdout captured into a variable ([Pigeonhole tests](https://opensource.apple.com/source/dovecot/dovecot-293/dovecot-pigeonhole/tests/plugins/extprograms/execute/execute.svtest.auto.html)) | `filter`: a message on stdout; `execute`: a string (variables default to at most 4k, [variables](https://doc.dovecot.org/2.3/settings/pigeonhole-ext/variables/)) | the Sieve script (`fileinto`, `addflag`, `addheader`) |

The common shape: **a verdict and a list of edits, applied by the host, with the original
message as the authority.** The one standardised result header in this space is
`Authentication-Results` (RFC 8601), for authentication only. Spam and classification results
travel in product-specific headers (`X-Spam-*` from SpamAssassin, Rspamd's own headers).
Message state for clients is standardised as IMAP / JMAP keywords (IANA registry), and filing
as Sieve (`fileinto` RFC 5228, `imap4flags` RFC 5232, `editheader` RFC 5293).

firstread therefore outputs a verdict, an edit list in the same terms Rspamd's `milter` block uses
(add headers with an order, remove headers by name and instance), keywords and a folder key.

## 3 · Inputs

Every per-message decision is a function of exactly these inputs, and the record names all of
them, so any decision can be replayed:

```
decide(message bytes, delivery context, state snapshot, recorded lookups, config version)
    -> (directive, record)
```

### 3.1 The message

- The bytes exactly as Dovecot hands them over. `sieve_filter_input_eol` defaults to `crlf`
  ([sieve_extprograms](https://doc.dovecot.org/latest/core/plugins/sieve_extprograms.html)), but
  firstread accepts CRLF and LF and never normalises what it writes back.
- Read to the end, always: Dovecot fails the action when a program does not consume its input.
- Header names are read the way Dovecot reads them: its parser skips whitespace before the colon
  ([message-header-parser.c](https://github.com/dovecot/core/blob/main/src/lib-mail/message-header-parser.c),
  "get name, skip LWSP before ':'"), so `X-Firstread-Folder : junk` is the same header to firstread
  as to Sieve. A differential test against Pigeonhole's own parser keeps it that way (section 7).
- Size: parsed by streaming with hard limits; beyond them, decisions use headers, structure and the
  first part of the text, and the record says the content was truncated.
- Encrypted (S/MIME, PGP) content is not readable; the record says so; header-level signals still apply.

### 3.2 The delivery context

The message alone does not say who it is for, who sent it on the envelope, or where it came from.
That comes from the host:

| field | source at hook A (Dovecot) | trust |
|---|---|---|
| mailbox user | `USER` environment variable (Dovecot passes `HOME`, `USER`, `SENDER`, `RECIPIENT`, `ORIG_RECIPIENT` to extprograms) | trusted |
| envelope sender | `SENDER` | trusted (as received by our MTA) |
| envelope recipient, original recipient | `RECIPIENT`, `ORIG_RECIPIENT` (differ after aliasing or forwarding) | trusted |
| client IP, HELO, TLS, time of arrival | the `Received` line added by **our own border MTA**, found by configured hostnames, never "the topmost line" | trusted only at the configured boundary |
| upstream authentication and spam results | `Authentication-Results` with our authserv-id and scanner headers added inside the boundary | trusted only inside the boundary |
| direction | derived: from the internet, from another mailbox on the same platform, a forward, a bounce | derived, recorded |
| idempotency key | hash of message bytes plus recipient | derived |

LMTP can deliver the same message again after a temporary failure. The idempotency key makes the
second delivery get the same stamp id and makes learners count it once.

### 3.3 State, lookups, configuration

- **State snapshot:** the learner state the decision read (counters, exemplars, heads), by id.
- **Lookups:** DNS, RDAP and similar answers are cached, and the values used are recorded in the
  event, because the internet changes and replay must not. Built for DNS (`firstread-net`): every
  lookup our own DKIM and DMARC checks make is in the record (`input.lookups`, with the time the
  message was judged at, `input.at`); a recording replays them, where a name it does not hold is
  a temporary error, never "no record", and a message judged outside the period the recording
  stands for gets no answers at all.
- **Configuration version:** thresholds, modes, data files.

### 3.4 Never inputs

The content behind URLs (never fetched), attachments as programs (never executed), anything that
arrives after the deadline, and any header claiming to be from firstread or our authserv-id that
was not added inside our own boundary.

### 3.5 How mail enters the mailbox, and what firstread does with each path

| path | stamped at entry | notes |
|---|---|---|
| LMTP / LDA delivery from the MTA | **yes** (hook A) | the normal path |
| IMAP APPEND by the user (Sent copies, drag-and-drop, client imports) | no | becomes an event (`message_append`); Sent copies feed the correspondent graph; any firstread headers inside are treated as foreign and untrusted |
| migrations and bulk imports | no | backfill treats them like existing mail |
| Sieve `redirect`, vacation replies, forwards out | n/a | they leave through the outbound path (hook E) |
| mail firstread itself generates (digests, notices) | own path | DKIM-signed by the platform and carrying a firstread MAC; mail that only *claims* to be a firstread digest is treated as impersonation |

## 4 · Outputs

### 4.1 The directive (synchronous, to the host)

A small, bounded, validated structure. It is the only thing the delivery path waits for.

| operation | allowed | notes |
|---|---|---|
| remove header | yes | by name and instance (all, n-th, n-th from the end), like Rspamd's `remove_headers`; only firstread's own namespace and untrusted `Authentication-Results` claiming our authserv-id. Every header in firstread's namespace that arrived with the message is removed regardless |
| add header | yes | only firstread's namespace and `Authentication-Results` (plus `X-Spam-*` in compatibility mode); name and value validated (section 5), folded, size-capped; added at the top, as trace-like fields conventionally are |
| prefix Subject | yes | in place, once (not again if already there), header only; strict thresholds only ([03](03-client-contract.md)) |
| set keywords | yes | IMAP atoms only; registered keywords plus the configured prefix; never user-owned ones such as `$NotJunk` |
| choose folder | yes | a folder **key** from the mode's allowed set (`junk`, `later`, …), never a folder name; the Sieve script maps each key to a real folder with a literal `fileinto` |
| SMTP action (milter hooks only) | continue, accept, tempfail, reject | reject only for policy-level certainty; delivery-time never rejects |
| change the body, strip attachments, change recipients, discard | **never** | no firstread output can delete, rewrite or redirect mail |

How a host applies it:

| host | mechanism | default |
|---|---|---|
| Dovecot, standard | Sieve `filter` runs `firstread-filter` as a test from a global script before the user's own (section 4.1.1). The filter reads the message, asks the daemon, applies the header edits to the original bytes itself (header block only; body bytes untouched by construction), writes the result. A global script after the user's own reads the derived folder and keyword headers to `addflag` and `fileinto` | **yes** |
| Dovecot, no external rewriting allowed | Sieve `execute :pipe :output` returns a compact directive (must fit the 4k variable default); Sieve applies it with `addheader` (`editheader` is off by default and caps values at 2048 bytes, [editheader](https://doc.dovecot.org/2.3/configuration_manual/sieve/extensions/editheader/)), `addflag`, `fileinto` | alternative |
| Postfix milter (hooks B, E) | milter return code plus `smfi_addheader` / `smfi_chgheader` | optional |

The deadline for the whole call is configured well below `sieve_filter_exec_timeout` (default
10 s) and is measured; `firstread-filter` enforces it itself (`FIRSTREAD_DEADLINE_MS`, default
2,000 ms), on a thread separate from the daemon call. This is not only about latency: on Dovecot
2.3.21 / Pigeonhole 0.5.21 a filter killed at `sieve_filter_exec_timeout` crashes the LMTP process
and the message is not stored (section 7). Past the deadline, or with the daemon unreachable or its
directive invalid, the filter writes the original message with only foreign firstread headers
removed and exits 0. If even that is impossible (no line ending at all) it writes nothing and exits
non-zero; so does a crash.

#### 4.1.1 The Sieve side

Established from Pigeonhole's source and specification (`main`, October 2026):

- Used as a **test**, `filter` is true only when the program exits successfully; on a non-zero exit
  the message is not replaced and the script continues
  ([cmd-filter.c](https://github.com/dovecot/pigeonhole/blob/main/src/plugins/sieve-extprograms/cmd-filter.c):
  "program indicated false result"; [specification](https://github.com/dovecot/pigeonhole/blob/main/doc/rfc/spec-bosch-sieve-extprograms.txt)
  section 8: a filter program "may return a 'false' result to indicate that the message was not
  changed"). Used as a plain action, an execution failure may fail the whole script instead.
- In a sequence of scripts (`sieve_before`, the user's script, `sieve_after`) all scripts share one
  result and one message context, so later scripts and the final keep see the filtered message
  ([sieve.c](https://github.com/dovecot/pigeonhole/blob/main/src/lib-sieve/sieve.c) `struct
  sieve_multiscript`; [sieve-result.c](https://github.com/dovecot/pigeonhole/blob/main/src/lib-sieve/sieve-result.c)).
- The sequence continues only while keep is in effect: a `fileinto` in an earlier script ends it
  (`sieve_multiscript_run`; the older
  [Pigeonhole configuration page](https://opensource.apple.com/source/dovecot/dovecot-239/dovecot/doc/wiki/Pigeonhole.Sieve.Configuration.txt.auto.html)
  says the same).

So the default deployment is two global scripts around the user's own
([ADR-0013](decisions/0013-sieve-acts-only-on-vouched-headers.md)):

```sieve
# sieve_before: stamp; if the filter did not vouch for the message, drop the directive headers a
# sender may have forged (editheader enabled for global scripts only, sieve_global_extensions)
require ["vnd.dovecot.filter", "editheader"];
if not filter "firstread-filter" {
    deleteheader "X-Firstread-Folder";
    deleteheader "X-Firstread-Keywords";
}
```

```sieve
# sieve_after: runs only for messages the user's own rules left where they were
require ["fileinto", "imap4flags", "variables"];
if header :matches "X-Firstread-Keywords" "*" {
    addflag "${1}";
}
if header :is "X-Firstread-Folder" "junk" {
    fileinto "Junk";
} elsif header :is "X-Firstread-Folder" "later" {
    fileinto "Later";
} else {
    keep;
}
```

- **The user's rules win:** they run between the two and see every firstread header, so a person
  can write rules on `X-Firstread-Tags`; whatever they file, firstread never files again.
- Keywords for messages the user's rules filed are set right after delivery through hook C.
- One message ends in one folder: firstread's scripts never `fileinto` before the user's script.
- Folder names live in the script (one literal `fileinto` per key, localised as the platform
  wishes); nothing from a header becomes a folder name.
- Where `editheader` cannot be enabled for global scripts, everything moves into the `sieve_before`
  script inside `if filter "firstread-filter" { … }`. That is equally safe, but a message firstread
  files away no longer reaches the user's own rules.

### 4.2 The stamp (the headers in the directive)

| header | for | notes |
|---|---|---|
| `Authentication-Results` | everyone | RFC 8601; our authserv-id |
| `X-Firstread` | machines | one line: version, stamp id, deployment id, tiers, model release, snapshot, top verdict and probability, **MAC** |
| `X-Firstread-Folder`, `X-Firstread-Keywords` | the Sieve scripts | rendered by the filter from the validated folder key and keywords, never supplied as text; any copy that arrived with the message is removed, also when the daemon is down |
| `X-Firstread-Scores`, `-Tags`, `-Sender`, `-Campaign`, `-Reasons` | clients and people | optional detail, switchable per platform |
| `X-Spam-Flag`, `X-Spam-Status` in SpamAssassin format | clients that trust SpamAssassin headers (Thunderbird has a "trust junk mail headers set by SpamAssassin" setting, [example](https://www.inmotionhosting.com/support/email/thunderbird-trust-junk-mail-headers/)) | **compatibility mode only**, for platforms with no other scanner; never overwrites a scanner's own headers |

The MAC is an HMAC with a per-deployment key over the stamp id, deployment id, verdict line and a
hash of the Message-ID. It proves the stamp was made by this deployment, so webmail, the digest
and the API can tell a real stamp from one that arrived inside an imported or appended message.
It does not prove the message is unchanged; it is not a signature over content.

### 4.3 The record (to the store and the API)

The full, versioned result. Field names follow the standards where one exists: authentication
results use RFC 8601 method and result names; explainable contributions look like Rspamd symbols;
model outputs use the typed-decision shape.

```json
{
  "schema": "firstread.verdict/1",
  "id": "st_…",
  "deployment": "dep_…",
  "idempotency_key": "…",
  "input": {
    "message_id_hash": "…", "content_key": "…", "size": 18231, "truncated": false, "encrypted": false,
    "context": { "user": "…", "recipient": "…", "orig_recipient": "…", "sender": "…",
                 "direction": "inbound-internet", "client_ip": "…", "helo": "…", "tls": "TLSv1.3" },
    "snapshot": "snap_…", "config": "cfg_…", "models": ["…"], "lookups": "lk_…"
  },
  "auth": { "spf": "pass", "dkim": [{ "d": "…", "result": "pass" }], "dmarc": "pass", "arc": "none" },
  "symbols": [
    { "name": "FIRST_CONTACT", "scope": "mailbox", "value": true },
    { "name": "IBAN_CHANGED_FOR_VENDOR", "scope": "mailbox", "value": true }
  ],
  "decisions": [
    { "question": "asks_payment_or_bank_change", "kind": "noul", "p": [0.03, 0.97], "tier": 1, "model": "…" },
    { "question": "urgency", "kind": "score", "levels": 6, "p": [0.01, 0.02, 0.05, 0.1, 0.41, 0.41], "tier": 1 }
  ],
  "verdicts": [ { "kind": "fraud", "p": 0.91, "reasons": ["first_contact", "iban_changed"] } ],
  "directive": { "folder": "inbox", "keywords": ["$Phishing"], "subject_prefix": null,
                 "add_headers": ["…"], "remove_headers": ["…"] },
  "provenance": { "tiers": [0, 1], "degraded": false, "timings_ms": { "tier0": 0, "tier1": 0 } }
}
```

(Values above illustrate the shape, not a real message.)

### 4.4 Events

Every decision is one `Delivered` event carrying the record's identifiers, features, decisions,
versions and recorded lookups (not the content). Learning reads events, never the live path.

### 4.5 Deferred outputs

| output | rule |
|---|---|
| late keyword / folder updates (hook C) | idempotent; **never override the user**: a message the user already moved, flagged or un-junked is not touched again; never move mail out of a folder the user chose |
| digest mail | platform-DKIM-signed, MAC'd, opt-in per mode, one-tap actions via POST confirmation pages |
| abuse reports to senders' providers | optional, ARF (RFC 5965) format, only on explicit user "this is a scam" plus platform policy |
| commons indicators | gated, bad-only ([10-commons.md](10-commons.md)) |
| outbound | milter return code at submission; JSON findings from `POST /v1/check-draft` |

### 4.6 Feedback in: what the mailbox owner did (hook D)

Learning reads what people do with their mail ([08](08-learning.md)), never the delivery path. In
the default deployment the owner's actions arrive through Dovecot IMAPSieve (RFC 6785), the
standard way to report spam and ham from IMAP moves:

| owner's action | IMAPSieve rule | reported as |
|---|---|---|
| copies or moves a message into Junk | `imapsieve_mailboxN_name = Junk`, causes `COPY` | `junk` |
| copies or moves a message out of Junk, except to Trash | `name = *`, `from = Junk`, causes `COPY` | `not_junk` |
| files a message into a folder of their own (not INBOX, Junk, Trash, Sent or Drafts) | `name = *`, causes `COPY` | `not_junk` |
| a copy reaches Sent | `name = Sent`, causes `APPEND COPY` | `sent` |

The scripts (`lab/l2/sieve/report-*.sieve`) pipe the message, with `imap.user`, to
`firstread feedback`, which sends one frame to `firstreadd`'s feedback socket: `{"v": 1, "op":
"junk" | "not_junk" | "sent" | "forget", "mailbox", "actor", "at", "message_len"}` followed by the
message bytes; the reply says `applied`, `duplicate`, `dropped` or `forgotten`. The daemon parses
the message, hashes its identifiers and applies the event to that mailbox's memory
([ADR-0018](decisions/0018-mailbox-memory-v0.md); format 2,
[ADR-0019](decisions/0019-own-dkim-dmarc-and-memory-v1.md)). A label lands on the record the
delivery was counted under: verified or unverified, as that message was at delivery.

- **Moving junk to Trash teaches nothing.** Deleting mail says nothing about whether it was wanted.
- **Filing mail away means it was wanted** (mox's automatic junk flags do the same). Moving mail
  from Junk into a folder of one's own fires two scripts; the second report is a duplicate and
  counted once.
- **firstread's own filing is not an action.** Delivery-time filing happens in LMTP, which does
  not run IMAPSieve; feedback from actors listed in `--own-actors` is dropped. Hook C, when built,
  uses `doveadm`, which does not run IMAPSieve either.
- **The pipe never blocks the move.** The scripts use `pipe :try`: if firstread is down the owner's
  move still happens; the label is lost, not the mail.
- **Labels are reversible and counted once.** The same judgement twice is a duplicate; a reversed
  judgement moves the count.
- The IMAP login must be the same user name as delivery uses (`USER` at LMTP), so both name the
  same memory.

Verified on Dovecot 2.3.21 / Pigeonhole 0.5.21 with `MOVE` and with `COPY` plus expunge, including
filing into a folder of the owner's own (`lab/l2/cases.py`, case M;
`lab/results/l2-dovecot-2.3.21.txt`).

## 5 · Invariants (each one has a test)

1. **Body bytes out equal body bytes in.** Only the header block is edited.
2. **No output deletes, discards, redirects or rewrites mail.**
3. **Header safety:** names are printable US-ASCII without `:`; values contain no CR or LF from any
   input, are RFC 2047-encoded when non-ASCII, folded to keep lines within RFC 5322's 998-octet
   limit, and capped in total size. Attacker-controlled text (display names, subjects) can never
   create a new header line.
4. **Keywords are valid IMAP atoms;** a folder choice is a key from the mode's allowed set.
5. **Fail open:** any failure, timeout or malformed reply still delivers the message, after the
   input was read to the end: the original bytes minus foreign firstread headers with exit 0, or,
   when the filter cannot vouch for the message, the original bytes kept by Pigeonhole with the
   `filter` test false.
6. **Idempotent:** the same message to the same recipient yields the same stamp id; learners count it once.
7. **Replayable:** the record names the snapshot, config, models and recorded lookups that decided.
8. **Foreign stamps never survive:** every header in our namespace that arrived with the message
   is removed on every path where the filter writes output, including the daemon-down fallback and
   the obsolete `Name : value` spelling; a stamp without a valid MAC is never shown as firstread's.
9. **The user wins:** in the default deployment the user's own Sieve rules run before firstread
   files anything, and late updates never undo a user's own action.
10. **Nothing a sender writes is acted on:** the Sieve scripts read firstread headers only after the
    filter vouched for them (`if not filter` deletes the directive headers otherwise); folder keys
    map to literal `fileinto`s; user-owned keywords are never set.
11. **firstread's own writes are never feedback:** keywords and moves firstread makes (at delivery
    and through hook C) are recorded, and their echoes in mailbox events are dropped before
    learning; keywords present at delivery are never read as a user's label.

## 6 · What the host sees when things go wrong

| situation | filter exit | message delivered | stamp |
|---|---|---|---|
| normal | 0 | stamped | full |
| daemon unreachable | 0 | original bytes minus foreign firstread headers | none |
| deadline passed | 0 | the same, or stamped with the tiers that finished | partial, `tiers=` says which |
| malformed MIME | 0 | stamped with what could be read | `parse=failed` |
| invalid directive from the daemon (fails validation) | 0 | original bytes minus foreign firstread headers; never partly applied | none; counted and alerted |
| no line ending at all, or the filter declines or crashes | non-zero | original bytes (Pigeonhole keeps the message; the `filter` test is false), with forged directive headers deleted by the `sieve_before` script | none |
| the filter is killed at `sieve_filter_exec_timeout` | killed | **nothing, on Dovecot 2.3.21**: the LMTP process panics and the session drops (section 7). Prevented by the filter's own deadline | none |
| shadow mode (`firstreadd --shadow`) | 0 | original bytes minus foreign firstread headers; the decision is only recorded | none |

## 7 · To verify on the deployed stack

Run in the lab on Dovecot 2.3.21 / Pigeonhole 0.5.21 (Ubuntu 24.04 packages), delivering over LMTP
and reading the stored mail back ([measurements/2026-10-26-lab-v0.md](measurements/2026-10-26-lab-v0.md),
`lab/l2/`):

| case | outcome |
|---|---|
| stamped, ham and spam, forged directive headers | as predicted: forged headers gone, spam in Junk with `$Junk`, ham in INBOX |
| user rule that files the message | as predicted: the user's folder wins; firstread files nothing and sets no keyword |
| daemon down; daemon that accepts and never answers | as predicted: INBOX, forged headers gone; the hang costs the filter's 2 s deadline |
| filter declining (exit 1) | as predicted: INBOX; `deleteheader` in `sieve_before` is visible in `sieve_after` |
| filter killed at `sieve_filter_exec_timeout` | **not as predicted**: LMTP panics (`output stream … (program client seekable output) is missing error handling`), signal 6, nothing stored |

Still to do on the deployed version:

- The same cases there, since the deployed Dovecot version is not known; and whether a later
  Dovecot release handles a killed filter.
- A filter terminated by a signal other than the timeout kill (not tested).
- Differential test: for every fixture, the header names firstread's splitter sees equal the names
  Pigeonhole sees (`header :matches` dump through `sieve-test`).
- Which client honours which of the stamp's headers and keywords ([03 · Client contract](03-client-contract.md)).
- Line-ending setting (`sieve_filter_input_eol`) in use.
