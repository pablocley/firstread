# 03 · Client contract

What a client receives and through which channel. Reuse what clients already understand; add our
own only where nothing exists; never require a plugin for the basics. How these channels are used
for different kinds of users is in [09-experience.md](09-experience.md).

## Channels

| channel | IMAP clients | POP3 clients | webmail | survives firstread removal | can carry feedback |
|---|---|---|---|---|---|
| headers | yes, if shown or filtered on | **yes, the main channel** | yes | yes | no |
| IMAP keywords | yes, varies by client | no | yes | yes | yes (removing / adding a tag) |
| folders (Sieve) | yes, every client | **no**, POP3 sees INBOX only | yes | yes | yes (moving mail) |
| Subject prefix | yes | yes | yes | yes | no |
| body banner with one-tap links | yes | yes | yes | yes | yes |
| digest mail with one-tap links | yes | **yes** | yes | yes | yes |
| HTTP API | no | no | yes | no | yes |

POP3 consequences: a POP3 user never sees the Junk folder, so filing there costs them the message.
For POP3 mailboxes firstread files to Junk only at a stricter threshold, uses the Subject prefix for
warnings, and relies on the digest for rescue and feedback.

## Headers

Added at delivery. Headers of the same names that arrived with the message are removed first, as
are `Authentication-Results` claiming our authserv-id that were not added inside our own trust
boundary (RFC 8601 section 5); results added by our own MTA or Rspamd stay.

```
Authentication-Results: <authserv-id>; spf=pass smtp.mailfrom=…; dkim=pass header.d=…; dmarc=pass header.from=…
X-Firstread: v=1; id=<opaque>; tiers=0,1; models=<release>; state=<learner snapshot>; verdict=fraud; p=0.91
X-Firstread-Scores: phishing=0.12; fraud=0.91; junk=0.04; important=0.66; urgency=4.1
X-Firstread-Tags: money, request-action
X-Firstread-Sender: relation=first-contact; domain-age-days=3; lookalike=1
X-Firstread-Campaign: id=<cluster id>; mailboxes=312
X-Firstread-Reasons: =?UTF-8?Q?…?=  (localised, plain language)
```

- `X-Firstread` is the one machine-parseable summary; the others can be switched off per platform.
- `state` records which learner snapshot decided, so any decision can be replayed.
- No extracted personal data in headers (IBANs, BSNs, OTP codes, amounts): API only.
- Headers are written once, at delivery, and never rewritten; later knowledge updates keywords,
  folders and the API record.

## Keywords

Registered first ([IANA IMAP and JMAP keywords](https://www.iana.org/assignments/imap-jmap-keywords/imap-jmap-keywords.xhtml)):

| keyword | source | set when |
|---|---|---|
| `$Phishing` | registered | `phishing` or `fraud` above the keyword threshold |
| `$Junk` / `$NotJunk` | registered | `junk`; `$NotJunk` belongs to the user and is read as feedback |
| `$Important` | RFC 8457 | `important` |
| `$CanUnsubscribe` / `$Unsubscribed` | RFC 9979 | unsubscribe available / done through firstread |
| `$Autosent` | RFC 9979 | machine-generated mail |
| `$HasAttachment` / `$HasNoAttachment` | RFC 9979 | from MIME structure |
| `$IsTrusted` | RFC 9979 | established, authenticated correspondent |
| `$Followed` / `$Notify` / `$Muted` | RFC 9979 | only through features the user turned on |

Own keywords use a configurable prefix (default `fr-`) and stable ids for the user-facing tags
(`fr-money`, `fr-orders`, `fr-request-action`, `fr-first-contact`, user rule tags). Whether
keywords carry localised names (`fr-facturen`) is decided by the client matrix below. Every
firstread keyword is also a feedback channel: removing one is a negative label, adding one a positive.

## Folders

Sieve files mail from the headers firstread added, in the same script that sets keywords. Which
folders exist depends on the mailbox's mode ([09](09-experience.md)): from "Junk only" to a
"Later" folder for low-interest bulk mail (fewer phone notifications) to category folders. Folder
moves by the user are the richest feedback there is ([08](08-learning.md)).

## One-tap feedback links (banner and digest)

Every warning banner and every digest item can carry links such as "this is safe", "this is a
scam", "not a newsletter I want", "always file these in …".

- Each link carries a signed, expiring token bound to one message, one mailbox and one action.
- Opening the link shows a confirmation page; the action happens only on its button (POST).
  Corporate link scanners open links automatically, and a GET must never teach anything.
- No login needed; the token is the authorisation, limited to that one action.
- Works in every client, including POP3.

## Subject prefix and banner

Both modify signed content: DKIM re-verification fails after a Subject change, and a body banner
breaks S/MIME and PGP signatures.

- Subject prefix: only `phishing` / `fraud` above a strict threshold; default on for POP3 mailboxes.
- Banner: never on signed messages; default on only for `phishing` / `fraud` above threshold and
  for first-contact payment requests; the platform decides after measuring false positives.

## API (sketch)

User scope authenticates with the mailbox's own credentials; admin and organisation scopes are separate.

| endpoint | purpose |
|---|---|
| `GET /v1/messages/{id}` | every distribution, reasons, entities, link and attachment facts, campaign |
| `GET /v1/mailboxes/{m}/overview` | subscriptions with read rates, awaiting reply, invoices and vendors, storage |
| `POST /v1/mailboxes/{m}/unsubscribe` | RFC 8058 one-click for the lists the user picked; explicit action only |
| `POST /v1/feedback` | explicit feedback from webmail (verdict, tag, reason was wrong) |
| `GET/PUT /v1/mailboxes/{m}/settings` | mode, digest frequency, language, scope sharing, off switch |
| `POST /v1/mailboxes/{m}/rules` | natural-language rules ("tag customer refund requests as Retour") |
| `POST /v1/check-draft` | pre-send checks |
| `GET /v1/search` | semantic search within the mailbox |
| `GET /v1/me/export`, `DELETE /v1/me/learning` | everything firstread learned about this mailbox, and erasing it |

## Client capability matrix (measure; do not assume)

Every cell is filled by testing a real account with the client, recording version and date.

| client | shows custom keywords | acts on `$Junk` / `$NotJunk` | shows `$Phishing` | sets `$Junk` when user marks junk | filters on custom headers |
|---|---|---|---|---|---|
| Thunderbird desktop | ? | ? | ? | ? | ? |
| Thunderbird Android | ? | ? | ? | ? | ? |
| Apple Mail macOS / iOS | ? | ? | ? | ? | ? |
| Outlook Windows / macOS / mobile | ? | ? | ? | ? | ? |
| Gmail app, IMAP account | ? | ? | ? | ? | ? |
| the platform's webmail | ? | ? | ? | ? | ? |
| POP3 setups | n/a | n/a | n/a | n/a | ? |

The results decide keyword naming, where folders must stand in for keywords, which clients produce
usable feedback, and whether a webmail plugin is worth building first.
