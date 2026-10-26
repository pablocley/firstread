# 05 · Sending

Outbound has three moments with different powers. Only the first one can ask the user
"are you sure?"; SMTP itself can only accept, defer or reject.

## 1 · Before send (webmail and clients that call the API)

`POST /v1/check-draft` with the draft and the sending mailbox. Returns findings with a severity;
the client decides how to show them.

| check | how |
|---|---|
| recipient domain typo | edit distance and keyboard adjacency to common providers and to domains this mailbox has written to before (`gmial.com`, a one-letter-off client domain) |
| recipient domain cannot receive mail | MX / A lookup, null MX |
| **replying into a spoofed thread** | a recipient's domain is a lookalike of a domain this mailbox normally writes to; the outbound half of BEC defence |
| first message ever to this address | sender relationship graph |
| attachment mentioned, none attached | Dutch and English cues ("bijlage", "bijgevoegd", "zie bijlage", "attached", "enclosed") in the new text, not the quoted part |
| sensitive data in plain text | BSN (11-proef), IBAN (mod-97) together with payment-change language, payment card numbers (Luhn), passwords and API keys |
| reply-all to many recipients | count and how many are outside the sender's domain |
| attachment larger than the recipient side is likely to accept | size threshold, suggest a link instead |

## 2 · At submission (MTA)

Hook E: a submission milter on Postfix, an ACL on Exim. No user interface here, so only hard
rules act, and everything else is a signal.

| check | action |
|---|---|
| **compromised account** | sudden volume, a fan-out to recipients never written to before, content matching an inbound phishing campaign now going out, login from an unusual network (from submission auth logs). High confidence: defer and alert the customer and support. Lower: alert only |
| outbound spam probability | same tier-1 heads as inbound; feeds the compromised-account score |
| per-account rate limits | adaptive to the account's own history, not one global number |
| signing and alignment | will this message be DKIM-signed for its From domain, and will DMARC align at the receiver? If not, tell the customer once, not per message |

The point of this layer is protecting the platform's IP reputation for every other customer.

## 3 · After send

Most "my mail does not arrive" tickets are answerable from data the server already has.

| feature | source |
|---|---|
| bounce and deferral explanations in plain language | DSN parsing plus MTA logs, classified: address unknown, mailbox full, blocked as spam, DMARC failure on our side, greylisting, TLS problem |
| delivery overview per recipient domain | MTA logs |
| the customer's own domain health | SPF, DKIM, DMARC (policy and alignment), MTA-STS, TLS-RPT, MX records, checked periodically; a concrete fix when something is wrong ("DMARC staat op p=none: …") |
| DMARC aggregate reports | parsed and summarised when the customer's `rua` points at us (`mail-auth` parses them) |
| newsletter senders | warnings when a customer's own bulk mail lacks one-click unsubscribe (RFC 8058) or authenticated alignment |

## Later, if wanted

- Server-side delayed send (an undo window that works from every client).
- Follow-up reminders: "no reply from X in 5 days", from thread state, set as `$Notify` on the
  original message.
