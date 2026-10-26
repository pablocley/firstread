# 00 · Goal

## One sentence

Give every mail client everything that can be known about every message, in a form the client can
act on without knowing firstread exists, and get measurably better at it every week by learning
from how people actually treat their mail.

## Who it serves

1. **People reading mail**, who all use mail differently ([09-experience.md](09-experience.md)):
   fewer scams reach them, the ones that do carry a specific warning in plain language, the inbox
   arrives sorted the way *they* sort, and the things that need them are obvious.
2. **People sending mail**: fewer dangerous sends, and a plain answer when mail does not arrive.
3. **The platform running it**: fewer tickets about spam, phishing, quota and bounces;
   compromised accounts caught before they hurt everyone's IP reputation.
4. **Other platforms running it**: a scam seen anywhere protects everyone in the commons minutes later.

## Four scopes

Each scope sees more mail and less personal detail than the one before.

| scope | what it knows | example of what only it can do |
|---|---|---|
| **mailbox** | this person's mail, correspondents, habits, folders, feedback | "you have never written to this address"; "you always file these in Projects" |
| **organisation** | the mailboxes of one customer (one domain or tenant), when its admin allows | "the name says Maarten, but Maarten writes from the company domain"; vendor bank details known company-wide |
| **platform** | every mailbox on one deployment, as aggregates keyed by infrastructure and bulk content | "this message hit 312 mailboxes in 4 minutes and 6 people already junked it" |
| **commons** | threat evidence from other deployments that opted in | "this campaign was confirmed on two other platforms an hour ago" |

What may cross from one scope to the next is defined precisely in [08-learning.md](08-learning.md)
and [10-commons.md](10-commons.md). Personal behaviour and personal content never leave the mailbox
(or the organisation, if its admin enabled sharing).

## Principles

1. **Decide once, at delivery; store the answer in the message.** Headers reach every client,
   keywords reach IMAP, folders reach every IMAP client, the digest reaches everyone.
2. **Learn from day one.** A new deployment starts from shipped models; a newly enabled mailbox
   starts by learning from its own history; every user action after that teaches. Progress is
   measured, not assumed ([07-evaluation.md](07-evaluation.md)).
3. **Learn from what people already do.** Moving mail, replying, flagging, deleting unread, removing
   a tag. Explicit feedback is one tap, never a form. No click or read tracking.
4. **Quiet by default, loud when it matters.** Most mail just arrives better sorted. Warnings are
   rare, specific and in plain language, with an alert budget per user.
5. **Standards before inventions.** Registered IMAP keywords and `Authentication-Results` first.
6. **Cheap first.** Deterministic checks and cached results on everything; models where they change
   the answer; the large decision model only when cheaper tiers are unsure.
7. **Compute per unique content, not per copy.** A newsletter sent to 10,000 mailboxes is analysed
   once and personalised per recipient cheaply ([11-scale.md](11-scale.md)).
8. **Calibrated.** Every score is a probability that means what it says, so each action has its
   own threshold and each user's thresholds can adapt.
9. **Identity is never a model's call.** Authentication and sender identity are deterministic.
10. **Known is not safe.** A familiar, authenticated sender can be compromised; firstread watches
    for a known sender behaving unlike themselves.
11. **Fail open, alert loudly.**
12. **Local only.** Models run on the platform's own hardware. No mail goes to an external AI API.
13. **Reuse the mature parts.** Rspamd-style spam scoring is consumed as a signal, not rebuilt.

## Not

- Not an MTA, IMAP server or webmail; it plugs into the ones that exist.
- Not an IMAP / POP3 proxy ([ADR-0002](decisions/0002-integrate-at-delivery.md)).
- Not a hosted service that receives anyone's mail. The commons exchanges threat evidence, never mail.
- Not a generative writing assistant.
- Not a tracker: no read receipts, no click tracking, no profiles for anyone but the user's own benefit.
