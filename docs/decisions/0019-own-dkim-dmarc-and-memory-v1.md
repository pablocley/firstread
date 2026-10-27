# ADR-0019 · Own DKIM and DMARC over recorded DNS, and mailbox memory keyed on verified identity

Status: accepted. SPF and ARC open; memory stays off unless `--memory` is given.

## Context

ADR-0018 left an identity gap: memory keyed on the From address, so a forger using a
correspondent's address got that correspondent's history, and an owner junking the forgery junked
the real sender. Closing it needs a verified sender identity at delivery. What the production MTA
writes into `Authentication-Results` is unknown (CLAUDE.md: do not assume the stack), and in the
lab only 681 of 7,652 timeline messages (8.9 %) carry a trusted DMARC pass.

The 2026 code we read (16 agent-memory and mail repositories, cloned and read on 2026-10-27,
[measurement](../measurements/2026-10-27-auth-dns-memory-v1.md) section 1) answered how to use an
identity once there is one: mox (`smtpserver/reputation.go`, commit 58d0a7788a) keeps a sender's
history apart for authenticated and unauthenticated mail, counts only messages the owner
classified, and treats unauthenticated mail from an address with authenticated history as suspect.
The agent-memory frameworks take the source of a memory as given by the caller; none
authenticates it.

## Decision

1. **Own DKIM** (`firstread-auth::dkim`, RFC 6376 / 8301 / 8463, on `ring`), judged at an explicit
   time: the delivery time in production, the message's Date in a replay. rsa-sha256 with keys of
   1,024 to 8,192 bits and ed25519-sha256; rsa-sha1 and keys with `t=y` are a permerror;
   an `l=` signature that does not cover the whole body passes but verifies no identity; no clock
   skew past `x=`. We wrote it rather than use `mail-auth`: 0.14 needs Rust 1.98 (we build on
   1.97), and 0.13.3 checks `x=` against the wall clock, so 201 of the lab's 209 signatures with
   `x=` could not be replayed.
2. **DMARC alignment without SPF** (`firstread-auth::dmarc`, RFC 7489): the From domain's policy
   (organisational domain from the Public Suffix List, `sp=` for subdomains), and whether a passing
   whole-body DKIM signature is aligned. Without SPF there is no DMARC fail, only `pass`,
   `unaligned`, `unusable` (no single From address) and `temperror`. **A verified identity** is an
   aligned DKIM pass from our own check, or DMARC pass in a trusted `Authentication-Results`.
3. **DNS behind one contract** (`firstread-net::Dns`). Every lookup is kept in the record with the
   time the message was judged at, so a decision replays exactly. A recording answers what it holds
   and nothing else (a miss is a temporary error, never "no record"), stands only for the period it
   was recorded for (`--dns-window`; outside it, no answers), and when several are loaded the
   earlier one's answer is kept. The live resolver has a deadline per attempt and a budget per
   message (`--dns-budget-ms`, default 800 ms), after which every lookup is a temporary error:
   DNS can never hold up a delivery.
4. **The lab records DNS once** (`lab/harness/record_dns.py`, DNS-over-HTTPS) for real 2026 mail
   only; SpamAssassin's 2002 mail and the synthetic slice get no answers. Our own checks are an
   input (`auth.own_*`) but disabled in the champion until a three-axis run keeps them.
5. **Memory format 2** (`firstread-graph`), after mox:
   - a sender's and a domain's history is kept apart for verified and unverified mail, and a label
     lands on the record its delivery was counted under;
   - only the owner writes trust: deliveries are counted but raise no fact;
   - unverified mail from an address with at least two verified deliveries raises
     `spoof_of_verified` and gets none of the unverified record's trust (rescues, correspondence,
     replies), which is stricter than mox;
   - a reply counts only when it references a Message-ID the owner sent and comes from one of that
     message's recipients (after Rspamd's `replies`);
   - free-mail domains (a data file, from Haraka's list) get no domain facts;
   - filing a message into a folder of one's own is a not-junk label (after mox's automatic junk
     flags; IMAPSieve, verified on Dovecot 2.3.21).
6. **Every memory fact has a direction** (`crates/firstread-graph/data/fact-directions.txt`): it
   may only raise or only lower P(junk). `ml/heads/train.py` fits memory within these bounds and
   `firstreadd` refuses a combiner whose weight for a mailbox fact points the other way, or for a
   fact without a direction. Fitted freely on the lab's corpora, a new IBAN for a domain and the
   owner junking a domain both came out lowering P(junk).

## Consequences

See the measurement for the numbers; in short:

- Our DKIM agrees with dkimpy on 1,580 of 1,615 real 2026 signatures; all 35 differences are
  `t=y` keys, where we follow RFC 6376. 1,025 of the 2,144 real 2026 messages (47.8 %) get a
  verified identity from our own check; together with trusted `Authentication-Results`, 1,468 of
  the 7,652 timeline messages (19.2 %, up from 8.9 %).
- A verified identity is not a good sender: 156 of 1,184 recent spam messages (13.2 %) are
  aligned and signed by their own domains. It only makes history attributable.
- Champion unchanged (cost 84.80, 0 FP, 95 FN) with recorded DNS on and `auth.own_*` disabled.
- Learning test on dev, λ = 100, Δ cost per 1,000 vs memory off: −6.20 [−11.38, −2.07] with
  active owners, −2.07 [−5.17, 0.00] passive, 0.00 when owners never act (v0: +4.14), no new
  legitimate message in Junk, poisoning check 0.0. The gain under active owners is smaller than
  v0's (−8.27), by design: v0 caught spam through hotmail.com's history as a whole and delivery
  counts, which anyone can raise. The directions account for the whole change against v1 fitted
  freely; the spoof rule changed no dev decision. Memory stays off unless `--memory` is given; it
  is a candidate for shadow mode, not a champion change.
- The spoof rule also fires on legitimate mail from a sender whose mail does not always align
  (1 of its 2 firings on dev; P(junk) 0.18 to 0.47, still in the inbox).
- Senders who never authenticate (all of SpamAssassin, many small senders) can still be
  impersonated with their history; the spoof rule protects only addresses that do authenticate.
  Closing the rest needs SPF (the client IP from our own border MTA) and ARC for lists and
  forwarders, or a policy that gives unverified history no trust at all.
- Live DNS is tested only against a local fake server (UDP, TCP fallback, NXDOMAIN, SERVFAIL,
  timeouts); public resolvers are not usable from the lab machine (UDP answers come back empty).
  A resolver that answers empty reads as "no record", so a deployment must use one it trusts.
