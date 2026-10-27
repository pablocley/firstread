# 2026-10-27 · Own DKIM and DMARC over recorded DNS, and mailbox memory v1

What was measured: what 2026 mail and memory code has that firstread's memory lacked; whether our
own DKIM and DMARC ([ADR-0019](../decisions/0019-own-dkim-dmarc-and-memory-v1.md)) agree with an
independent implementation on real mail; how much of the lab's mail gets a verified identity; and
whether memory keyed on that identity still lowers the cost of decisions. Results:
[`lab/results/memory-v1/`](../../lab/results/memory-v1/),
[`lab/results/l2-dovecot-2.3.21.txt`](../../lab/results/l2-dovecot-2.3.21.txt).

Machine: 2 vCPU Intel Xeon @ 2.80 GHz, 7 GB RAM, Linux 6.18. Rust 1.97.0 (release build), ring
0.17.14; Python 3.13 with dkimpy 1.1.8 (the oracle), numpy 2.5.3, scikit-learn 1.9.1, scipy 1.18.1;
Dovecot 2.3.21 with Pigeonhole 0.5.21. Tier 1 as the `oct26b` champion (e5-small, ONNX Runtime
int8, 192 tokens).

## 1 · What the 2026 code showed

16 repositories cloned and read on 2026-10-27 (commit and date of the clone). "Ran": its tests,
offline, on this machine.

| repository | commit | what it has | taken |
|---|---|---|---|
| [mox](https://github.com/mjl-/mox) (MIT) | 58d0a7788a, 2026-10-09 | sender history per mailbox, kept apart for mail whose From was validated or not (`smtpserver/reputation.go:176-196`); only messages the owner classified count (`m.Junk \|\| m.Notjunk`, `:131-133`); unvalidated mail from an address with validated history is suspect (`:184-195`); filing into a non-special folder is a not-junk flag (`store/account.go:722-778`); Sent recipients are known (`:2437-2474`). Ran `go test ./smtpserver -run TestReputation`: ok | the split, owner-only trust, the spoof rule (stricter: see below), filing labels |
| [Rspamd](https://github.com/rspamd/rspamd) (Apache-2.0) | da591f47f2, 2026-10-24 | `replies.lua`: Message-IDs only of mail an authenticated user sent, and a reply must come from its recipient (`:243-286`). `known_senders.lua`: a sender is known once seen (`:119-131`), the flaw memory v0 had | the reply rule |
| [Stalwart](https://github.com/stalwartlabs/stalwart) (AGPL-3.0) | 47df4c0bae, 2026-10-26 | the address-book override needs DMARC pass (`email/src/message/ingest.rs:397-427`); a trusted reply is any thread with a Sent message, not DMARC-gated (`ingest/checks.rs:55-130`) | nothing new |
| [SpamAssassin](https://github.com/apache/spamassassin) TxRep (Apache-2.0) | 328ed086ca, 2026-10-27 | keys by DKIM signer when signed (`TxRep.pm:1504-1535`), but the default DB_File backend ignores the signer; reputation is the mean of its own past scores, so it reinforces itself | a warning |
| [haraka-plugin-known-senders](https://github.com/haraka/haraka-plugin-known-senders) (MIT) | 6ab74d986e, 2026-05-28 | inbound counts only when the envelope domain is validated; free-mail domains ignored (`config/known-senders.ini:8-15`). Ran: 26 of 26 pass | the free-mail list |
| [lemmalog](https://github.com/JordyZomer/lemmalog) (MIT) | 9cc2cf1bc0, 2026-10-01 | facts with sources and a valid-time interval; deterministic supersession (`src/agent.rs:436-541`). Ran: 46 pass | not yet (bitemporal IBAN history) |
| [statewave](https://github.com/smaramwbc/statewave) (Apache-2.0) | 0f26bc7f1e, 2026-10-24 | single-valued claims superseded by time window, each with the rule that decided (`server/services/supersession.py`). Ran: 16 pass | not yet |
| [graphiti](https://github.com/getzep/graphiti) (Apache-2.0) | 2b5db9e139, 2026-10-26 | valid time and system time per edge; deciding a contradiction is an LLM call (`edge_operations.py:986-995`) | no: identity must be code |
| [cognee](https://github.com/topoteretes/cognee) (Apache-2.0) | 37f788bd28, 2026-10-16 | feedback folded in as a running average (`apply_feedback_weights.py:69-87`) | no |
| [OWASP agent-memory-guard](https://github.com/OWASP/www-project-agent-memory-guard) (Apache-2.0) | 91ae5a32f7, 2026-10-27 | repeated writes by the agent itself are not corroboration (`detectors/self_reinforcement.py`); source labels "do not authenticate a principal" (`events.py:35-53`). Ran: 34 pass | the principle, already a rule |
| [remnic](https://github.com/joshuaswarren/remnic) (MIT) | 0bdcbb2dcb, 2026-10-27 | promotion to trusted needs corroboration from a different source class (`trust-zones.ts:232-370`) | no |
| [inbox-zero](https://github.com/elie222/inbox-zero) (AGPL-3.0) | 87e1dc6794, 2026-10-27 | each learned pattern records its origin, and undoing a label removes only what that label wrote (`utils/rule/learned-patterns.ts:67-96`); "prior contact" counts inbound mail, no authentication anywhere | no |
| mem0, MemOS, letta-code, Zero | 26cdefb466, adcb9f270c, 4c78cbe420, 36132735ca | caller-supplied sources, LLM-decided updates; Zero makes every sender of any inbound message a known contact | no |

The missing piece came from a mail server, not from an agent-memory framework: every framework
takes the source of a memory as given; mox is the only code found that ties learned history to
authentication. The GitHub search API was not reachable from here, so the search is not complete.

## 2 · Our DKIM and DMARC against dkimpy

**Fixtures** (`fixtures/auth/`, `crates/firstread-auth/tests/fixtures.rs`): 20 messages signed by
dkimpy with throw-away keys (rsa 512 / 1,024 / 2,048, ed25519, simple and relaxed, `l=`, `x=`,
`t=y`, rsa-sha1, revoked and missing keys, a changed body, a changed Subject, a second From on top,
a third-party signer, bare LF line ends). All 20 verify as `expected.json` says; where we differ
from dkimpy by design is listed in `fixtures/auth/README.md`.

**Real mail.** `firstread auth-batch` over the 2,144 train, calib and dev messages of 2026 (lore
and untroubled) with the recorded DNS of section 3, judged at each message's Date, then dkimpy's
`verify()` over the same signatures, with the same answers and its clock set to the same time
(`time.time` patched):

| | signatures |
|---|---|
| both pass | 1,073 |
| both do not pass | 507 |
| dkimpy pass, ours permerror (`t=y`, RFC 6376 section 3.6.1) | 35 |
| other differences | 0 |

Ours on those 1,615 signatures: pass 1,073; permerror 522 (no key 328, a key record whose `v=` is
not DKIM1 142, `t=y` 35, revoked 8, a required tag missing 4, rsa-sha1 3, other 2); fail 19 (header
signature 11, body hash 8); temperror 1. 1.8 s for all 7,652 timeline messages (one thread).

**Verified identities** (aligned whole-body DKIM pass):

| | messages | signed | verified |
|---|---|---|---|
| lore, legitimate (kernel lists) | 960 | | 869 (90.5 %) |
| untroubled, spam | 1,184 | | 156 (13.2 %) |
| all real 2026 mail | 2,144 | 1,579 | 1,025 (47.8 %) |
| SpamAssassin 2002–2005, synthetic, 16 untroubled from before the window | 5,508 | 0 | 0 (no answers by design) |

A verified identity is not a good sender: one spam message in eight is signed and aligned by its
own domain. It only makes history attributable.

## 3 · Recorded DNS

`lab/harness/record_dns.py` asks the real code which names it needs (`auth-batch` against the
recording so far), resolves them over DNS-over-HTTPS (dns.google), and repeats until nothing new is
asked: 1,607 answers (1,003 with records, 600 without, 4 temporary errors) for 2,144 messages,
recorded 2026-10-27, 252 KB in 8 files (`lab/data/dns-recorded/`); the sealed split's 264 answers stay
with the sealed split. Only real mail dated within the window gets answers (2025-09-22 to
2026-10-28, `dns-recorded.meta.json`).

Two faults found while measuring, both fixed before the results below:

- **Today's policies on 2002 mail.** One recording serves every message, so 522 SpamAssassin
  messages from hotmail.com, yahoo.com, msn.com and others got today's answers, 214 of them a
  p=reject or p=quarantine policy. A recording now stands for its window only (`--dns-window`):
  outside it every lookup is a temporary error, `outside the recording`. Six untroubled spam
  messages whose Date does not parse are judged at time 0 and now get no answers either.
- **The sealed recording changed dev answers.** The daemon merged the sealed split's recording
  after the main one and let it win on a clash; for one key it had recorded a SERVFAIL, so 11 lore
  messages lost their verified identity in every lab run. The first recording's answer now stays.

With both fixed, the champion run is unchanged: cost 84.80 per 1,000, 0 FP, 95 FN (dev), with
`auth.own_*` disabled as on main.

## 4 · Memory v1

What changed from v0 ([ADR-0019](../decisions/0019-own-dkim-dmarc-and-memory-v1.md) decision 5),
each after the code of section 1:

| v0 | v1 | after |
|---|---|---|
| one history per address and domain | kept apart for verified and unverified mail; a label lands on the record its delivery was counted under | mox |
| `sender_seen_log`, `domain_seen_log`: delivery counts | deliveries counted, no fact rises with them | mox, Rspamd's flaw |
| none | `spoof_of_verified`: unverified mail from an address with ≥ 2 verified deliveries | mox |
| `wrote_to_*` for any From | `wrote_to_sender` (verified), `wrote_to_sender_unverified`, `wrote_to_domain` (verified) | |
| `known_thread`: any reference to mail the mailbox received or sent | `reply_to_sent`: a reference to mail the owner sent, from one of its recipients | Rspamd `replies` |
| hotmail.com treated like any domain | no domain facts for free-mail domains | Haraka |
| labels from Junk moves | also filing into a folder of one's own | mox |

The learning test is that of the v0 measurement (all 7,652 train, calib and dev messages in Date
order through the real filter and daemon, owners on true labels through `firstread feedback`, dev
scored against memory off, λ = 100, threshold 0.990, paired bootstrap), now with recorded DNS and
`--clock message`, so our own check verifies the 2026 mail. Identity for memory: 1,468 of 7,652
messages (1,025 by our own check, 681 by trusted `Authentication-Results`, 238 by both).

**Pre-registered before the first v1 run.** H1: with owners who never act, v1 equals memory off.
H2: with active owners, v1 costs no more than v0 (−8.27). H3: the poisoning check stays at 0.0.

**First v1 run, fitted freely** (`ablation-unbounded-no-spoof-rule` below, identical to the first
run, which had the two DNS faults of section 3: they changed no decision). H1 held, H3 held, H2
failed: −5.17 [−10.34, 0.00]. Where v0 and v1 decide dev spam differently (active):

- v0 caught 3 SpamAssassin spam messages from hotmail.com through hotmail.com's junk history as a
  whole; v1 gives free-mail domains no domain facts, by design.
- v1 catches 4 spam messages that v0 let through: 2 untroubled ones from bpost.be and 1
  SpamAssassin one from netnoteinc.com, which v0 released on delivery counts, and 1 synthetic one
  on `sender_junk_log`; it releases 1 SpamAssassin message v0 and memory off kept in Junk.
- v1 let a forged invoice into the inbox (`synthetic_nl-8bad234ebd50c1fe`: a known vendor's
  address, no DMARC pass, a new IBAN; memory off puts it in Junk at 0.9989). Its facts:
  `spoof_of_verified` (+2.93), `wrote_to_sender_unverified` (−3.21), `iban_new_for_domain`
  (−2.23); P(junk) 0.9871, under the threshold. Fitted freely, a new IBAN lowered P(junk) in all
  three profiles (−2.66 even when owners never act), and so did the owner junking a domain
  (`domain_junk_log` −1.00 active, −2.19 passive): SpamAssassin's 2002 mail has no authentication
  and few IBANs, and 63 % of the timeline is SpamAssassin.

So v1 got two rules in code ([ADR-0019](../decisions/0019-own-dkim-dmarc-and-memory-v1.md)
decision 6): every fact has a direction that bounds its weight, and unverified mail from an
address that authenticates gets none of the unverified record's trust. **Pre-registered before
that run**, with dev no longer blind to this question: H1 and H3 as before; H2: active Δ ≤ 0 with
no new legitimate message in Junk; H4: the forged invoice goes to Junk and no fitted weight breaks
its direction. H4 uses the message that showed the hole, so it is a regression check, not
evidence.

| memory | owners | cost / 1k | FP | FN | Δ vs off, CI95 | poisoned mailbox: decisions changed |
|---|---|---|---|---|---|---|
| off | | 84.80 | 0 | 95 | | |
| v0 | none | 88.93 | 0 | 104 | +4.14 [+1.03, +8.27] | |
| v0 | passive | 82.73 | 0 | 95 | −2.07 [−8.27, +3.10] | |
| v0 | active | 76.53 | 0 | 86 | −8.27 [−14.48, −2.07] | 10 |
| v1 fitted freely, no spoof rule | none | 84.80 | 0 | 95 | 0.00 [0.00, 0.00] | |
| v1 fitted freely, no spoof rule | passive | 85.83 | 0 | 93 | +1.03 [−3.10, +6.20] | |
| v1 fitted freely, no spoof rule | active | 79.63 | 0 | 87 | −5.17 [−10.34, 0.00] | 1 |
| **v1** | none | 84.80 | 0 | 95 | 0.00 [0.00, 0.00] | |
| **v1** | passive | 82.73 | 0 | 90 | −2.07 [−5.17, 0.00] | |
| **v1** | active | 78.59 | 0 | 85 | −6.20 [−11.38, −2.07] | 5 |

All four hold for v1: H1 (bit-identical to off), H2 (no new FP in any profile, active CI excludes
0), H3 (largest change in any other mailbox 0.0, every run), H4 (the forged invoice at 0.9997 in
Junk in all three profiles).

Which rule did it: v1 with the directions but without the spoof rule
(`ablation-no-spoof-rule`) fits the same combiners and takes the same decision on every dev
message; the forged invoice goes to Junk there too, at 0.9918 under active owners, just over the
threshold. The directions account for the whole change in cost; the spoof rule changes no dev
decision and adds the margin on that one message (0.9918 to 0.9997), by voiding
`wrote_to_sender_unverified`. The 526 dev messages without any memory fact got P(junk)
bit-identical to memory off. No invariant violations.

Weights of v1 (active): `sender_junk_log` +5.56, `sender_ok_log` −5.74, `domain_ok_log` −5.74,
`wrote_to_sender_unverified` −3.48, `wrote_to_domain` −1.63, `wrote_to_sender` −1.27,
`spoof_of_verified` +1.43; `domain_junk_log`, `iban_new_for_domain` and `reply_to_sent` end at
their bound, 0. Facts that fired on dev (active): `first_contact` 529, `wrote_to_sender_unverified`
295, `domain_junk_log` 154, `wrote_to_domain` 56, `unknown_thread` 36, `wrote_to_sender` 22,
`iban_new_for_domain` 19, `sender_junk_log` 16, `domain_ok_log` 6, `sender_ok_log` 5,
`spoof_of_verified` 2, `reply_to_sent` 1.

Against v0 under active owners, v1 still misses the 3 hotmail.com messages v0 caught and catches
4 that v0 let through (bpost.be twice and netnoteinc.com, released by v0's delivery counts, and
one synthetic message on `sender_junk_log`). The cost per 1,000 counts SpamAssassin mail only, so
the untroubled and synthetic catches do not show in it (FN over all dev: v0 86, v1 85).

Found on the way: the first v1 build put every owner label on the unverified record (feedback
arrives without the delivery's verification), while verified deliveries read the verified one. A
label now lands on the record its delivery was counted under. That run is kept as
`bug-label-bucket.learning.json` (same costs; FN 94 passive, 88 active).

## 5 · Hook D on Dovecot 2.3.21 (L2, case M)

As in the v0 measurement, plus filing (`lab/l2/sieve/report-filed.sieve`): the owner moves
letter1 from `nieuwsbrief@krant.example` from INBOX into a folder `Archief`; letter2 from the same
sender, junk on its content alone, then lands in INBOX. 3 labels learned: the two Junk moves and
the filing; moving junk to Trash taught nothing; the reply to a message in Sent carries
`wrote_to_sender_unverified=1 reply_to_sent=1` (the fixtures carry no DKIM). Cases A–H and S are
unchanged. Rerun on the final build: identical.

## 6 · Limits

- **SPF is not evaluated** (it needs the client IP from our own border MTA), so a message without
  an aligned DKIM pass is never a DMARC fail, and senders who authenticate by SPF only are
  unverified. **ARC** is not evaluated: mailing lists that break DKIM make their posters
  unverified (the lore lists mostly do not).
- **Senders who never authenticate** (all of SpamAssassin, many small senders) can still be
  impersonated with their history (`sender_ok_log`, `wrote_to_sender_unverified`); the spoof rule
  protects only addresses that do authenticate.
- **The spoof rule fires on legitimate mail** from a sender whose mail does not always align: 1 of
  its 2 firings on dev (`synthetic_nl-129521ad110ad80f`, DKIM pass but not aligned; P(junk) 0.18
  off, 0.47 with v1, still in the inbox).
- **IBAN facts carry no weight yet**: `iban_new_for_domain` sits at its bound, 0. The corpora
  hold too few payment requests to learn it; the direction only keeps it from doing harm.
- The profiles are assumptions, one SpamAssassin mailbox holds 63 % of the timeline, the
  synthetic Dutch mailbox has 656 messages, and the learning test has no sealed counterpart.
  The v1 rules were written after looking at dev.
- **Live DNS** is tested only against a local fake server (UDP, TCP on truncation, NXDOMAIN,
  SERVFAIL, timeouts). From this machine a public resolver is not usable: UDP queries to 8.8.8.8
  and 1.1.1.1 get a NOERROR reply with 0 answers for `_dmarc.gmail.com`, which publishes a policy,
  and TCP times out. A resolver that answers like that would read as "no record"; the deployment
  must use a resolver it trusts.

Reproduce: after `sh lab/reproduce.sh <lab_data>`, `HF_HUB_OFFLINE=1 python3 -I
lab/harness/learning.py <short run dir>` gives the v1 rows; `python3 -I lab/harness/run.py
<run dir>` the champion row; `firstread auth-batch <items>` with `--dns` for each
file of `lab/data/dns-recorded/`, `--dns-window 1758499200,1793231999 --clock message`, section 2. Re-recording DNS (`python3 -I
lab/harness/record_dns.py <lab_data>`) gives today's answers, not those of 2026-10-27.
