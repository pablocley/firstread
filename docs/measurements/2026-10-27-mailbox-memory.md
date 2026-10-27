# 2026-10-27 · Mailbox memory v0: hook D on Dovecot, and the learning test

What was measured: whether mailbox memory ([ADR-0018](../decisions/0018-mailbox-memory-v0.md))
receives the owner's actions from a real Dovecot, and whether it lowers the cost of decisions on
the dev split when owners act. Results: [`lab/results/memory-v0/`](../../lab/results/memory-v0/),
[`lab/results/l2-dovecot-2.3.21.txt`](../../lab/results/l2-dovecot-2.3.21.txt).

Machine: 2 vCPU Intel Xeon @ 2.80 GHz, 7 GB RAM, Linux 6.18. Rust 1.97.0 (release build); Python
numpy 2.5.3, scikit-learn 1.9.1, scipy 1.18.1; Dovecot 2.3.21 (47349e2482) with Pigeonhole from the
Debian packages of `lab/l2/setup.sh`. Tier 1 as the `oct26b` champion (e5-small, ONNX Runtime int8,
192 tokens). One learning run takes 201–216 s.

## 1 · Hook D on Dovecot 2.3.21 (L2, case M)

`python3 lab/l2/cases.py`, user `dora`, IMAP actions by a real IMAP client against the real
IMAPSieve scripts of `lab/l2/`, fixture combiner of `lab/l2/combiner.json`:

| step | result |
|---|---|
| news1 from an unknown sender | Junk |
| owner moves it Junk → INBOX, then news2 from the same sender | INBOX |
| owner copies friend1 INBOX → Junk, then friend2 from the same sender | Junk |
| owner moves other1 Junk → Trash, then other2 from the same sender | Junk (deleting junk teaches nothing) |
| owner appends a message to `contact@partner.example` to Sent, then the reply | INBOX; `wrote_to_sender=1 known_thread=1 first_contact=0` |
| labels learned | 2: the owner's two moves; firstread's own filing into Junk at delivery is no IMAP action |

The IMAP login must equal the LMTP recipient (`dora@lab.invalid`), or feedback lands in another
mailbox's memory ([12](../12-interfaces.md) section 4.6). Cases A–F, H and S are unchanged.

## 2 · The learning test

`lab/harness/learning.py` ([13](../13-lab.md) section 7). All 7,652 train, calib and dev messages
(never sealed) in Date order through the real filter and daemon, each to its own mailbox (its
recipient): one SpamAssassin mailbox with 4,836 messages, the untroubled spam archive 1,200, the
synthetic Dutch mailbox 656, three kernel lists 960. Owners act on true labels through the real
`firstread feedback`:

| profile | junk left in the inbox moved to Junk | legitimate mail rescued from Junk | replies | delay |
|---|---|---|---|---|
| none | 0 | 0 | 0 | |
| passive | 30 % | 50 % | 0 | 1–48 h |
| active | 80 % | 90 % | 10 % of legitimate non-list mail in the inbox | 1–12 h |

Pass A runs the timeline with the combiner without memory (C0) deciding; a combiner C1 is trained on
pass A's calib records, now with `mailbox.*`; pass B runs the timeline again from empty memory with
C1 deciding. Dev is scored from pass B against memory off with the scorer of `run.py`: cost per
1,000 primary messages (SpamAssassin, 967 of the 1,528 dev messages), λ = 100, threshold 0.990,
paired bootstrap, CI95; FP, FN and the changed decisions count all 1,528.

Three ways to fit C1, each run once:

- **joint**: `mailbox.*` fitted with everything else (L1 logistic, as the champion's combiner).
- **joint without absence facts**: the same, without `mailbox.first_contact` and
  `mailbox.unknown_thread`.
- **residual** (`[combiner] memory = "residual"`, `ml/heads/train.py`): the combiner without memory
  is fitted first, on the same rows in calib order, and came out bit-identical to C0 (weights and
  intercept) in all three profiles; the memory weights are then fitted on top of its logit with no
  intercept, no centring and no absence facts (L2). A message for which memory knows nothing has
  all its memory inputs at 0, so it is decided exactly as without memory.

| C1 | profile | cost / 1k | FP | FN | Δ vs off, CI95 | new FP | spam newly caught / missed |
|---|---|---|---|---|---|---|---|
| off (C0) | | 84.80 | 0 | 95 | | | |
| joint | none | 286.45 | 2 | 89 | +201.65 [−9.31, +514.99] | 2 | 15 / 9 |
| joint | passive | 176.84 | 1 | 80 | +92.04 [−19.65, +306.10] | 1 | 21 / 6 |
| joint | active | 172.70 | 1 | 80 | +87.90 [−22.75, +301.96] | 1 | 21 / 6 |
| joint, no absence facts | none | 286.45 | 2 | 89 | +201.65 [−9.31, +514.99] | 2 | 15 / 9 |
| joint, no absence facts | passive | 176.84 | 1 | 81 | +92.04 [−19.65, +306.10] | 1 | 20 / 6 |
| joint, no absence facts | active | 171.66 | 1 | 80 | +86.87 [−23.78, +300.93] | 1 | 21 / 6 |
| **residual** | none | 88.93 | 0 | 104 | +4.14 [+1.03, +8.27] | 0 | 0 / 9 |
| **residual** | passive | 82.73 | 0 | 95 | −2.07 [−8.27, +3.10] | 0 | 8 / 8 |
| **residual** | active | 76.53 | 0 | 86 | −8.27 [−14.48, −2.07] | 0 | 12 / 3 |

Owner actions in pass B (active, residual): 312 junk, 5 rescues, 366 copies to Sent. No invariant
violations in any run.

**Why joint fails.** The joint fit gives history negative weights (`sender_seen_log` −0.76,
`domain_seen_log` −0.55 for none) and raises the intercept from −0.26 to +2.52 (+2.75 without the
absence facts). For mail from a stranger every history input is 0, so the higher intercept is a
push towards Junk. The new false positive in every joint run is `spamassassin-0194ad4537396505`,
hard ham from a first contact: P(junk) 0.9619 without memory, 0.9957 with, also when
`first_contact` has no weight at all. Leaving the absence facts out cannot help, because absence
lives in the intercept.

**Residual, checked.** The 385 dev messages without any memory fact got P(junk) bit-identical to
memory off in all three profiles. Memory weights for active: `sender_junk_log` +5.83,
`sender_ok_log` −5.11, `domain_ok_log` −5.11, `wrote_to_domain` −2.20, `wrote_to_sender` −1.08,
`sender_seen_log` −0.35, `known_thread` −0.31, `domain_junk_log` +0.39.

**Against the rule.** Learner changes must improve the cost under several owner profiles, not one
([13](../13-lab.md) section 7). Residual memory improves it under active (CI95 excludes 0, no new
FP), is equal under passive and worse under none: 9 more spam missed, none caught. With no owner
actions memory has only delivery counts, and `sender_seen_log` lowers P(junk), so a sender who sends
again looks known. Delivery counts are something a sender raises by sending. So memory v0 is not a
champion change: it is built, off unless `--memory` is given, and the residual fit is the default of
the learning test.

**Poisoning check** (pass B of active repeated, the owner of `ksummit@lists.lab.invalid` labels every
delivery junk): largest change of P(junk) in every other mailbox 0.0 in all three runs; decisions
changed in the poisoned mailbox 15, 12 and 10.

## 3 · Found on the way

`List-Id` was never read: mail-parser parses it as an address, so `list.id` was 0 for every lab
message. Fixed in `firstread-parse` (raw header value, whitespace collapsed); the cost of memory off
stayed 84.80 and `list.id` now has weight −0.20.

## 4 · Limits

- The profiles are assumptions: owners act on true labels at fixed rates; real owners mislabel,
  act later or not at all.
- Rescues are rare (3 to 6 per timeline), because memory off puts almost no legitimate mail in
  Junk. The `ok` weights rest on a handful of calib examples, and `sender_ok_log` and
  `domain_ok_log` get the same weight because each rescued sender is its domain's only one.
- One SpamAssassin mailbox holds 63 % of the timeline; SpamAssassin is 2002–2005 English mail; the
  false-positive side rests on 49 dev hard-ham messages.
- Three fits ran on dev; residual was picked after the first two failed, for its structural
  property. Dev is no longer blind to this question, and the learning test has no sealed
  counterpart yet.
- **Identity.** Memory keys on the From address. Only IBANs wait for verified identity (DMARC pass
  in a trusted `Authentication-Results`). A forger using a correspondent's address gets that
  correspondent's history (`wrote_to_*`, `*_ok_log`), and an owner junking the forgery junks the
  real sender. 681 of the 7,652 timeline messages (8.9 %) carry a verified identity. Before memory
  may lower P(junk) outside shadow mode, the history that lowers it must be read only for verified
  identities, and that needs `Authentication-Results` from the MTA or firstread's own
  SPF/DKIM/DMARC with recorded DNS.

Reproduce: after `sh lab/reproduce.sh <lab_data>` (data, renders, ONNX export, embedding cache),
`HF_HUB_OFFLINE=1 python3 -I lab/harness/learning.py <short run dir>` (AF_UNIX paths limit the run
dir to a short path). `memory = "joint"` with `disabled = []` gives the joint row, adding
`"mailbox.first_contact", "mailbox.unknown_thread"` to `disabled` gives the second, and
`memory = "residual"` gives the third. Combiner releases in the result files identify each fit.
