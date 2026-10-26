# 08 · Learning

firstread is self-learning from the first message. A deployment, a mailbox and an organisation
each start from something useful and get better from what people already do with their mail.
"Better after a week" is a measured claim, with the method in [07-evaluation.md](07-evaluation.md).

## 1 · Where the labels come from

Most users will never press a feedback button. The system has to learn mostly from behaviour,
weight it by how much it really says, and make explicit feedback cost one tap.

| source | effort | what it teaches | strength | channel |
|---|---|---|---|---|
| move into Junk | none extra | junk / scam for this mailbox | strong | IMAPSieve (hook D) |
| move out of Junk | none extra | not junk; also a false positive to learn from | strong | IMAPSieve |
| client sets `$Junk` / `$NotJunk` | none extra | same | strong | push events (hook G) |
| remove or add a firstread tag | none extra | that tag was wrong / right | strong for that tag | push events |
| move to the user's own folder | none extra | this kind of mail belongs there | strong for folder habits | IMAPSieve |
| reply, forward | none | wanted, probably important, not bulk-junk | medium | Sent folder, `\Answered`, `$Forwarded` |
| flag | none | important | medium | push events |
| read soon after arrival | none | interest | weak | `message_read` |
| deleted unread | none | low interest (not "junk": people delete bills they already know) | weak | `message_trash` / `message_expunge` |
| never read, list mail | none | low interest in that list | weak, accumulates | absence of `message_read` |
| one-tap webmail banner or digest link | one tap | the verdict or tag in question | strong | API (F) |
| webmail buttons and "why?" corrections | one tap | verdict, tag, or which reason was wrong | strong | API |
| campaign confirmed bad | none | every copy is bad | strong, platform | platform loop |
| support or abuse desk labels | staff | ground truth for hard cases | strongest, rare | admin API |
| DSN / bounce outcomes, compromised account confirmed | none | outbound labels | strong | MTA logs, support |

Weak signals are never acted on alone. Their weights are learned by comparing them with strong
labels on the same messages, per mailbox type, and kept only where they predict.

What firstread does **not** use: link clicks, read receipts, tracking pixels, time spent reading.
It does not track people.

What is **not a label**: anything firstread did itself. Keywords present at delivery, keywords and
moves made through hook C, and Sieve filing by firstread's own scripts are recorded when they
happen, and the event adapter drops their echoes (`flags_set`, IMAPSieve copies) before any
learner sees them. Only changes a person makes after delivery count.

## 2 · Learners, from fastest to slowest

| learner | scope | what it is | reacts within |
|---|---|---|---|
| **reputation counters** | mailbox, organisation, platform | Beta-binomial counts per key (sender, domain, DKIM signer, IP / ASN, URL domain, attachment hash, campaign) and outcome, with time decay | the next message |
| **exemplar memory** | mailbox, organisation | embeddings of messages the user labelled (explicitly or strongly implicitly), kept with their labels; a new message's nearest labelled neighbours vote. One correction fixes the next near-identical message | the next message |
| **campaign memory** | platform | cluster ids with verdicts; a verdict on one copy reaches all copies, including already delivered ones (hook C) | seconds to minutes |
| **personal residual heads** | mailbox | per decision, a small online logistic model on top of the global head's logit and a few personal features, regularised towards zero so it only moves where this person consistently differs | after enough labels for that head; minutes |
| **personal thresholds** | mailbox | per action, adjusted by this person's rescue rate (often rescues from Junk → stricter Junk filing) | days |
| **folder habit miner** | mailbox | frequent "this sender / list / kind → that folder" patterns; above support and confidence it becomes a *suggestion*, never a silent rule | days |
| **platform heads and combiner** | platform | retrained daily from the event log, trust-weighted, on bulk-content examples with aggregated labels, deterministic ground truth, and labelled mail from organisations that opted in; personal mail trains only its own mailbox's learners. Promoted only by champion / challenger on replay (below) | a day |
| **user rules** | mailbox | natural-language rule answered by the tier-2 model; corrections become labels; promoted to a tier-1 head once it beats tier 2 on held-out data | instantly usable; cheaper over weeks |
| **base models** | deployment, commons | encoder and decision-model refresh by distillation ([04-models.md](04-models.md)) | releases, months |

All learners read the same event log, so all of them can be replayed and audited.

## 3 · Cold start: nobody starts from zero

| starts | from |
|---|---|
| a new deployment | shipped global heads and decision model; shipped reputation priors from public data; commons indicators if it joins |
| a newly enabled mailbox | **its own history**: the Sent folder seeds the correspondent graph and colleague list; existing folders become labels for folder habits; the Junk folder becomes weak negatives (old filters made mistakes too); flags and answered marks seed importance; read patterns of lists seed newsletter interest |
| a new organisation | its domains, its mailboxes' Sent folders (organisation graph), shared vendors from past invoices |
| a brand-new user with an empty mailbox | organisation and platform scopes; personal learners switch on as labels arrive |

The mailbox backfill is throttled (I/O-friendly, resumable), headers-first, and embeds only recent
months by default. It runs under the same privacy rules as live mail.

## 4 · What crosses scopes

| from → to | may cross | never crosses |
|---|---|---|
| mailbox → organisation (admin opt-in) | colleague directory, vendor bank details seen, labelled exemplars of business mail, sender relationships at company level | private mail of individuals; read behaviour; personal residuals |
| mailbox / organisation → platform | counts per infrastructure key and outcome; campaign membership of bulk content | anything about individual correspondents; content of non-bulk mail; who reads what |
| platform → commons | see [10-commons.md](10-commons.md): bad-only indicators that passed the platform's k-threshold | everything else |

Two rules make platform-level learning private by construction:

- **k-threshold.** A platform aggregate only influences other mailboxes once at least *k* distinct,
  established mailboxes contributed (distinct counts kept with HyperLogLog-style sketches). One
  person's behaviour is never visible through it, and one account cannot move it.
- **Bulk-only content.** Content fingerprints and embeddings cross mailboxes only for mail that is
  itself bulk (seen in at least *k* mailboxes). Personal mail can never qualify.

## 5 · Guardrails

| risk | guard |
|---|---|
| **poisoning by sock-puppet accounts** (marking their own spam "not junk" to whitelist it) | trust weight per account (age, history, agreement with consensus); cap per account per key; k-threshold; **asymmetry**: "not junk" acts only in the mailbox (and organisation), "junk / scam" can reach the platform after corroboration |
| a user whitelisting a scam | safety floor: authentication failures and lookalikes keep their warning; "trust this sender" binds to an authenticated identity only |
| learning from its own mistakes | training labels come from people and ground truth, never from firstread's own past verdicts |
| selection bias (mail filed away gets no feedback) | the digest shows a sample of borderline filtered mail with one-tap rescue, which gives the counterfactual labels |
| implicit-signal noise | weights learned against strong labels; weak signals never act alone |
| a worse model or learner state | daily snapshots; champion / challenger on replay over held-out recent days, per language and mailbox type, with hard negatives as a veto; one-command rollback; the stamp names the snapshot that decided |
| drift (new campaigns, seasons, new senders) | counters decay; exemplars age out; daily retraining; drift alarms on score distributions |
| feedback storms (a big campaign, a client bug setting flags) | rate limits per source, anomaly detection on feedback volume, quarantine of suspicious feedback batches |
| the right to erasure | per-mailbox learned state is separable and deletable (`DELETE /v1/me/learning`); platform aggregates hold no per-person data by construction |

## 6 · How we know it learned

The acceptance test for "self-learning" (details in [07](07-evaluation.md)):

1. Freeze learner state at day 0.
2. Replay days 0–7 of events through the learners.
3. Score day-8 messages with the day-0 state and with the day-7 state; compare against the
   labels that arrive for day-8 messages.
4. The day-7 state must win on the core verdicts, per language and per mailbox type, and lose on
   none of the hard negatives.

Live, the same shows as falling rescue rate (mail moved out of Junk per thousand filed), falling
report rate (mail moved into Junk per thousand delivered to the inbox), and falling tag-correction rate.
