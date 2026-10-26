# 07 · Evaluation

Nothing ships on someone else's model card. Every model, learner and threshold is accepted on our
own data, on our own hardware, and the learning claim is tested like any other.

## Evaluation sets

| slice | source | labels |
|---|---|---|
| Dutch business mail: invoices, quotes, orders, shipping, customer requests | synthetic from real templates; consented samples where a basis exists | axes, tags, action required, urgency |
| Dutch personal and everyday mail: government, school, health, travel, social | synthetic, public senders | axes |
| phishing and fraud: banks, tax office, DigiD, parcels, payment requests, CEO fraud, IBAN change, QR, callback, extortion | synthetic plus confirmed bulk campaigns (structure and fingerprints; content only with a basis) | risk, reasons |
| English and German counterparts | same | same |
| machine mail: monitoring, cron, notifications, bounces, auto-replies | synthetic, public | sender kind |
| injection attempts | written in-house | must not move verdicts |
| **hard negatives**: real-looking legitimate mail that looks scary (genuine payment requests from known suppliers, real password resets, urgent mail from colleagues) | synthetic | must stay clean; a veto set |
| **event-log replays**: recorded delivery and feedback events (features, not content) | from shadow mode on the platform | the learning tests below |

Fixtures are `.eml` with label files; replays are event logs. Raw customer mail never enters the repository.

## Metrics

| metric | why |
|---|---|
| phishing / fraud recall at a fixed false-positive rate on hard negatives | false positives on real invoices are what customers notice |
| per language, per mailbox mode, per protocol (IMAP / POP3) | an average hides the people it fails |
| calibration error and reliability per head | per-action thresholds only work on calibrated scores |
| tag precision / recall per axis value | |
| **rescue rate**: mail moved out of Junk per 1,000 filed | live false positives |
| **report rate**: mail moved into Junk per 1,000 kept in the inbox | live false negatives |
| **tag-correction rate**: tags removed or added per 1,000 tagged | live tag quality |
| warnings per user per week | the alert budget |
| delivery latency added, p50 / p99 per tier, on production hardware | what may run inline |
| core-seconds per message, content-cache hit rate | capacity |
| fail-open, degraded and deadline-miss rates | silent failure is the worst failure |
| quantisation parity: int8 vs fp32 top-1 agreement | accept quantised models only if they make the same calls |
| ticket volume by category | the business outcome |

## The learning tests

**Week-one test** (the acceptance test for "self-learning"):

1. Freeze learner state at day 0.
2. Replay days 0–7 through all learners.
3. Score day-8 messages with day-0 and day-7 state; compare with day-8 labels.
4. Pass when day-7 beats day-0 on the core verdicts in every language and mode slice with enough
   data, and loses on no hard negative.

**Backfill test**: for a set of consenting mailboxes, compare day-0 decisions with and without the
mailbox backfill. Backfill must help or be switched off.

**Promotion test** (every day, for platform heads and combiner): challenger vs champion on the most
recent held-out days; promote only on a win with the hard-negative veto; keep the loser's report.

**Poisoning test**: replay with injected adversarial feedback (sock puppets, feedback storms);
verdicts for other mailboxes must not move beyond a set tolerance.

## Rollout

1. Shadow: stamps and decisions go to the event log only. Learners run. Nothing visible.
2. Compare with Rspamd and with user behaviour; set thresholds from data; run the week-one test on
   real replays.
3. Headers and keywords on.
4. Folders by mode; digest opt-in.
5. Retroactive campaign actions.
6. Subject prefix and banners last, per measured false-positive rate.
7. Commons participation after legal review.
