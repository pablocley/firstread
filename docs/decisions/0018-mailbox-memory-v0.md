# ADR-0018 · Mailbox memory v0: hashed facts from deliveries and the owner's own actions

Status: accepted for v0; the store choice of ADR-0006 stays open

## Context

Until now every decision looked at one message alone. The sealed query of tag `oct26b` showed
where that fails: three legitimate hard-ham messages (commercial mail the owner wanted) in Junk at
any threshold ([measurement](../measurements/2026-10-26-lab-pareto-loop.md)). What tells such mail
apart is history: this mailbox has received from this sender before, its owner wrote to them,
rescued them from Junk, or replies within a thread that exists. docs/02-signals.md ("Per mailbox")
and docs/08-learning.md describe that memory; none of it was built.

## Decision

1. **Three events, no verdicts.** Memory is a fold over `Delivered` (a message reached the mailbox,
   whatever firstread decided), `Label` (the owner judged a message junk or not junk) and `Sent`
   (a copy reached Sent). No event carries a firstread verdict, so memory cannot learn from
   firstread itself (`firstread-graph`).
2. **Facts, not decisions.** Memory adds named inputs (`mailbox.*`: sender and domain seen, junked
   and rescued by the owner, written to, first contact, known and unknown thread, IBAN new or known
   for a sender domain) to the combiner. The combiner, trained like any other, decides how much
   they weigh; a combiner that needs them refuses to score without them. Memory is fitted as a
   residual (`[combiner] memory = "residual"`): the combiner without memory first, then memory
   weights on top of its logit without an intercept and without the absence facts
   (`first_contact`, `unknown_thread`), so mail the mailbox knows nothing about is decided exactly
   as without memory. Fitting everything jointly moved the intercept towards Junk for every
   stranger and put a legitimate first contact in Junk
   ([measurement](../measurements/2026-10-27-mailbox-memory.md)).
3. **Read before, apply after.** Facts come from the state before the message; the record names
   that state (`provenance.snapshot`, the number of events applied). The delivery is applied after
   the reply reaches the filter, under the mailbox's lock, so deliveries to one mailbox are decided
   in order and the delivery path never waits on a write.
4. **Keyed hashes only.** Addresses, domains, Message-IDs and IBANs are stored as HMAC-SHA256
   under a key derived from the deployment key. Facts need equality, nothing else. Files are named
   by the keyed hash of the mailbox.
5. **The event log is the source of truth.** Per mailbox: an append-only log of applied events and a
   state saved every 50 events; loading replays the log past the saved state. `forget` deletes
   both (erasure follows the mailbox, docs/06-security-privacy.md).
6. **Bounded.** Message-IDs 50,000, senders and domains 20,000 each (the oldest the owner never
   labelled go first), labels 20,000, IBANs 8 per domain.
7. **IBANs only from verified mail.** An IBAN is remembered for a domain only when DMARC passed for
   it in `Authentication-Results` from inside our boundary, so a forger cannot make an IBAN known.
8. **Feedback arrives on its own socket**, never on the delivery path: `firstread feedback`, called
   by Dovecot IMAPSieve scripts when the owner moves mail into Junk, out of Junk (not to Trash), or
   a copy reaches Sent (hook D). Feedback from actors listed in `--own-actors` (firstread's own
   accounts) is dropped and never learned. Shadow mode learns too (rollout step 1).
9. **One store behind a trait.** `MemoryStore` with a file implementation (one directory, the
   single-server profile of ADR-0006). A central store is a second implementation.

## Consequences

- Measured on real Dovecot 2.3.21: a rescue from Junk changes the next delivery from that sender,
  moving mail into Junk does the reverse, moving junk to Trash teaches nothing, a reply to a mail the
  owner sent is a known thread, and delivery-time filing by firstread produces no label
  (`lab/results/l2-dovecot-2.3.21.txt`).
- One mailbox's memory never reaches another's decisions: by construction (state per mailbox) and
  tested in the daemon and in the lab's poisoning check (largest change in other mailboxes 0.0).
- Learning test on dev, λ = 100 (residual fit): cost per 1,000 −8.27 [−14.48, −2.07] with active
  owners, −2.07 [−8.27, +3.10] with passive owners, +4.14 [+1.03, +8.27] with owners who never act,
  no new legitimate message in Junk in any profile. That fails the rule of improving under several
  profiles, so memory is not a champion change; it runs only with `--memory`.
- Delivery counts (`*_seen_log`) are raised by anyone who sends; with no owner actions they are all
  memory has, and they cost spam caught. Whether they stay an input is the next question.
- **Identity gap.** Facts key on the From address; only IBANs wait for verified identity. A forger
  using a correspondent's address gets that correspondent's history, and an owner junking the
  forgery junks the real sender. Before memory may lower P(junk) outside shadow mode, history that
  lowers it must be read only for verified identities (DMARC pass in a trusted
  `Authentication-Results`), which needs the MTA's `Authentication-Results` or firstread's own
  SPF/DKIM/DMARC with recorded DNS.
- Not built yet: organisation scope, hook G events (`$Junk` / `$NotJunk` flags, replies seen as
  `\Answered`), backfill of an existing mailbox's history, folder habits, exemplar memory, and a
  way to tell firstread's own IMAP sessions apart in IMAPSieve (hook C is to use `doveadm`, which
  does not run IMAPSieve).
- Domain-level facts treat a free-mail domain like any other; whether that needs a provider list
  (a data file) is open.
