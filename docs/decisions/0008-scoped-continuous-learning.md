# ADR-0008 · Continuous learning in scopes, on an event log

Status: accepted

## Decision

- Every delivery, feedback event and model release is an event in an append-only log. Learners
  consume it; any day can be replayed through any learner state.
- Learning happens in layers, fastest first: reputation counters, exemplar memory, campaign memory,
  personal residual heads, personal thresholds, folder habits, daily platform heads, rare base-model
  releases ([08-learning.md](../08-learning.md)).
- Four scopes (mailbox, organisation, platform, commons) with explicit rules for what may cross.
  Personal mail teaches its own mailbox; bulk content and infrastructure teach the platform;
  bad-only, gated indicators reach the commons.
- Implicit feedback (moves, replies, flags, reads, deletes, tag edits) is the main label source;
  explicit feedback is one tap; no click or read tracking.
- Learned state that affects other people is promoted only by champion / challenger on replay,
  snapshotted, and reversible.

## Why

A fixed model cannot know a person's correspondents, a company's vendors or this morning's
campaign. The cheap layers that learn in real time are where most of the week-one gain comes from;
the slow layers keep the base sound. The event log makes all of it testable.

## Rejected

- Retraining one global model on everything nightly: slow to react, mixes personal data across
  mailboxes, and one bad night affects everyone.
- Personal fine-tuning of the encoder per mailbox: too expensive, too little data per mailbox.
