# Working in this repository

firstread gives every email a first read at delivery, stamps it with everything knowable, and
learns continuously from how people treat their mail. Start with `README.md`, then
`docs/00-goal.md`, `docs/01-architecture.md` and `docs/08-learning.md`.

## Truthfulness

- Do not state a number you did not measure or cannot link to a source. Measurements go in
  `docs/measurements/` with hardware, runtime, precision, sample size and the script.
- Do not assume the production mail stack (MTA, Dovecot version, panel, Rspamd, hardware, volume).
  Design so it works without the assumption, and write the open question down.
- Model cards are claims. A model or learner is good when it passes `docs/07-evaluation.md`.
- When the docs turn out wrong, fix them in the same change.

## Non-negotiables

- Fail open: no path may lose, bounce or indefinitely delay mail because firstread failed. Every
  inline step has a deadline. Fail-open is counted and alerted on.
- Identity and authentication are deterministic code, never a model output.
- Never fetch URLs found in mail; never execute attachments.
- No customer mail in the repository, fixtures, logs above debug level, model hubs, external APIs
  or the commons.
- Scope rules from `docs/08-learning.md` are enforced in code: personal data cannot reach platform
  or commons paths except through the k-threshold and bulk-only gates, and those gates have tests.
- "Not junk" never propagates beyond the mailbox / organisation; commons carries bad-only indicators.
- Learners never train on firstread's own verdicts as labels.
- Anything that changes decisions for other people is promoted only through champion / challenger
  on replay, and can be rolled back.
- Feedback links act only on POST from a confirmation page.

## Structure

- Library crates know nothing about sockets, Dovecot or Postfix; binaries do. Every signal is
  testable on one `.eml` (`firstread inspect`); every learner on a recorded event log (`firstread replay`).
- Every model output uses the typed-decision contract in `firstread-core`.
- Thresholds, keyword names, reason texts, brand and provider lists, modes are data files.
- Architectural changes get an ADR in `docs/decisions/`.

## Done means

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass.
- New signals have fixtures that prove they fire and that they do not.
- New learners pass the week-one replay test and the poisoning test.
- Performance claims come with a measurement file.
