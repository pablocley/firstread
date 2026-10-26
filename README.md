# firstread

**Every email gets a first read before you do.**

firstread sits between the mail server accepting a message and any IMAP, POP3 or webmail client
fetching it. It reads every message once, at delivery, and stamps it with everything that can be
known about it: who really sent it, whether it is safe, what kind of mail it is, whether it needs
you, and what the rest of your mailbox, your organisation and the whole platform already know
about it.

In: the message plus its delivery context (recipient, envelope sender, trusted transport facts).
Out: a verdict and a small, validated edit list the mail system applies (headers, keywords, folder),
plus a full record for the API. Never a rewritten message: the body is never touched.

It learns from day one. Every move to Junk, every reply, every tag a user removes teaches it,
privately, at the right scope: the mailbox, the organisation, the platform, and (optionally)
other firstread deployments through a shared threat commons.

The name nods to System-1 decision models such as JEV: a fast, calibrated first read, with slower
deliberation only where it changes the answer.

## Status

Design phase. Nothing here filters mail yet.

| doc | settles |
|---|---|
| [00 · Goal](docs/00-goal.md) | purpose, scopes, principles, what firstread refuses to be |
| [01 · Architecture](docs/01-architecture.md) | where it sits, tiers, event log, failure modes, crates |
| [02 · Signals](docs/02-signals.md) | the mail taxonomy, every signal, threat coverage |
| [03 · Client contract](docs/03-client-contract.md) | headers, keywords, folders, digest, feedback links, API |
| [04 · Models](docs/04-models.md) | the JEV-style decision model, embeddings, measurements, distillation |
| [05 · Sending](docs/05-sending.md) | before send, at submission, after delivery |
| [06 · Security and privacy](docs/06-security-privacy.md) | hostile input, poisoning, data protection per scope |
| [07 · Evaluation](docs/07-evaluation.md) | how we know it works, including "better after a week" |
| [08 · Learning](docs/08-learning.md) | self-learning from day one: feedback, learners, cold start, guardrails |
| [09 · Experience](docs/09-experience.md) | how different people use mail, and what each of them sees |
| [10 · Commons](docs/10-commons.md) | learning across servers: what is shared, how, and what never is |
| [11 · Scale](docs/11-scale.md) | volume, compute per unique content, sharding, degradation |
| [12 · Interfaces](docs/12-interfaces.md) | exactly what goes in (message plus delivery context) and what comes out (verdict plus edit list, record, events), mapped to milter, Rspamd, SpamAssassin and Sieve |
| [decisions/](docs/decisions/) | architecture decision records |
| [measurements/](docs/measurements/) | numbers measured so far, with the scripts that produced them |

## Repository

```
crates/      Rust workspace: daemon, delivery filter, milter, CLI, and the libraries behind them
ml/          Python: distillation, training, calibration, evaluation, ONNX export, benchmarks
fixtures/    test messages (synthetic or explicitly consented; never raw customer mail)
docs/        design, decisions, measurements
```

Runtime in Rust, learning in Python: [ADR-0001](docs/decisions/0001-rust-runtime-python-learning.md).
firstread is a standalone product; any mail platform can run it: [ADR-0007](docs/decisions/0007-independent-product.md).

## Ground rules

- Never lose or delay mail because firstread is slow or broken. Fail open, and alert on it.
- Never claim a number that was not measured. Every figure links to its source or measurement.
- Customer mail never enters this repository, a model hub, an external AI API, or the commons.
