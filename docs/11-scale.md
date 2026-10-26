# 11 · Scale

Designed for a platform with many mail nodes and millions of mailboxes, while still running on a
single small server. No platform's real volume is assumed anywhere in this document; plug in
measured numbers.

## Compute per unique content, not per copy

Most mail by volume is bulk: newsletters, notifications, campaigns, each sent to many mailboxes,
often personalised with a name or a tracking token. Analysing every copy wastes almost all the work.

1. Normalise the message: visible text, per-recipient tokens removed (the recipient's name and
   address, greeting lines, tracking and unsubscribe tokens in URLs), link targets normalised,
   attachments by hash.
2. Hash that into a **content key**.
3. Tier 1 (embedding, heads) and tier 2 run once per content key; results are cached platform-wide.
4. Per recipient, only the cheap part runs: authentication context, sender relationship, personal
   residual heads on the cached embedding, exemplar lookup, thresholds.

The content key is also what campaign clustering starts from, and bulk content is the only content
allowed to cross mailboxes ([08-learning.md](08-learning.md)), so one mechanism serves cost,
detection and privacy. The cache hit rate is a primary metric.

## Capacity, as a formula

```
cores for tier 1 ≈ (messages per second) × (unique-content fraction) × (core-seconds per unique message) / (target utilisation)
```

Measured so far ([baseline](measurements/2026-10-26-cpu-baseline.md)): multilingual-e5-small took
177 ms wall time on 2 threads in eager PyTorch for ~512 tokens, so at most ≈ 0.35 core-seconds per
unique message on that sandbox. ONNX Runtime with int8 on production CPUs is expected to be
cheaper but has **not been measured yet**.

Worked example with **assumed** inputs, to show the shape only: 5 million messages a day is
≈ 58 per second on average. With an assumed unique-content fraction of 0.3, 0.35 core-seconds per
unique message and 60% target utilisation, tier 1 needs ≈ 10 cores on average, more at peaks.
Replace every assumed number with a measurement before planning hardware.

Tier 2 is sized separately: it only sees the unsure fraction and user rules, it is asynchronous,
and it can live on one GPU box or a few CPU nodes.

## Storage, per unit

| item | size |
|---|---|
| one embedding, 384 dimensions | 1,536 B as float32, 768 B as float16, 384 B as int8 |
| one embedding, 640 dimensions | 2,560 B / 1,280 B / 640 B |
| embeddings are stored **per content key**, not per copy | bulk mail costs one vector |
| per-recipient record (scores, reasons, entities, ids) | small; dominated by entities |
| delivery event (features and decisions, no content) | small; retained for a configurable replay window |

## Layout

| component | placement | scales by |
|---|---|---|
| `firstreadd` | on every mail node, next to Dovecot | mail nodes; stateless apart from caches |
| per-mailbox and organisation state | central store, sharded by mailbox (organisations co-located) | shards |
| platform counters | counter store with approximate distinct counting (sketches) for k-thresholds | keys |
| content cache and vectors | central, keyed by content key | unique content |
| event log | append-only, partitioned by mailbox | partitions |
| learners | consumers of the event log, partitioned like it; platform aggregation as separate consumers | partitions |
| tier-2 service | separate pool, queue in front | queue depth |
| commons client | one per deployment | n/a |

The delivery path only ever does bounded-latency lookups with deadlines against local caches and
the stores; learning, aggregation, backfill and digests run off the event log, never inline.

## Degradation, in order

When load or a dependency fails, shed in this order and stamp what was skipped:

1. digests and backfill pause
2. tier 2 queue grows; low-priority items expire
3. inline tier 1 becomes post-delivery (hook C applies results)
4. tier-0 extras (RDAP, DNSBL beyond cache) skipped
5. never shed: parsing, authentication, stripping of spoofed headers, fail-open delivery

## Enabling at scale

Turning firstread on for an existing platform triggers mailbox backfill for every mailbox.
It runs at the lowest priority, rate-limited per storage node, newest mailboxes and most active
mailboxes first, resumable, and measured: backfill throughput and its I/O impact on IMAP latency
are metrics with limits.
