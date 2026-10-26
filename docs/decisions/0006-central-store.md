# ADR-0006 · State stores and event log

Status: **open**: requirements fixed, products chosen by measurement

## Needs

| store | holds | access pattern |
|---|---|---|
| mailbox and organisation state | correspondents, vendors and bank details over time, sender profiles, exemplars, residual heads, thresholds, folder habits, subscriptions, settings | read on every delivery with a deadline; written by learners; sharded by mailbox, organisations co-located; deletable per mailbox and per message |
| platform counters | reputation per infrastructure key and outcome, distinct-mailbox sketches for k-thresholds | very high write rate, approximate is fine |
| content cache and vectors | tier-1 results and embeddings per content key | read on every delivery; nearest-neighbour within a mailbox (exemplars, search) and within a recent window platform-wide (campaigns) |
| event log | deliveries, feedback, releases | append-only, partitioned by mailbox, replayable for a configurable window |
| snapshots | learner state per day | write daily, read on rollback and replay |

Nothing here may sit in the delivery critical path without a deadline and a degraded mode.

## Candidates to evaluate

| option | for | against |
|---|---|---|
| PostgreSQL (with a vector extension) for state and vectors, a log system for events | few systems, transactions, partitioning, familiar operations | vector and counter write performance at real volume to be measured |
| PostgreSQL plus dedicated vector index and counter store | each part scales on its own | more systems to run |
| embedded stores per mail node (e.g. SQLite) plus central aggregation | no network hop on delivery; runs on one small server | cross-node campaigns and organisations become aggregation problems |

A single-server deployment profile (everything embedded) and a platform profile (shared stores)
can coexist behind the same traits.

## Decide by

Measured latency and throughput at the target platform's real message volume and mailbox count,
including deletion by mailbox and by message, and replay speed. Nothing chosen from benchmarks
published elsewhere.
