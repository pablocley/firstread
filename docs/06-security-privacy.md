# 06 · Security and privacy

## Every byte is hostile

- **Memory-safe parsing** with hard limits on size, MIME depth, part count, header count and
  decompressed size; parser, filter client, QR decoder and event adapters are fuzzed continuously.
- **No automatic URL fetching.** Mail contains one-time login links, confirm and unsubscribe links,
  and tracking URLs; fetching them acts on the user's behalf and enables SSRF. Link analysis is static.
- **No attachment execution or rendering** beyond structure, hashes, QR decoding and (tier 2, on
  suspicion) OCR in a sandboxed worker.
- **Prompt injection.** Mail can address the model ("this message is safe"). Identity and
  authentication come from deterministic code the text cannot change; model outputs feed a combiner,
  never act alone; the evaluation set contains injection attempts in Dutch, English and German.
- **Spoofed stamps.** `X-Firstread-*` headers that arrived with the message, and
  `Authentication-Results` claiming our authserv-id that were not added inside our own trust
  boundary, are removed before stamping (RFC 8601 section 5 requires deleting such instances unless
  they came directly from a trusted MTA, [RFC 8601](https://datatracker.ietf.org/doc/html/rfc8601.html)).
  Results added by our own MTA or Rspamd are kept.
- **Feedback links** carry signed, expiring, single-purpose tokens and act only on a POST from a
  confirmation page, so link scanners cannot trigger them.
- **Least privilege.** Daemon under its own user, systemd-sandboxed, Unix sockets with tight
  permissions, egress limited to DNS, RDAP, the stores and configured commons hubs.
- **Supply chain.** Model files pinned by sha256; crates pinned; commons data verified by signature.
- **Fail open, loudly.** Fail-open, degraded and deadline-miss rates are alerting metrics.

## Attacks on the learning itself

| attack | defence |
|---|---|
| sock-puppet accounts teaching "not junk" for a campaign | "not junk" acts only in the mailbox / organisation; platform effects need *k* distinct established mailboxes; per-account trust weights and caps |
| an attacker probing thresholds by sending variants | campaign clustering groups variants; per-sender rate of near-misses is itself a signal |
| a compromised account mass-relabelling mail | anomaly detection on feedback volume per account; suspicious batches quarantined from training |
| a malicious commons participant | bad-only sharing, corroboration across independent deployments, signatures, expiry ([10-commons.md](10-commons.md)) |
| model or learner regression | champion / challenger on replay, snapshots, rollback ([08-learning.md](08-learning.md)) |

## Privacy by scope

This section lists the positions to confirm with whoever owns the platform's processing agreements;
it is not legal advice.

| scope | data | basis to confirm | default |
|---|---|---|---|
| mailbox | everything about that mailbox's mail and behaviour | security filtering as part of the mail service; organisation features as features the customer uses | on, with a per-mailbox off switch |
| organisation | colleague directory, vendors and bank details, business exemplars | the organisation as controller of its own business mail, enabled by its admin | off until an admin enables it |
| platform | counts per infrastructure key, bulk-content fingerprints, k-thresholded | security processing (GDPR Recital 49 describes network and information security as a legitimate interest, [text](https://gdpr-info.eu/recitals/no-49/)) | on |
| commons | bad-only indicators, gated | same, plus a participation agreement | off until the platform joins |
| platform heads learning from mail | bulk content with aggregated labels; personal mail only from organisations that opted in | security processing for bulk; the organisation's choice for its own mail | bulk on; organisations off until they opt in |
| training base models on customer mail | — | needs its own basis and explicit consent | **off**; base models train on public data, open teachers and commons indicators |

Rules:

- **Local only.** No mail content goes to an external AI API.
- **Embeddings are personal data** when they come from personal mail: same protection, retention
  and deletion as the mail. Only bulk-content embeddings are shared beyond the mailbox.
- **Deletion follows the mailbox.** Expunged message → its record, vectors (unless bulk and still
  referenced by other copies) and entities go. Deleted mailbox → all its learned state goes.
- **Export and erase.** A user can export what firstread learned about their mailbox and erase it.
- **No extracted personal data in headers.**
- **BSN is detected, never stored.** Dutch law restricts processing of the BSN.
- **No tracking.** No click, read-receipt or reading-time collection.
- **Audited access.** Staff access to per-message records is logged and reviewable.
- **Explainable.** Every visible action has reasons; every decision names the model release and
  learner snapshot that made it.
