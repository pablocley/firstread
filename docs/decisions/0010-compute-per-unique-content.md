# ADR-0010 · Compute per unique content, personalise per recipient

Status: accepted; cache hit rate to be measured on real traffic

Expensive analysis (embedding, heads, tier 2) is keyed on a normalised content key with
per-recipient tokens removed, cached platform-wide, and reused for every copy. Per recipient, only
cheap work runs: authentication context, sender relationship, personal residuals, exemplars,
thresholds.

The same key drives campaign clustering and marks which content counts as bulk, the only content
allowed to teach beyond one mailbox. One mechanism for cost, detection and privacy.

Risk: over-aggressive normalisation could merge genuinely different messages. Mitigation: the key
covers visible text, normalised link targets and attachment hashes; collisions are measured on the
evaluation set.
