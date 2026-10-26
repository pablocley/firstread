# ADR-0009 · Cross-server learning through an optional threat commons

Status: accepted (design); first hub after legal review

## Decision

- Every deployment works fully on its own. Cross-server learning is optional.
- Deployments exchange **bad-only threat indicators** (bulk-campaign fingerprints, malicious
  infrastructure, URL domains, attachment hashes) through **pull-based, signed hubs**. Anyone can run
  a hub; a deployment can follow several.
- Indicators leave a deployment only after its local k-threshold and confirmation gates.
- Preferences, allowlists, behaviour, identities and legitimate content never cross servers.
- Models cross servers only as signed releases with evaluation reports, never trained on
  participants' legitimate mail.

## Rejected

- A central service that scans everyone's mail (privacy, latency, single point of failure).
- Peer-to-peer gossip (Sybil resistance and moderation without a hub).
- Federated learning of weights, for now (leakage without secure aggregation and differential
  privacy; benefit unmeasured).

Details: [10-commons.md](../10-commons.md).
