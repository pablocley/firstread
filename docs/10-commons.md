# 10 · Commons: learning across servers

## Should firstread learn across servers at all?

Yes, but narrowly. Two very different kinds of knowledge exist:

| knowledge | benefits from more servers? | why |
|---|---|---|
| **threats**: campaigns, malicious infrastructure, malicious attachments | **a lot** | attackers hit many platforms; the first platform to see a campaign can protect all others within minutes; small deployments gain the most |
| **preferences**: what a person or company considers important, which newsletters they like, how they file | **no** | inherently local; sharing it adds privacy risk and no accuracy |
| **general understanding of mail** (the models) | yes, slowly | better base models help everyone, but they ship as releases, not as live data |

So: share **threat evidence** live, share **models** as signed releases, share **nothing** about
preferences or legitimate mail.

## Options considered

| option | for | against | verdict |
|---|---|---|---|
| no cross-server learning | simplest, most private | every deployment rediscovers every campaign; small ones stay weak | the default; every deployment must work fully alone |
| central hosted service that scans everyone's mail | strongest signal | every customer's mail leaves its platform; latency; single point of failure; a privacy and legal non-starter | **rejected** |
| peer-to-peer gossip between deployments | no central party | Sybil attacks, moderation, discovery and abuse handling become very hard | rejected for now |
| federated learning of model weights | models improve from everyone's data without moving data | gradients leak without secure aggregation and differential privacy; heavy machinery for a gain we have not measured | deferred until measurement shows a gap the other parts leave |
| **hub-and-spoke threat commons, pull-based, signed, optional** | small hub; deployments stay autonomous; anyone can run a hub; a deployment can follow several hubs | someone has to run the first hub; trust between participants must be managed | **chosen** |

Precedent: Rspamd's public fuzzy-hash storage already lets independent installations share hashes
of known spam through a shared server ([fuzzy storage docs](https://docs.rspamd.com/tutorials/fuzzy_storage);
the maintainer reported the public service running with over 500k hashes in November 2025,
[mailing list](https://lists.rspamd.com/pipermail/users/2025-November/003868.html)).

## Does it need hosting?

A hub, yes, and it is small: ingest submissions, deduplicate, aggregate corroboration, sign, serve
deltas. No mail and no models run on it. firstread deployments never depend on it to deliver mail;
if every hub disappears, they continue on local learning and expire stale indicators.

Who runs the first hub is a governance choice, not a technical one. The project can run one;
any operator (a hosting company, a CERT, a group of providers) can run another; deployments choose
which hubs to follow and how much to trust each.

## What is shared

Only indicators that are **bad**, **bulk or infrastructure**, and **already confirmed locally**:

| indicator | shared form | gate before it may leave a deployment |
|---|---|---|
| campaign fingerprint | near-duplicate sketch of normalised bulk content (per-recipient tokens removed) | seen in ≥ *k* distinct mailboxes locally, and verdict bad with ≥ *k* corroborating mailboxes or an operator |
| URL | registrable domain; normalised URL with query and per-recipient path tokens stripped, as a hash | part of a confirmed-bad campaign, or reputation bad over ≥ *k* mailboxes |
| sender infrastructure | sending IP / prefix, ASN, DKIM signing domain, envelope / header From domain | reputation bad over ≥ *k* mailboxes; never an individual's address at a public free-mail provider |
| attachment | SHA-256 | confirmed malicious |
| campaign embedding centroid | vector centroid of a confirmed-bad bulk cluster | same as campaign fingerprint |

Every indicator carries: verdict, confidence, first and last seen, local count bucket (not exact
counts), expiry, and the submitting deployment's signature.

Never shared: anything about legitimate mail, allowlists, user behaviour, user identities, recipient
addresses, message content, per-mailbox learned state, or personal embeddings.

## Trust

| threat | guard |
|---|---|
| a malicious deployment whitelisting its spam | impossible by design: the commons carries *bad* evidence only; "good" never crosses servers |
| a malicious or broken deployment blacklisting a competitor or a legitimate sender | an indicator influences verdicts in proportion to independent corroboration (distinct deployments), weighted by each source's track record; a single source can at most add a weak signal; affected senders can be cleared by hub operators; every action is attributable by signature |
| stale indicators | every indicator expires unless re-confirmed |
| a compromised hub | hub signs aggregates; deployments verify; deployments can follow several hubs and require agreement |
| deanonymising users through the commons | the gates above: only bulk and infrastructure, only after the local k-threshold, coarse count buckets |

## Models through the commons

Model releases (heads, encoders, calibration) are published signed, with their evaluation report.
They can be trained on public data, distillation from open teacher models, and the indicators the
commons already carries (all of which are bad bulk content). They are never trained on a
participant's legitimate or personal mail. Each deployment evaluates a release on its own replay
set before promoting it ([07](07-evaluation.md)).

## Protocol sketch

- Pull: deployments fetch signed deltas every few minutes over HTTPS; a push channel for urgent,
  high-confidence campaigns is optional.
- Submit: deployments post signed indicator batches that passed their local gates.
- Format: compact records with a versioned schema; an export to STIX 2.1 for interoperability with
  existing threat-intelligence tooling is possible later.
- Identity: each deployment has a signing key registered with the hub; keys can be revoked.

## Legal

Sharing infrastructure and campaign indicators is security processing. GDPR Recital 49 describes
processing that is strictly necessary and proportionate for network and information security as a
legitimate interest, naming providers of electronic communications networks and services and of
security services, with examples such as preventing unauthorised access and stopping the spread of
malicious code ([Recital 49](https://gdpr-info.eu/recitals/no-49/)). Whether that covers each
indicator type above, and what the participation agreement must say, is for counsel to confirm
before the first hub goes live.
