# 02 · Signals

## The mail people actually receive

One flat list of categories breaks on real mail: an invoice can come from a person or a system, be
expected or a scam, urgent or not. firstread describes every message on independent axes, each a
typed decision, and derives the few tags a user sees from them ([09-experience.md](09-experience.md)).

| axis | type | values |
|---|---|---|
| **sender kind** | `choice` | person · organisation, transactional · organisation, bulk · machine / system · mailing list · auto-reply · bounce / delivery report |
| **topic** (multi-label) | `noul` per topic | money (invoice, receipt, payment, bank) · orders and shipping · travel and tickets · account and security · work and projects · customers (requests, quotes, complaints) · government · health · education and school · social and community · calendar and events · news and content · promotions · jobs · legal · personal life |
| **intent** | `choice` | inform · request action · request reply · sell · scam |
| **risk** | `noul` per risk | spam · phishing · payment / invoice fraud · malware · extortion · callback scam |
| **urgency** | `score` 0–5 | from "no action" to "now" |
| **importance to this person** | `score`, personalised | learned from this mailbox's behaviour |

The long tail this has to cover, explicitly: password resets and 2FA codes, login alerts, parcel
notices, receipts, subscription renewals, bank and tax letters, government message-box notices,
school portals, doctor appointments, calendar invites, out-of-office replies, bounces, server and
monitoring alerts (hosting customers get many), GitHub-style notifications, forum digests, mailing
list discussions, cold sales outreach (legitimate but unwanted, not spam), newsletters you read,
newsletters you never read, forwarded chains, and every flavour of scam.

## Per message

### Authenticity and transport (tier 0)

| signal | notes |
|---|---|
| SPF (MAIL FROM, HELO), DKIM per signature (v1, v2), DMARC with alignment and policy, ARC | ARC is on the historic track ([mail-auth README](https://github.com/stalwartlabs/mail-auth)) but still helps with known forwarders |
| last-hop TLS, client IP, forward-confirmed rDNS, ASN, country | from our own MTA's Received line only |
| Rspamd score, action, symbols | trusted only when added by our own MTA |
| Received-chain sanity | hop count, impossible timestamps, private addresses in public hops |
| backscatter | a bounce for mail this mailbox never sent |

### Identity (tier 0, deterministic)

| signal | notes |
|---|---|
| display-name spoofing | a brand, colleague or contact name the authenticated address does not back up |
| Reply-To divergence | to a free-mail or very young domain |
| lookalike domain | confusables, punycode, edit distance to domains this mailbox, its organisation and the platform know, **including the customer's own domains** |
| brand impersonation | brand invoked in name or body, authenticated domain not the brand's; first data sets for Dutch themes: banks, tax office, DigiD, parcel carriers, payment requests, fines |
| sender domain age | RDAP registration date |
| first sighting | sender, domain, DKIM signer new to this mailbox / organisation / platform |
| fake reply | Subject or quoting says "reply" but nothing in the mailbox's history matches `In-Reply-To` / `References` |

### Content (tier 0 extraction, tier 1 understanding)

| signal | notes |
|---|---|
| the axes above | tier-1 heads, personal residuals, exemplar memory; tier 2 when unsure |
| asks for credentials, payment, bank-detail change, personal data, gift cards, remote access, a phone call | separate `noul` heads; each a possible reason |
| extracted entities | IBAN (mod-97), BSN (11-proef; detected, never stored), amounts, dates and deadlines (nl, en, de formats), OTP codes, tracking numbers, order and invoice numbers, phone numbers, crypto addresses, `text/calendar` invites |
| links | count, domains, text vs target mismatch, shorteners, IP literals, URL domain age, links hosted on large legitimate platforms (shared documents, e-signature) |
| **QR codes** | decoded from images and PDF attachments; treated as links (QR phishing has no visible URL) |
| visible vs hidden text | text as rendered; ratio of hidden text, zero-width and homoglyph characters |
| instructions to an AI | `noul` head: the message addresses an AI assistant or agent (orders to ignore instructions, hidden requests to summarise, forward or fetch); with hidden text, it drives the safety block AI clients receive ([15](15-ai-native-clients.md) section 5) |
| attachments | type by content, double extensions, macros, HTML attachments (local phishing pages), encrypted archives with the password in the body, executables, size |
| image-only or PDF-only lure | flagged in tier 0; OCR in tier 2 only when other signals are suspicious |
| list facts | `List-Unsubscribe`, one-click (RFC 8058), `List-Id` |
| trackers | tracking pixels and known tracker domains (information for the user; firstread itself never tracks) |

## Per mailbox

Built in v0 ([ADR-0018](decisions/0018-mailbox-memory-v0.md), `firstread-graph`, inputs
`mailbox.*`): sender relationship (seen, written to, first contact, judged junk or not by the
owner, per address and per domain), known and unknown threads (a reply to nothing this mailbox
received or sent), and an IBAN new or known for a sender domain. Only the IBAN facts wait for a
verified identity; the others key on the From address, which falls short of the safety floor below
until history that lowers P(junk) is read only for verified identities (ADR-0018). The rest of this
table is not built.

| signal | notes |
|---|---|
| **sender relationship** | none / seen / you wrote to them / regular two-way correspondent; seeded from the Sent folder |
| **sender profile anomaly** | a known sender behaving unlike themselves: new link domains, new attachment types, different language or style, first payment request, sent at unusual hours. Catches thread hijacking from compromised accounts, where authentication passes |
| **bank-detail change** | an invoice or payment request from a sender you have paid before, now with a different IBAN |
| folder habit | where this person files mail like this |
| importance prior | how this person treats this sender and kind of mail: replies, flags, reads quickly, deletes unread |
| thread state | awaiting your reply, awaiting theirs |
| subscriptions | every list, frequency, read rate |
| duplicates, storage hogs | |

## Per organisation (admin opt-in)

| signal | notes |
|---|---|
| colleague impersonation | display name of a colleague from an outside address |
| organisation-wide sender relationship | "nobody in this company has ever corresponded with this domain" |
| shared vendors and their bank details | an IBAN change caught even if this employee never paid this vendor |
| shared mailboxes | `info@`, `support@`: learned as a team, routed by intent (quote request, complaint, invoice) |

## Platform-wide

Only aggregates keyed by infrastructure or bulk content cross mailboxes, and only after enough
independent mailboxes contributed ([08-learning.md](08-learning.md)).

| signal | notes |
|---|---|
| campaign id, size, spread rate | near-duplicate fingerprints plus embeddings |
| campaign verdict | from feedback on other copies, tier 2, operators, the commons; applied retroactively |
| reputation | sender domain, DKIM signer, IP / ASN, URL domains, attachment hashes, with counts |
| targeted vs bulk | spear-phishing is rare and dangerous; bulk is common and cheap to stop |

## Commons (optional)

Indicators from other deployments, weighted by how many independent sources confirm them
([10-commons.md](10-commons.md)).

## Verdicts

A calibrated combiner turns all of the above into the few conclusions clients act on, each with
its top reasons:

| verdict | drives |
|---|---|
| `phishing` | `$Phishing`, warning, quarantine at a strict threshold |
| `fraud` | warning with the specific reason (bank-detail change, impersonated colleague) |
| `junk` | `$Junk`, Junk folder, with per-user thresholds |
| `important` | `$Important`, stays in the inbox, may notify |
| `needs_action` | a firstread keyword, the digest's action list |
| `bulk_low_interest` | quiet folder or tag; unsubscribe suggestion |

**Safety floor.** A user can teach firstread that a sender's newsletters are wanted; they cannot
switch off phishing warnings for mail that fails authentication or comes from a lookalike domain.
"Trust this sender" binds only to an authenticated identity.

## Threat coverage, explicitly

| attack | covered by |
|---|---|
| mass phishing | campaign clustering, reputation, heads, commons |
| spear-phishing, first contact | sender relationship, domain age, lookalike, intent heads |
| CEO / colleague fraud | display-name vs organisation directory, Reply-To divergence, payment and secrecy heads |
| invoice / IBAN fraud, including from a genuinely compromised vendor | bank-detail change (works even when authentication passes) |
| thread hijacking from a compromised known account | sender profile anomaly |
| abuse of legitimate platforms (shared-document and e-signature notices) | link target analysis and intent, not authentication |
| QR phishing | QR decoding |
| callback scams (no link, "call this number") | callback head plus phone number extraction |
| image-only and PDF-only lures | tier-0 flag, tier-2 OCR |
| HTML evasion | rendered visible text, hidden-text signals |
| malware | attachment structure, hashes, reputation, encrypted archive with password in body |
| extortion | intent head plus crypto address extraction |
| fluent AI-written scams | nothing relies on spelling mistakes; identity, relationship and intent carry the weight |
| fake replies | `In-Reply-To` checked against mailbox history |
| lookalikes of the customer's own domain | lookalike check against organisation domains; also reported to the organisation |
