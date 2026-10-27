# fixtures/auth

Synthetic messages signed by dkimpy (an independent DKIM implementation) with throw-away keys,
the public keys and DMARC policies as a DNS recording (`dns.jsonl`), and what each message must
verify as (`expected.json`, checked by `crates/firstread-auth/tests/fixtures.rs` and the pipeline
tests). `make.py` regenerates all of it with new keys; the private keys are never written here.

Where firstread deliberately differs from dkimpy (both follow from the RFCs):

| case | dkimpy | firstread | why |
|---|---|---|---|
| `sha1` | pass | permerror | RFC 8301: verifiers must not consider rsa-sha1 signatures valid |
| `testing-key` | pass | permerror | RFC 6376 3.6.1: keys with `t=y` must not be treated differently from unsigned mail |
| `extra-from-on-top` | fail | pass, DMARC unusable | the signature covers the bottom From and verifies; two From fields verify no identity |
| `expiring-expired` | pass within 10 h of `x=` | permerror after `x=` | firstread allows no clock skew past `x=` |

On 1,615 real signatures in the lab's 2026 mail (lore, untroubled) with recorded DNS, firstread
and dkimpy agree on 1,580; all 35 differences are `t=y` keys
([measurement](../../docs/measurements/2026-10-27-auth-dns-memory-v1.md)).
