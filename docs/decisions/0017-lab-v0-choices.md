# ADR-0017 · v0 choices from the first lab loop

Status: accepted for v0; every item names what would reopen it

Evidence: [measurements/2026-10-26-lab-v0.md](../measurements/2026-10-26-lab-v0.md) and
[measurements/2026-10-26-lab-pareto-loop.md](../measurements/2026-10-26-lab-pareto-loop.md). The only
within-source labelled data was the SpamAssassin corpus (English, 2002 to 2005), so these choices
are about the delivery path, the code and the method more than about Dutch mail.

## Decision

1. **Tier-1 embedder: multilingual-e5-small on ONNX Runtime, int8 (dynamic quantisation), 192
   tokens, 2 threads, SentencePiece tokenizer**, `query: ` prefix, one logistic head per question
   with a temperature fitted on a held-out split. Under the three-axis rule (tag `oct26b`) each of
   these steps kept quality equal and cut latency or footprint beyond noise: ONNX int8 against
   torch fp32 latency ×0.43, CPU ×0.42, memory ×0.57; 192 tokens against 256 latency ×0.90, CPU
   ×0.86; SentencePiece against the `tokenizers` library memory ×0.63 (the library holds about
   300 MB for e5's 250k-entry vocabulary). 160 and 128 tokens each put a legitimate message in
   Junk. e5-small beat potion-multilingual-128M beyond noise on quality in tag `oct26`; potion is
   4× faster than the champion but worse on quality and holds 1.9 GB. mmBERT-small was not better
   beyond noise and ranked mail worst head alone; harrier-270m was worse on all three axes
   (latency ×9.9, memory ×5.2). Against the starting point (torch fp32, 256 tokens) in one timing
   pass: latency ×0.36, CPU ×0.35, memory ×0.35 (1,087 to 385 MB). Reopen when: a Dutch labelled
   set exists; an embedder beats it there beyond noise; or production CPUs change the latency
   picture.
2. **Combiner: logistic with an L1 penalty, C=4; heads stay at C=1.** On dev the combiner steps
   (C=2, then L1, then C=4 with L1) cut cost from 121.0 to 84.8 per 1,000 with no legitimate message
   in Junk; C=4 without L1, C=1 or 8 with L1, a recalibration and a class-balanced head did not
   pass, nor did head C=0.5, 2 or 3. These are dev choices: on the one sealed query the champion
   scored 350 per 1,000 (three of 25 hard-ham messages in Junk), and the starting point has not
   been scored there. Reopen when: a sealed comparison of the two exists, or shadow mode gives
   real legitimate mail.
3. **Junk threshold: the Bayes decision from the cost table**, P(junk) ≥ 100/101 ≈ 0.990, not a
   value tuned on dev. In tag `oct26`, dev showed 0.97 would catch 31 % more spam with no false
   positive, but the first false positives sat between 0.97 and 0.95 on 664 legitimate messages,
   and one costs 100.
   On the sealed split, swept once over λ fixed beforehand (9 to 999), 0.990 put 3 of 830
   legitimate primary messages in Junk and left 33 % of spam in the inbox; λ = 20 (0.952) would put
   4 and leave 26 %; the hard-ham errors survive λ = 999 (one left). Reopen when: shadow mode on
   real mail gives a legitimate set large enough to locate that edge, or the owner changes the
   costs.
4. **All 32 tier-0 facts stay.** Links, subject and meta facts help beyond noise; authentication
   cannot be measured on this data (no trusted `Authentication-Results`) and stays because identity
   is deterministic code ([04](../04-models.md)); the rest are neutral here and stay as unproven,
   to be ablated again on Dutch data. The IBAN detector requires a known country code, that
   country's exact length, word boundaries and mod-97.
5. **The lab's weights never ship.** Its heads and combiners learnt corpus fingerprints (for
   example one-click unsubscribe towards junk, because only the modern spam had it), and they were
   trained on sources recorded as evaluation-only. Production heads and combiners are trained on
   sources whose terms allow it (`use = "train"`: untroubled spam, synthetic Dutch, and consented
   capture of the deployment's own mail), with the lab's method and gates.
6. **v0 runs in shadow mode first** ([07](../07-evaluation.md), rollout step 1): `firstreadd
   --shadow` decides and records every message but replies with an empty directive, so nothing is
   visible and nothing is filed, until a combiner trained on that deployment's labelled mail passes
   the lab's gates on replay.
7. **The filter's own deadline stays well below `sieve_filter_exec_timeout`.** On Dovecot 2.3.21 /
   Pigeonhole 0.5.21, a filter killed at that timeout makes the LMTP process panic and the message
   is not stored. `firstread-filter` defaults to 2,000 ms on a separate thread and falls back by
   itself; operators keep `sieve_filter_exec_timeout` at least a few seconds above it.
   Reopen when: a Dovecot release that handles the kill is the minimum supported version.
8. **The lab refuses to train on a source whose recorded use does not allow it.** Lab-internal
   training on evaluation-only sources is an explicit list in `lab/datasets.toml`, set by the owner.

## Open, for the owner

- λ itself. 100 is the geometric middle of the literature's 9 (sender asked to resend) and 999
  (blocked mail deleted); where a Junk folder sits between them depends on whether people look in
  it, or get a digest of it. The sweep in the
  [loop measurement](../measurements/2026-10-26-lab-pareto-loop.md) shows what 9 to 999 do on the
  sealed split. This is a price, so it is the owner's.
- A second sealed query (`sealed_queries_per_tag`), to score the starting point and the champion
  together.
- Confirm or empty `[lab] internal_training` in `lab/datasets.toml` (now SpamAssassin and lore,
  flagged; the v0 runs used both before the check existed).
- Price phishing and fraud left in the inbox, and the `inbox_marked` action. On the synthetic
  slice the tag-`oct26` champion missed all 7 CEO-fraud messages; Junk is the wrong place for them
  anyway.
- Whether a bag-of-words n-gram head joins the embedder: it ranks the 2002 English mail better
  (AUC 0.993 against 0.987) but catches fewer at the strict threshold; it needs a provider to be
  measured on the full path.

## Consequences

- Day one in production needs consented capture of the deployment's own mail: nothing the lab
  trained may decide there.
- The v0 stack is measured end to end on real Dovecot: forged firstread headers never survive,
  the user's own rules win, and every failure path tested delivers the message to the inbox.
