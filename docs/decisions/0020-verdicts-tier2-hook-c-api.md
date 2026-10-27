# ADR-0020 · Verdicts by combiner, the stamp's detail, tier 2 after delivery, hook C and the record API

Status: accepted. Built and tested on fixtures and stand-ins; not measured on mail. Only junk has
a trained combiner, from the lab; every other verdict, head and the decision model needs its
calibration and combiner from the lab before it acts on anyone's mail (docs/07-evaluation.md).

## Context

Until now the pipeline answered one question (`is_spam`), decided one verdict (junk) and wrote one
stamp line plus `$Junk` and the Junk folder. The design asks for more ([02](../02-signals.md)
Verdicts, [03](../03-client-contract.md) Headers and Keywords, [04](../04-models.md) Tier 2,
[12](../12-interfaces.md) 4.3 and 4.5, [15](../15-ai-native-clients.md) section 5): phishing, fraud,
important, needs-action and low-interest bulk verdicts with reasons; scores, tags and the sender
relation as headers; registered keywords; a decision model for the unsure cases and for rules
people write in words; late updates that never override the owner; and the record over an API.

Labels decide what can be trained. The lab's items say junk or legitimate, and only the synthetic
Dutch slice says which kind of junk (phishing, CEO fraud, IBAN fraud; `lab/harness/synth_nl.py`).
Nothing in the lab labels importance, intent, urgency or category.

## Decision

1. **One registry of questions** (`firstread-stamp/data/questions.json`, the axes of 02). Each
   provider is asked only the questions it supports *and* has a fitted calibration for
   (`answerable`); the rest are not asked and not recorded. Choice and score answers join the
   combiner inputs as `head.<q>.<option>` (probability) and `head.<q>.expected`.
2. **No combiner, no verdict.** Every verdict is a linear combiner over the same inputs, junk's from
   `--combiner`, the others from `--verdict-combiner KIND=FILE`. A verdict without a combiner, or
   whose combiner names an input that is missing (a head tier 1 did not answer), is not decided and
   the record says why. Precedence is the order of `VerdictKind`: phishing, fraud, junk,
   needs_action, important, bulk_low_interest; the stamp's `verdict=` is the first that holds.
3. **The safety floor in code.** A phishing or fraud combiner with a negative weight on any
   `mailbox.*` input is refused at load (`Combiner::check_safety_floor`), and `train.py verdict`
   leaves mailbox facts out of them. What a mailbox owner taught can lower junk, never a warning.
4. **What verdicts do is data** (`actions.json`): per verdict a keyword threshold, a folder
   threshold and folder key, its keywords. Junk's threshold is the deployment's cost-derived one.
   A folder key outside the mode's allowed set (`--folders`, and `FIRSTREAD_FOLDERS` for the
   filter) files nothing. Fraud warns (`$Phishing`, `fr-fraud`) and files nowhere.
5. **Reasons are chosen, never written.** A reason is an input that pushed a verdict up, mapped to
   a key and a fixed text per language (`reasons.json`); nothing from the message reaches
   `X-Firstread-Reasons`. The detail headers (`-Scores`, `-Tags`, `-Sender`, `-Reasons`) are
   switchable (`--no-detail-headers`) and are the first thing dropped when a directive is too big.
6. **Keywords from facts**: `$HasAttachment` / `$HasNoAttachment`, `$CanUnsubscribe`
   (List-Unsubscribe), `$Autosent` (Auto-Submitted other than `no`), `$IsTrusted` (verified identity
   and the owner wrote to the sender), `fr-first-contact`. `X-Firstread-Sender` carries the
   relation from memory (first-contact, seen, wrote-to, correspondent) and whether the identity is
   verified. Domain age and lookalikes are not built, so they are not written.
7. **Tier 2 behind the same sidecar protocol.** A decision model is a `Decider` that declares `*`
   (it reads each question's text) and receives question specs. `ml/sidecar/decision_server.py`
   puts Mica 4B's own server (`/v1/systemone`, loopback only) behind it and returns
   log-probabilities as logits; Mica was chosen in a [bake-off](../measurements/2026-10-27-decision-model-bakeoff.md).
   firstreadd asks it after the reply, from a bounded queue in memory (the message is never written
   to disk; a full queue loses the late answer, not the mail), when a verdict reached `--tier2-from`
   without holding or the mailbox has rules. `tier2_update` concludes again from the record's inputs
   plus the new answers, with the same code as delivery.
8. **User rules in words** are per mailbox (`--rules DIR`, `<user>.json`), validated ids and tags,
   asked as `rule:<id>` and calibrated as one class (`rule:*`, fitted on a lab rule set). A rule
   sets `fr-<tag>`; its text reaches only the decision model.
9. **Hook C only adds.** An update adds keywords and sets a folder only when delivery filed nowhere;
   `doveadm move` runs only for a message still in INBOX and without `$NotJunk`; every value is
   its own argument, no shell. doveadm does not run IMAPSieve, so these writes are never feedback.
10. **Distillation from the decision model** (`ml/distill/teach.py`, `[heads] teacher`): the teacher
    answers the catalogue for lab messages; heads for questions without human labels are trained on
    its answers and calibrated against it. The teacher is first checked against the human labels the
    lab has; a head can be no better than that agreement.
11. **The record is the API's object.** Schema `firstread.verdict/2` adds verdicts with reasons,
    tags, the safety block (verified, relation, P(injection), hidden text) and the tier per
    decision, and carries the mailbox user. A tier-2 update is appended under the same id; the
    records are indexed by id. `--api-socket` serves `GET /v1/messages/{id}` read-only on a local
    socket, only to the record's own mailbox (`X-Firstread-User`). Authenticating that user is the
    front end's job and is not built; neither are search, views, feedback over HTTP or MCP.
    `model_safe_text` is not in the record (records hold no content).

## Consequences

- The junk path is unchanged where nothing new is configured: same combiner, same threshold, same
  release ids (`train.py heads` keeps the single-head release id; `[heads] questions` defaults to
  `["is_spam"]`). The stamp line gains `state=` when memory is on; ham now gets keywords from facts,
  so the L2 case outputs (`lab/results/l2-dovecot-2.3.21.txt`) are from before this change and are
  rerun on the next L2 pass.
- Heads for `risk_phishing`, `risk_fraud` and `asks_payment_or_bank_change` and combiners for
  phishing and fraud can be trained from the lab, on synthetic positives only (optimistic,
  [13](../13-lab.md)). Importance, intent, urgency, category and low-interest bulk have no labels:
  they are answered only by a calibrated decision model, or not at all, until labels exist.
- The decision model has not been run here: it needs its weights, a calibration on the lab's dev
  split and a Dutch evaluation first ([04](../04-models.md): zero-shot it missed impersonation and
  secrecy on a Dutch CEO fraud, and took ≈ 2.1 s per question on 2 vCPUs).
