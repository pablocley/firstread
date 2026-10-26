# 14 · Providers: any System 1 model behind one contract

firstread must outlive every model it starts with. JEV-style decision models, encoders with heads,
and whatever comes next all plug in behind the same two interfaces, and swapping one is an entry in
the registry plus a calibration run, never a code change in the delivery path.

## 1 · Two kinds of provider

| kind | does | examples |
|---|---|---|
| **decider** | reads one rendered message and **many typed questions at once**, returns raw logits per question in outcome order | tier-1 heads on an embedding; a JEV-style 0.8B model behind llama.cpp; JEV-9B on a GPU box; a future encoder that reads state and questions in one pass |
| **embedder** | turns rendered text into a vector in a named **space** | multilingual-e5-small, harrier-oss-v1-270m, mmBERT fine-tunes, static potion embeddings for fingerprints |

Both are in `firstread-core::provider`. Library code sees only these traits; ONNX Runtime,
llama.cpp, vLLM or an HTTP endpoint are backends behind them.

Many questions per call is part of the contract because one decoder pass per question does not fit
the delivery path ([04](04-models.md): ≈ 2.1 s per question on our sandbox).

## 2 · The manifest

Every provider ships a manifest; the registry is a data file.

| field | why |
|---|---|
| release id | recorded in every decision and stamp |
| weights sha256 | supply chain; a mismatch disables that provider |
| licence, commercial use allowed | a model we may not use commercially never reaches customer mail |
| locality: in-process, local service, remote | decides which data it may see (section 4) |
| languages | measured in the lab, not copied from a model card |
| maximum input | the renderer truncates to it and records that it did |
| prompt template (deciders) | how a typed question is put to this model; JEV-style models expect their own format |
| space (embedders) | model, version, preprocessing and dimension; vectors from different spaces never meet |

## 3 · Calibration makes models interchangeable

- Providers return **raw logits**. A calibration file per (release, question), fitted on the lab's
  dev split, turns them into the `noul` / `choice` / `score` distributions of
  `firstread-core::decision`.
- **No calibration, no decision:** a (release, question) pair without a fitted calibration returns
  an error instead of a guess. A new model cannot silently change behaviour.
- Thresholds act on calibrated probabilities, so they keep their meaning across models. They are
  still re-checked in the lab for every new release, because two calibrated models can rank
  messages differently.

## 4 · Data rules, enforced in code

| locality | public and synthetic data | customer mail |
|---|---|---|
| in-process | yes | yes, if the licence allows commercial use |
| local service (llama.cpp, vLLM on our own hardware) | yes | yes, if the licence allows commercial use |
| remote (any external API) | in the lab only, and only where the dataset's terms allow sending it out | **never** ([06](06-security-privacy.md): no mail content to an external AI API) |

The check runs before every call, in the lab and in production, and the lab gate "data rules"
([13](13-lab.md) section 5) fails a run that broke it.

## 5 · Embedding spaces and swaps

Vectors are stored with their space id. Search, exemplar memory and heads all belong to one space.

Swapping the embedder:

1. Add the new release to the registry; the lab fits heads and calibration in the new space and
   measures it, including search quality on the retrieval set ([15](15-ai-native-clients.md)).
2. On promotion, deliveries write both spaces; a background job re-embeds existing mail from the
   mailbox itself (labels are keyed by message, not by vector, so exemplars survive).
3. Reads switch per mailbox once its backfill is complete; the old space is deleted afterwards.

Comparing vectors across spaces is refused by the code, not left to discipline.

## 6 · What a new model must pass

The same as any other change: the lab's gates and cost ([13](13-lab.md)), the sealed test, then
champion / challenger and shadow mode. A model card is a claim; the lab is the measurement.
