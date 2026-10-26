# ADR-0003 · Rspamd is a signal source, not something to rebuild

Status: accepted

Spam scoring with Bayes, fuzzy hashes, RBLs, URL blocklists and years of rules is a solved,
maintained problem. Rebuilding it in Rust is years of work for no differentiation.

## Decision

- If Rspamd (or another scanner) runs at the MTA, firstread reads its result from the headers it
  added, trusting them only when added by our own MTA.
- If it does not, firstread can call Rspamd's HTTP scanning API directly.
- Rspamd's score and symbols are inputs to firstread's combiner, next to its own signals.
- User feedback (hook D) can be forwarded to Rspamd's learning as well, so both improve.

## What firstread adds that Rspamd does not do

Per-mailbox memory (sender relationship, vendor bank-detail history), typed calibrated decisions
beyond spam / ham, client-facing tags and keywords, platform-wide campaign verdicts applied
retroactively, outbound user-facing checks, and the API.

Rspamd's own GPT module (local LLMs via Ollama supported, per [its docs](https://docs.rspamd.com/modules/gpt/))
stays an optional extra signal.
