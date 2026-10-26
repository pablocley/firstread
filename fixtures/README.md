# fixtures/

Test messages as `.eml` files, each with a `.labels.toml` next to it describing what firstread
should conclude (verdicts, tags, reasons that must appear, signals that must fire).

Allowed here: synthetic messages written for testing, public newsletters, and messages whose owner
has explicitly agreed to their use. Never raw customer mail. Personal data in fixtures is invented
(use IBANs and BSNs that are valid by checksum but known test values, never real ones).

Suggested layout:

```
inbound/phishing/      bank, tax office, DigiD, parcel, payment request lures (nl, en, de)
inbound/fraud/         CEO fraud, invoice with changed IBAN, lookalike-domain threads
inbound/legit/         invoices, receipts, shipping, newsletters, personal, calendar
inbound/hard-negative/ legitimate mail that looks scary
inbound/injection/     messages that try to talk the model out of a verdict
inbound/malformed/     broken MIME, huge headers, deep nesting (parser hardening)
outbound/              drafts for the pre-send checks
```
