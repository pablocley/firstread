"""Which lab items answer which question, from what the items record (label, slice, subclass).

1, 0, or None (the item does not say; left out, never guessed). Shared by ml/heads/train.py and
ml/distill/teach.py, which checks a teacher against these before its answers are trusted.
"""

# Legitimate mail is never phishing or fraud. Junk says which kind only in the synthetic Dutch slice,
# whose subclasses are labelled by construction (lab/harness/synth_nl.py): heads and combiners for
# these questions rest on synthetic positives, which docs/13-lab.md calls optimistic.
SYNTH = "synthetic_nl"
FRAUD = {"fraud_ceo", "fraud_iban"}


def kind_label(subclasses):
    def f(it):
        if it["label"] != "junk":
            return 0
        if it["slice"] != SYNTH:
            return None
        return 1 if it.get("subclass") in subclasses else 0
    return f


LABELS = {
    "is_spam": lambda it: 1 if it["label"] == "junk" else 0,
    "risk_phishing": kind_label({"phishing"}),
    "risk_fraud": kind_label(FRAUD),
    "asks_payment_or_bank_change": lambda it: (None if it["slice"] != SYNTH else
                                               1 if it.get("subclass") in FRAUD | {"invoice", "reminder"} else 0),
}
VERDICT_LABELS = {"junk": LABELS["is_spam"], "phishing": LABELS["risk_phishing"], "fraud": LABELS["risk_fraud"]}
