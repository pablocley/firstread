"""CPU latency + sanity check of a 0.8B JEV-style decision model on Dutch/English mail.
Usage: python3 -I bench_jev08.py <model_dir>
"""
import sys, time, statistics, json, os

model_dir = sys.argv[1]
sys.path.insert(0, model_dir)
import torch
torch.set_num_threads(os.cpu_count())
from jev_style_decision import JevStyleDecision

MAILS = {
    "nl_bec": {
        "from": '"Maarten de Vries" <maarten.devries.ceo@gmail.com>',
        "reply_to": "finance-desk@protonmail.com",
        "subject": "Dringend: betaling vandaag nog",
        "body": ("Hoi, ik zit de hele dag in een overleg en ben slecht bereikbaar. Kun je vandaag nog een "
                 "spoedbetaling van EUR 18.450 doen aan onze nieuwe leverancier? Het IBAN is gewijzigd, gebruik "
                 "NL91 ABNA 0417 1643 00 t.n.v. Global Supply BV. Stuur me een bevestiging zodra het gedaan is "
                 "en bespreek dit niet met anderen, het is vertrouwelijk. Groet, Maarten"),
    },
    "nl_invoice": {
        "from": "facturen@energieleverancier.nl",
        "subject": "Uw factuur voor oktober 2026 staat klaar",
        "body": ("Beste klant, uw factuur van oktober 2026 staat klaar in Mijn Omgeving. Het bedrag van EUR 112,40 "
                 "wordt rond 28 oktober automatisch afgeschreven van uw rekening. U hoeft niets te doen. "
                 "Met vriendelijke groet, Klantenservice"),
    },
    "en_newsletter": {
        "from": "news@shop.example",
        "subject": "Autumn sale: 30% off everything this weekend",
        "body": ("Don't miss our biggest autumn sale. Use code FALL30 at checkout. "
                 "Unsubscribe: https://shop.example/u/abc123"),
    },
}

Q = [
    {"t": "noul", "ins": "The message asks the recipient to make a payment or to use changed bank details.", "crit": None},
    {"t": "noul", "ins": "The sender is impersonating someone (a colleague, executive, bank or brand) rather than writing as themselves.", "crit": None},
    {"t": "choice", "ins": "What kind of email is this?", "crit": {
        "personal": "written by a person to the recipient",
        "transactional": "invoice, receipt, order or account notice from a service the recipient uses",
        "marketing": "newsletter, promotion or advertising",
        "notification": "automated alert or status update",
        "security": "login, password or security alert",
        "scam": "phishing, fraud or scam attempt"}},
    {"t": "score", "ins": "How urgently does the recipient need to act?", "crit": [
        "no action", "can wait weeks", "this week", "within a day or two", "today", "immediately"]},
    {"t": "noul", "ins": "The recipient is expected to reply or do something.", "crit": None},
    {"t": "noul", "ins": "The message pressures the recipient to keep it secret or to skip normal checks.", "crit": None},
]


def state_of(m):
    return {"from": m["from"], "reply_to": m.get("reply_to"), "subject": m["subject"], "body": m["body"]}


t0 = time.perf_counter()
m = JevStyleDecision(model_dir, device="cpu", dtype="float32")
load_s = time.perf_counter() - t0
print(f"threads={torch.get_num_threads()} load={load_s:.1f}s")

# warmup
m.decide_many(state_of(MAILS["nl_invoice"]), Q[:1])

results = {}
for name, mail in MAILS.items():
    st = state_of(mail)
    out = m.decide_many(st, Q)
    results[name] = out
    print(f"\n== {name}  (input_tokens≈{out[0]['input_tokens']})")
    for q, r in zip(Q, out):
        p = r["probabilities"]
        top = max(p, key=p.get)
        print(f"  [{q['t']:6}] {q['ins'][:70]:70} -> {top} {p[top]:.2f}" + (f"  p(true)={p['true']:.2f}" if q['t']=='noul' else ""))

# latency: single noul question, and 6 questions in one decide_many
st = state_of(MAILS["nl_bec"])
single, many = [], []
for _ in range(12):
    t = time.perf_counter(); m.decide(st, Q[0]["ins"], qtype="noul"); single.append(time.perf_counter() - t)
for _ in range(6):
    t = time.perf_counter(); m.decide_many(st, Q); many.append(time.perf_counter() - t)
print(f"\nlatency single noul: median {statistics.median(single)*1000:.0f} ms  p90 {sorted(single)[int(len(single)*0.9)-1]*1000:.0f} ms")
print(f"latency 6 questions (decide_many): median {statistics.median(many)*1000:.0f} ms  min {min(many)*1000:.0f} ms")
json.dump({"load_s": load_s, "single_ms": [x*1000 for x in single], "many6_ms": [x*1000 for x in many],
           "threads": torch.get_num_threads(), "cpu": "see lscpu"},
          open(os.path.join(os.path.dirname(__file__), "bench_jev08_result.json"), "w"), indent=1)
