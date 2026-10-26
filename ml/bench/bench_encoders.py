"""CPU latency of small encoders/embedders on mail-sized inputs + a tiny NL/EN sanity check.
Usage: python3 -I bench_encoders.py <cache_dir>
"""
import sys, os, time, statistics, json
cache = sys.argv[1]
os.environ["HF_HOME"] = cache
import torch
torch.set_num_threads(os.cpu_count())
from transformers import AutoTokenizer, AutoModel

NL_INV = "Beste klant, uw factuur van oktober staat klaar. Het bedrag van EUR 112,40 wordt automatisch afgeschreven."
EN_INV = "Dear customer, your October invoice is ready. The amount of EUR 112.40 will be debited automatically."
NL_NEWS = "Mis onze herfstuitverkoop niet: 30% korting op alles dit weekend met code HERFST30."
NL_BEC = ("Hoi, ik zit in een overleg. Kun je vandaag nog EUR 18.450 overmaken naar onze nieuwe leverancier? "
          "Het IBAN is gewijzigd. Bespreek dit niet met anderen.")
EN_BEC = ("Hi, I'm in a meeting. Can you wire EUR 18,450 to our new supplier today? "
          "The bank details changed. Keep this between us.")
LONG = (NL_BEC + " ") * 12  # ~400-500 tokens

def timeit(fn, n):
    fn()
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return statistics.median(ts) * 1000

def cos(a, b):
    return float(torch.nn.functional.cosine_similarity(a, b, dim=-1))

out = {}

# 1) mmBERT-small: raw encoder forward (proxy for a fine-tuned multi-head classifier)
tok = AutoTokenizer.from_pretrained("jhu-clsp/mmBERT-small")
mdl = AutoModel.from_pretrained("jhu-clsp/mmBERT-small").eval()
for L in (256, 512):
    enc = tok(LONG, truncation=True, max_length=L, return_tensors="pt")
    with torch.no_grad():
        ms = timeit(lambda: mdl(**enc), 10)
    out[f"mmbert_small_fwd_{enc['input_ids'].shape[1]}tok_ms"] = round(ms, 1)
    print(f"mmBERT-small forward {enc['input_ids'].shape[1]} tok: {ms:.0f} ms")

# 2) multilingual-e5-small (mean pooling, 'query: ' prefix)
tok = AutoTokenizer.from_pretrained("intfloat/multilingual-e5-small")
mdl = AutoModel.from_pretrained("intfloat/multilingual-e5-small").eval()
def e5(texts, L=512):
    enc = tok(["query: " + t for t in texts], truncation=True, max_length=L, padding=True, return_tensors="pt")
    with torch.no_grad():
        h = mdl(**enc).last_hidden_state
    m = enc["attention_mask"].unsqueeze(-1).float()
    v = (h * m).sum(1) / m.sum(1)
    return torch.nn.functional.normalize(v, dim=-1)
ms = timeit(lambda: e5([LONG]), 10)
v = e5([NL_INV, EN_INV, NL_NEWS, NL_BEC, EN_BEC])
out["e5_small_512tok_ms"] = round(ms, 1)
out["e5_sims"] = {"nl_inv~en_inv": cos(v[0], v[1]), "nl_inv~nl_news": cos(v[0], v[2]), "nl_bec~en_bec": cos(v[3], v[4]), "nl_bec~nl_inv": cos(v[3], v[0])}
print(f"multilingual-e5-small ~512 tok: {ms:.0f} ms  sims={out['e5_sims']}")

# 3) harrier-oss-v1-270m via sentence-transformers
from sentence_transformers import SentenceTransformer
st = SentenceTransformer("microsoft/harrier-oss-v1-270m", device="cpu")
st.max_seq_length = 512
ms = timeit(lambda: st.encode([LONG], normalize_embeddings=True), 8)
v = torch.tensor(st.encode([NL_INV, EN_INV, NL_NEWS, NL_BEC, EN_BEC], normalize_embeddings=True))
out["harrier270m_512tok_ms"] = round(ms, 1)
out["harrier_dim"] = int(v.shape[1])
out["harrier_sims"] = {"nl_inv~en_inv": cos(v[0], v[1]), "nl_inv~nl_news": cos(v[0], v[2]), "nl_bec~en_bec": cos(v[3], v[4]), "nl_bec~nl_inv": cos(v[3], v[0])}
print(f"harrier-oss-v1-270m ~512 tok: {ms:.0f} ms dim={v.shape[1]} sims={out['harrier_sims']}")

# 4) potion-multilingual-128M (static)
from model2vec import StaticModel
sm = StaticModel.from_pretrained("minishlab/potion-multilingual-128M")
ms = timeit(lambda: sm.encode([LONG]), 50)
v = torch.tensor(sm.encode([NL_INV, EN_INV, NL_NEWS, NL_BEC, EN_BEC]))
v = torch.nn.functional.normalize(v, dim=-1)
out["potion_ml_ms"] = round(ms, 3)
out["potion_dim"] = int(v.shape[1])
out["potion_sims"] = {"nl_inv~en_inv": cos(v[0], v[1]), "nl_inv~nl_news": cos(v[0], v[2]), "nl_bec~en_bec": cos(v[3], v[4]), "nl_bec~nl_inv": cos(v[3], v[0])}
print(f"potion-multilingual-128M: {ms:.2f} ms dim={v.shape[1]} sims={out['potion_sims']}")

out["threads"] = torch.get_num_threads()
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_encoders_result.json"), "w"), indent=1)
