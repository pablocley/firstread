"""Tier-1 embedding providers for the local sidecar (docs/14-providers.md).

Each embedder has a manifest (licence, commercial use, template, token limit) and runs in one
configuration: a runtime (torch, onnx, or numpy for static embeddings), a numeric format
(fp32 or int8), a token limit and a thread count. The space id holds everything that changes the
vectors (model, input template, token limit, runtime and numeric format, render version), so
vectors made differently never mix. Thread count is left out: it changes only the order of
floating-point sums, not the model.

Models load in the configured format explicitly; some default to bfloat16, which is slower on CPUs
without bf16 support and gives different vectors. int8 is dynamic quantisation (weights int8,
activations quantised per call), so vectors depend on what is in a batch: caches are filled one
message at a time, as delivery computes them.

Every model loads from a pinned Hugging Face revision (`revision` below), so a rerun gets the same
weights. ONNX models are exported once by `export_onnx.py` into `$FIRSTREAD_ONNX_DIR/<embedder>/`
with a sha256 manifest, which is checked at load.
"""

import hashlib
import json
import os
import sqlite3
import time

import numpy as np

EMBEDDERS = {
    "potion-ml-128m": {"hf": "minishlab/potion-multilingual-128M", "revision": "73908c3438cf03b6a01bcb9611d62b23d0726f08",
                        "files": ["config.json", "model.safetensors", "tokenizer.json", "README.md"],
                        "kind": "model2vec",
                        "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 0,
                        "runtimes": {"numpy": ["fp32"]}},
    "e5-small": {"hf": "intfloat/multilingual-e5-small", "revision": "614241f622f53c4eeff9890bdc4f31cfecc418b3",
                  "files": ["config.json", "model.safetensors", "sentencepiece.bpe.model", "special_tokens_map.json",
                            "tokenizer.json", "tokenizer_config.json"],
                  "kind": "meanpool",
                  "licence": "MIT", "commercial_use": True, "template": "query: {text}", "max_tokens": 256,
                  "runtimes": {"torch": ["fp32", "int8"], "onnx": ["fp32", "int8"]},
                  # The model's own SentencePiece file, with XLM-R's fairseq id layout: bos 0, pad 1,
                  # eos 2, unk 3, SentencePiece ids shifted by one. Holds about 70 MB in memory where
                  # the `tokenizers` library holds about 300 MB for the same 250k-entry vocabulary.
                  "sentencepiece": {"file": "sentencepiece.bpe.model", "offset": 1, "bos": 0, "pad": 1,
                                    "eos": 2, "unk": 3}},
    # No onnx runtime: its export differed from torch by up to 3e-3 on the last hidden state
    # (export_onnx.py refuses above 1e-4), 2026-10-26.
    "mmbert-small": {"hf": "jhu-clsp/mmBERT-small", "revision": "abc32620dd4f6ab06f5fbe905dc25f310618e09f",
                      "files": ["config.json", "pytorch_model.bin", "special_tokens_map.json", "tokenizer.json",
                                "tokenizer_config.json"],
                      "kind": "meanpool",
                      "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 256,
                      "runtimes": {"torch": ["fp32", "int8"]}},
    "harrier-270m": {"hf": "microsoft/harrier-oss-v1-270m", "revision": "31de22b673913c7d658c0f03f792d77c2dcf8ebd",
                      "files": ["1_Pooling/config.json", "README.md", "config.json", "config_sentence_transformers.json",
                                "model.safetensors", "modules.json", "special_tokens_map.json", "tokenizer.json",
                                "tokenizer_config.json"],
                      "kind": "sentence_transformers",
                      "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 256,
                      "runtimes": {"torch": ["fp32", "int8"]}},
}


def resolve(name, runtime=None, precision=None, max_tokens=None, threads=None, ort_arena=None, tokenizer=None):
    """The full configuration of one embedder; unset fields take the registry defaults.

    ort_arena: onnxruntime's CPU memory arena and memory-pattern planning (on by default); they
    change memory use and speed, not the vectors, so they are not part of the space id.
    tokenizer: "hf" (the `tokenizers` library, default) or "sentencepiece" (onnx runtime, models
    with a SentencePiece file); the two split some inputs differently, so it is part of the space."""
    e = dict(EMBEDDERS[name])
    runtime = runtime or next(iter(e["runtimes"]))
    if runtime not in e["runtimes"]:
        raise ValueError(f"{name} has no {runtime} runtime ({sorted(e['runtimes'])})")
    precision = precision or "fp32"
    if precision not in e["runtimes"][runtime]:
        raise ValueError(f"{name} on {runtime} has no {precision} ({e['runtimes'][runtime]})")
    if max_tokens:
        if e["kind"] == "model2vec":
            raise ValueError("static embeddings have no token limit")
        e["max_tokens"] = int(max_tokens)
    tokenizer = tokenizer or "hf"
    if tokenizer == "sentencepiece" and (runtime != "onnx" or "sentencepiece" not in e):
        raise ValueError(f"{name} on {runtime} has no sentencepiece tokenizer")
    if tokenizer not in ("hf", "sentencepiece"):
        raise ValueError(f"unknown tokenizer {tokenizer}")
    e.update(name=name, runtime=runtime, precision=precision, threads=int(threads or os.cpu_count() or 1),
             ort_arena=True if ort_arena is None else bool(ort_arena), tokenizer=tokenizer)
    return e


def space_id(cfg, render_version):
    tok = "-sp" if cfg.get("tokenizer") == "sentencepiece" else ""
    return (f"{cfg['name']}|{cfg['template'].replace('{text}', 'T')}|{cfg['max_tokens']}|"
            f"{cfg['runtime']}-{cfg['precision']}{tok}|render:{render_version}")


def config_args(cfg):
    """Command-line flags that recreate `cfg` in server.py, embed_batch.py and latency.py."""
    return ["--embedder", cfg["name"], "--runtime", cfg["runtime"], "--precision", cfg["precision"],
            "--max-tokens", str(cfg["max_tokens"]), "--threads", str(cfg["threads"]),
            "--ort-arena", "1" if cfg["ort_arena"] else "0", "--tokenizer", cfg["tokenizer"]]


def add_config_args(ap):
    ap.add_argument("--embedder", required=True)
    ap.add_argument("--runtime")
    ap.add_argument("--precision")
    ap.add_argument("--max-tokens", type=int, default=0)
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--ort-arena", type=int, default=1)
    ap.add_argument("--tokenizer", default="hf")


def from_args(a):
    return resolve(a.embedder, a.runtime, a.precision, a.max_tokens or None, a.threads or None, bool(a.ort_arena),
                   a.tokenizer)


class Cache:
    def __init__(self, root: str, space: str):
        os.makedirs(root, exist_ok=True)
        fname = hashlib.sha256(space.encode()).hexdigest()[:16] + ".sqlite"
        self.db = sqlite3.connect(os.path.join(root, fname))
        self.db.execute("create table if not exists v (k text primary key, d blob)")
        self.db.execute("create table if not exists meta (k text primary key, v text)")
        self.db.execute("insert or replace into meta values ('space', ?)", (space,))
        self.db.commit()

    def get(self, key):
        r = self.db.execute("select d from v where k=?", (key,)).fetchone()
        return None if r is None else np.frombuffer(r[0], dtype=np.float32)

    def put_many(self, pairs):
        self.db.executemany("insert or replace into v values (?, ?)",
                            [(k, np.asarray(v, dtype=np.float32).tobytes()) for k, v in pairs])
        self.db.commit()

    def keys(self):
        return {r[0] for r in self.db.execute("select k from v")}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def onnx_path(name, precision):
    root = os.environ.get("FIRSTREAD_ONNX_DIR")
    if not root:
        raise RuntimeError("the onnx runtime needs FIRSTREAD_ONNX_DIR")
    d = os.path.join(root, name)
    manifest = json.load(open(os.path.join(d, "manifest.json")))
    path = os.path.join(d, manifest["files"][precision]["file"])
    if _sha256(path) != manifest["files"][precision]["sha256"]:
        raise RuntimeError(f"{path}: sha256 does not match its manifest")
    return path, manifest


def snapshot(cfg):
    """Local directory of the pinned revision, with only the files the model needs (downloaded on
    first use unless HF_HUB_OFFLINE=1)."""
    from huggingface_hub import snapshot_download
    return snapshot_download(cfg["hf"], revision=cfg["revision"], allow_patterns=cfg["files"])


def _normalise(v):
    n = np.linalg.norm(v, axis=1, keepdims=True)
    return (v / np.maximum(n, 1e-12)).astype(np.float32)


class Embedder:
    def __init__(self, cfg):
        self.cfg = cfg
        kind, runtime = cfg["kind"], cfg["runtime"]
        local = snapshot(cfg)
        if kind == "model2vec":
            from model2vec import StaticModel
            self.model = StaticModel.from_pretrained(local, force_download=False)
            return
        if runtime == "onnx":
            import onnxruntime as ort
            from tokenizers import Tokenizer
            path, manifest = onnx_path(cfg["name"], cfg["precision"])
            if cfg["tokenizer"] == "sentencepiece":
                import sentencepiece as spm
                self.sp_layout = cfg["sentencepiece"]
                self.sp = spm.SentencePieceProcessor(model_file=os.path.join(local, self.sp_layout["file"]))
            else:
                tok_path = os.path.join(local, "tokenizer.json")
                if _sha256(tok_path) != manifest["tokenizer_sha256"]:
                    raise RuntimeError(f"{tok_path}: tokenizer differs from the one exported with the model")
                self.tok = Tokenizer.from_file(tok_path)
                self.tok.enable_truncation(cfg["max_tokens"])
                pad = self.tok.token_to_id(manifest["pad_token"])
                self.tok.enable_padding(pad_id=pad, pad_token=manifest["pad_token"])
            so = ort.SessionOptions()
            so.intra_op_num_threads = cfg["threads"]
            so.inter_op_num_threads = 1
            so.enable_cpu_mem_arena = cfg["ort_arena"]
            so.enable_mem_pattern = cfg["ort_arena"]
            self.sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
            return
        import torch
        torch.set_num_threads(cfg["threads"])
        if kind == "sentence_transformers":
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(local, device="cpu", model_kwargs={"dtype": torch.float32})
            self.model.max_seq_length = cfg["max_tokens"]
            if cfg["precision"] == "int8":
                self.model[0].auto_model = torch.ao.quantization.quantize_dynamic(
                    self.model[0].auto_model, {torch.nn.Linear}, dtype=torch.qint8)
        else:
            from transformers import AutoModel, AutoTokenizer
            self.tok = AutoTokenizer.from_pretrained(local)
            self.model = AutoModel.from_pretrained(local, dtype=torch.float32).eval()
            if cfg["precision"] == "int8":
                self.model = torch.ao.quantization.quantize_dynamic(self.model, {torch.nn.Linear}, dtype=torch.qint8)

    def embed(self, texts):
        cfg = self.cfg
        inputs = [cfg["template"].replace("{text}", t) for t in texts]
        kind = cfg["kind"]
        if kind == "model2vec":
            return _normalise(np.asarray(self.model.encode(inputs), dtype=np.float32))
        if cfg["runtime"] == "onnx":
            # The fast tokenizer emits a token for trailing whitespace that the slow one drops.
            if cfg["tokenizer"] == "sentencepiece":
                ids, mask = self._sp_encode([s.rstrip() for s in inputs])
            else:
                enc = self.tok.encode_batch([s.rstrip() for s in inputs])
                ids = np.asarray([e.ids for e in enc], dtype=np.int64)
                mask = np.asarray([e.attention_mask for e in enc], dtype=np.int64)
            h = self.sess.run(None, {"input_ids": ids, "attention_mask": mask})[0]
            m = mask[..., None].astype(np.float32)
            return _normalise((h * m).sum(1) / np.maximum(m.sum(1), 1e-9))
        import torch
        if kind == "sentence_transformers":
            with torch.inference_mode():
                return np.asarray(self.model.encode(inputs, normalize_embeddings=True), dtype=np.float32)
        enc = self.tok(inputs, truncation=True, max_length=cfg["max_tokens"], padding=True, return_tensors="pt")
        with torch.inference_mode():
            h = self.model(**enc).last_hidden_state
        m = enc["attention_mask"].unsqueeze(-1).float()
        return _normalise(((h * m).sum(1) / m.sum(1)).numpy())


def _sp_encode_impl(self, texts):
    lay, n = self.sp_layout, self.cfg["max_tokens"]
    rows = []
    for t in texts:
        body = [i + lay["offset"] if i != self.sp.unk_id() else lay["unk"] for i in self.sp.encode(t)]
        rows.append([lay["bos"]] + body[:n - 2] + [lay["eos"]])
    width = max(len(r) for r in rows)
    ids = np.full((len(rows), width), lay["pad"], dtype=np.int64)
    mask = np.zeros((len(rows), width), dtype=np.int64)
    for k, r in enumerate(rows):
        ids[k, :len(r)] = r
        mask[k, :len(r)] = 1
    return ids, mask


Embedder._sp_encode = _sp_encode_impl


def timed_single(emb: Embedder, texts):
    out = []
    for t in texts:
        s = time.perf_counter()
        emb.embed([t])
        out.append((time.perf_counter() - s) * 1000)
    return out
