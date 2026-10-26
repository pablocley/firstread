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

ONNX models are exported once by `export_onnx.py` into `$FIRSTREAD_ONNX_DIR/<embedder>/` with a
sha256 manifest, which is checked at load.
"""

import hashlib
import json
import os
import sqlite3
import time

import numpy as np

EMBEDDERS = {
    "potion-ml-128m": {"hf": "minishlab/potion-multilingual-128M", "kind": "model2vec",
                        "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 0,
                        "runtimes": {"numpy": ["fp32"]}},
    "e5-small": {"hf": "intfloat/multilingual-e5-small", "kind": "meanpool",
                  "licence": "MIT", "commercial_use": True, "template": "query: {text}", "max_tokens": 256,
                  "runtimes": {"torch": ["fp32", "int8"], "onnx": ["fp32", "int8"]}},
    # No onnx runtime: its export differed from torch by up to 3e-3 on the last hidden state
    # (export_onnx.py refuses above 1e-4), 2026-10-26.
    "mmbert-small": {"hf": "jhu-clsp/mmBERT-small", "kind": "meanpool",
                      "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 256,
                      "runtimes": {"torch": ["fp32", "int8"]}},
    "harrier-270m": {"hf": "microsoft/harrier-oss-v1-270m", "kind": "sentence_transformers",
                      "licence": "MIT", "commercial_use": True, "template": "{text}", "max_tokens": 256,
                      "runtimes": {"torch": ["fp32", "int8"]}},
}


def resolve(name, runtime=None, precision=None, max_tokens=None, threads=None):
    """The full configuration of one embedder; unset fields take the registry defaults."""
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
    e.update(name=name, runtime=runtime, precision=precision, threads=int(threads or os.cpu_count() or 1))
    return e


def space_id(cfg, render_version):
    return (f"{cfg['name']}|{cfg['template'].replace('{text}', 'T')}|{cfg['max_tokens']}|"
            f"{cfg['runtime']}-{cfg['precision']}|render:{render_version}")


def config_args(cfg):
    """Command-line flags that recreate `cfg` in server.py, embed_batch.py and latency.py."""
    return ["--embedder", cfg["name"], "--runtime", cfg["runtime"], "--precision", cfg["precision"],
            "--max-tokens", str(cfg["max_tokens"]), "--threads", str(cfg["threads"])]


def add_config_args(ap):
    ap.add_argument("--embedder", required=True)
    ap.add_argument("--runtime")
    ap.add_argument("--precision")
    ap.add_argument("--max-tokens", type=int, default=0)
    ap.add_argument("--threads", type=int, default=0)


def from_args(a):
    return resolve(a.embedder, a.runtime, a.precision, a.max_tokens or None, a.threads or None)


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


def _normalise(v):
    n = np.linalg.norm(v, axis=1, keepdims=True)
    return (v / np.maximum(n, 1e-12)).astype(np.float32)


class Embedder:
    def __init__(self, cfg):
        self.cfg = cfg
        kind, runtime = cfg["kind"], cfg["runtime"]
        if kind == "model2vec":
            from model2vec import StaticModel
            self.model = StaticModel.from_pretrained(cfg["hf"])
            return
        if runtime == "onnx":
            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer
            path, manifest = onnx_path(cfg["name"], cfg["precision"])
            tok_path = hf_hub_download(cfg["hf"], "tokenizer.json")
            if _sha256(tok_path) != manifest["tokenizer_sha256"]:
                raise RuntimeError(f"{tok_path}: tokenizer differs from the one exported with the model")
            self.tok = Tokenizer.from_file(tok_path)
            self.tok.enable_truncation(cfg["max_tokens"])
            pad = self.tok.token_to_id(manifest["pad_token"])
            self.tok.enable_padding(pad_id=pad, pad_token=manifest["pad_token"])
            so = ort.SessionOptions()
            so.intra_op_num_threads = cfg["threads"]
            so.inter_op_num_threads = 1
            self.sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
            return
        import torch
        torch.set_num_threads(cfg["threads"])
        if kind == "sentence_transformers":
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(cfg["hf"], device="cpu", model_kwargs={"dtype": torch.float32})
            self.model.max_seq_length = cfg["max_tokens"]
            if cfg["precision"] == "int8":
                self.model[0].auto_model = torch.ao.quantization.quantize_dynamic(
                    self.model[0].auto_model, {torch.nn.Linear}, dtype=torch.qint8)
        else:
            from transformers import AutoModel, AutoTokenizer
            self.tok = AutoTokenizer.from_pretrained(cfg["hf"])
            self.model = AutoModel.from_pretrained(cfg["hf"], dtype=torch.float32).eval()
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


def timed_single(emb: Embedder, texts):
    out = []
    for t in texts:
        s = time.perf_counter()
        emb.embed([t])
        out.append((time.perf_counter() - s) * 1000)
    return out
