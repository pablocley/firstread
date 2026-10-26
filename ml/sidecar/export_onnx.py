"""Export a mean-pooled embedder to ONNX (fp32) and quantise it (int8), with a sha256 manifest.

Usage: python3 -I export_onnx.py <embedder> <out_root>

Writes <out_root>/<embedder>/model-fp32.onnx, model-int8.onnx and manifest.json. The export uses
the torch.export-based exporter with eager attention; the script refuses to write the manifest
unless the fp32 graph matches torch within 1e-4 on the last hidden state for a short and a
truncated long input.
"""
import hashlib
import json
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from providers import EMBEDDERS, resolve, snapshot  # noqa: E402

name, root = sys.argv[1], sys.argv[2]
e = EMBEDDERS[name]
if e["kind"] != "meanpool":
    sys.exit(f"{name}: only mean-pooled transformer embedders are exported")
from transformers import AutoModel, AutoTokenizer  # noqa: E402

local = snapshot(resolve(name))
tok = AutoTokenizer.from_pretrained(local)
model = AutoModel.from_pretrained(local, dtype=torch.float32, attn_implementation="eager").eval()


class LastHidden(torch.nn.Module):
    def __init__(self, m):
        super().__init__()
        self.m = m

    def forward(self, input_ids, attention_mask):
        return self.m(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state


out = os.path.join(root, name)
os.makedirs(out, exist_ok=True)
fp32 = os.path.join(out, "model-fp32.onnx")
example = tok([e["template"].replace("{text}", "hallo wereld, dit is een voorbeeld met wat woorden")], return_tensors="pt")
b, s = torch.export.Dim("batch", max=64), torch.export.Dim("seq", max=8192)
torch.onnx.export(LastHidden(model), (example["input_ids"], example["attention_mask"]), fp32,
                  input_names=["input_ids", "attention_mask"], output_names=["last_hidden_state"],
                  dynamic_shapes={"input_ids": {0: b, 1: s}, "attention_mask": {0: b, 1: s}},
                  dynamo=True, external_data=False)

import onnxruntime as ort  # noqa: E402
from onnxruntime.quantization import QuantType, quantize_dynamic  # noqa: E402

sess = ort.InferenceSession(fp32, providers=["CPUExecutionProvider"])
for text in ["kort", "een langere zin om te testen of alles gelijk is " * 40]:
    enc = tok([e["template"].replace("{text}", text)], truncation=True, max_length=e["max_tokens"], return_tensors="np")
    got = sess.run(None, {"input_ids": enc["input_ids"].astype(np.int64),
                          "attention_mask": enc["attention_mask"].astype(np.int64)})[0]
    with torch.no_grad():
        want = model(input_ids=torch.from_numpy(enc["input_ids"]), attention_mask=torch.from_numpy(enc["attention_mask"])).last_hidden_state.numpy()
    diff = float(np.abs(got - want).max())
    print(f"parity {len(enc['input_ids'][0])} tokens: max abs diff {diff:.2e}")
    if diff > 1e-4:
        sys.exit("fp32 export does not match torch; manifest not written")

int8 = os.path.join(out, "model-int8.onnx")
quantize_dynamic(fp32, int8, weight_type=QuantType.QInt8)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


manifest = {"embedder": name, "hf": e["hf"], "revision": e["revision"], "pad_token": tok.pad_token,
            "tokenizer_sha256": sha(os.path.join(local, "tokenizer.json")),
            "exporter": f"torch {torch.__version__} torch.onnx.export(dynamo=True); onnxruntime {ort.__version__} quantize_dynamic QInt8",
            "files": {"fp32": {"file": "model-fp32.onnx", "sha256": sha(fp32), "bytes": os.path.getsize(fp32)},
                      "int8": {"file": "model-int8.onnx", "sha256": sha(int8), "bytes": os.path.getsize(int8)}}}
json.dump(manifest, open(os.path.join(out, "manifest.json"), "w"), indent=1)
print(json.dumps(manifest["files"]))
