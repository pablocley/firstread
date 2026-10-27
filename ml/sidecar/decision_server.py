"""The tier-2 sidecar: a JEV-style decision model behind the provider contract (docs/14-providers.md).

Usage: python3 -I decision_server.py --socket PATH --model-dir DIR --release ID
                                     [--licence NAME --commercial-use yes|no] [--max-input-tokens N]
                                     [--threads N]

DIR holds a JEV-style model with its own `jev_style_decision.JevStyleDecision` (as published with
chaoliangUNSW/Jev-Style-0.8B-Decision-v3, docs/04-models.md; the same interface ml/bench/bench_jev08.py
measured). --release names the model and its revision; it is what calibrations are fitted for.

Speaks the frames of `firstread-core::wire` like server.py, and declares "*": it reads each
question's text, so it can be asked any question, including the rules people write in words:
  {"op": "manifest"} -> release, licence, commercial_use, supported ["*"], max_input_tokens
  {"op": "logits", "text": ..., "questions": [ids], "specs": [{"id", "text", "kind", "outcomes"}]}
      -> {"logits": [[...], ...]} in each question's outcome order
The model's raw scores are returned as logits: per outcome, logit(" yes") - logit(" no") at that
outcome's readout token, before the model's own temperature (its readout_config.json). The daemon's
calibration, fitted in the lab, turns them into decisions. The model directory is checked against its
own sha256 manifest at load (verify=True). Not measured on our mail: the model
card is a claim, and a calibration fitted in the lab comes first (no calibration, no decision).
Never called in the delivery path: firstreadd asks it from its queue after delivery.
"""
import argparse
import json
import os
import socket
import struct
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--socket", required=True)
ap.add_argument("--model-dir", required=True)
ap.add_argument("--release", required=True)
ap.add_argument("--licence", default="Apache-2.0")
ap.add_argument("--commercial-use", choices=["yes", "no"], default="yes")
ap.add_argument("--max-input-tokens", type=int, default=4096)
ap.add_argument("--threads", type=int, default=0)
a = ap.parse_args()

def logits_of(spec, scores):
    """Raw scores in the question's outcome order. The model names noul outcomes "false" / "true",
    choice outcomes by option and score levels "0".."k-1" (option_names in its runtime)."""
    names = ["false", "true"] if spec["kind"] == "noul" else spec["outcomes"]
    keys = names if spec["kind"] != "score" else [str(i) for i in range(len(names))]
    missing = [k for k in keys if k not in scores]
    if missing:
        raise ValueError(f"{spec['id']}: the model returned no score for {missing}")
    return [float(scores[k]) for k in keys]


def question_of(spec):
    """The question in the form JevStyleDecision.decide_many takes (bench_jev08.py)."""
    if spec["kind"] == "noul":
        return {"t": "noul", "ins": spec["text"], "crit": None}
    if spec["kind"] == "choice":
        return {"t": "choice", "ins": spec["text"], "crit": {o: o.replace("_", " ") for o in spec["outcomes"]}}
    return {"t": "score", "ins": spec["text"], "crit": list(spec["outcomes"])}


def recv_exact(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def main():
    sys.path.insert(0, a.model_dir)
    import torch
    if a.threads:
        torch.set_num_threads(a.threads)
    from jev_style_decision import JevStyleDecision
    model = JevStyleDecision(a.model_dir, device="cpu", dtype="float32", verify=True)

    def handle(req):
        if req["op"] == "manifest":
            return {"release": a.release, "licence": a.licence, "commercial_use": a.commercial_use == "yes",
                    "languages": [], "max_input_tokens": a.max_input_tokens, "supported": ["*"]}
        if req["op"] == "logits":
            specs = req.get("specs") or []
            if [s["id"] for s in specs] != list(req["questions"]):
                return {"error": "specs must name the questions, in order"}
            out = model.decide_many(req["text"], [question_of(s) for s in specs])
            return {"logits": [logits_of(s, r["scores"]) for s, r in zip(specs, out)]}
        return {"error": "unknown op"}

    if os.path.exists(a.socket):
        os.unlink(a.socket)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(a.socket)
    srv.listen(4)
    print(f"decision sidecar: {a.release} on {a.socket}", flush=True)
    while True:
        c, _ = srv.accept()
        try:
            n = struct.unpack(">I", recv_exact(c, 4))[0]
            body = json.dumps(handle(json.loads(recv_exact(c, n)))).encode()
            c.sendall(struct.pack(">I", len(body)) + body)
        except Exception as e:  # one bad request never takes the sidecar down
            print(f"decision sidecar: {e}", file=sys.stderr, flush=True)
        finally:
            c.close()


if __name__ == "__main__":
    main()
