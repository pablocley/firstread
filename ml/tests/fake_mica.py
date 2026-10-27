"""A stand-in for Mica's server (akivet/Mica, POST /v1/systemone) for the sidecar tests.

`answer(text, question)` gives a dict in Mica's typed result shape; every request is checked against
Mica's request format and kept in `requests`.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_QUESTIONS = 16


def serve(answer):
    requests = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == "/v1/systemone", self.path
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert set(body) == {"state", "questions"} and isinstance(body["state"], str)
            assert 1 <= len(body["questions"]) <= MAX_QUESTIONS
            for q in body["questions"].values():
                assert q["type"] in ("noul", "choice", "score") and q["instructions"]
            requests.append(body)
            out = json.dumps({"model": "mica-v0.5-4b", "answers": {
                k: answer(body["state"], q) for k, q in body["questions"].items()}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", requests


def typed(q, p_true=None, pick=None, level=None):
    if q["type"] == "noul":
        return {"type": "noul", "noul": p_true}
    if q["type"] == "choice":
        ids = list(q["criteria"])
        return {"type": "choice", "probabilities": {i: (0.8 if i == pick else 0.2 / (len(ids) - 1)) for i in ids}}
    n = len(q["criteria"])
    return {"type": "score", "probabilities": {str(i): (1.0 if i == level else 0.0) for i in range(n)}}
