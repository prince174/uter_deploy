"""Deterministic LLM protocol fixture; no claim of real LLM quality."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def reply(self, data):
        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply({"status": "ok", "data": [{"id": "test-model"}]})

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        messages = json.dumps(data)
        text = "Software solutions are available."
        if "fixture-output-pii" in messages:
            text = "Contact alice@example.com for help."
        self.reply({"id": "fixture-completion", "object": "chat.completion", "model": "test-model",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]})

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
