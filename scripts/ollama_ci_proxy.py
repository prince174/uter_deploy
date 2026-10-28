"""CI-only forwarding proxy: count real Ollama responses without recording prompts."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import urllib.error
import urllib.request

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Disposable GitHub-hosted runner required')

stats = {'successful_completions': 0, 'completion_tokens': 0}


class Handler(BaseHTTPRequestHandler):
    def relay(self):
        if self.path == '/stats' and self.command == 'GET':
            data = json.dumps(stats).encode(); self.send_response(200)
        else:
            allowed = {('GET', '/health'), ('GET', '/v1/models'), ('POST', '/v1/chat/completions')}
            if (self.command, self.path) not in allowed:
                self.send_error(404); return
            size = int(self.headers.get('Content-Length', 0))
            if size > 1024 * 1024:
                self.send_error(413); return
            body = self.rfile.read(size) if size else None
            req = urllib.request.Request('http://127.0.0.1:11434' + self.path, data=body,
                                         headers={'Content-Type': 'application/json'}, method=self.command)
            try:
                with urllib.request.urlopen(req, timeout=120) as upstream:
                    data=upstream.read(); self.send_response(upstream.status)
                    if self.command == 'POST' and upstream.status == 200:
                        result=json.loads(data); content=result['choices'][0]['message']['content']
                        if content and content.strip():
                            stats['successful_completions'] += 1
                            stats['completion_tokens'] += result.get('usage', {}).get('completion_tokens', 0)
            except urllib.error.HTTPError as error:
                self.send_response(error.code); data=b'{}'
        self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data)))
        self.end_headers(); self.wfile.write(data)

    do_GET = relay
    do_POST = relay

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0',11435),Handler).serve_forever()
