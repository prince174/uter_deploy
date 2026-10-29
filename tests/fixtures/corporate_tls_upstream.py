"""Disposable deterministic HTTPS OpenAI-like fixture; this is not a real LLM."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl


class Fixture(BaseHTTPRequestHandler):
    def reply(self, code, value):
        body = json.dumps(value).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        value = self.headers.get('Authorization', '')
        return hmac.compare_digest(value, 'Bearer ' + self.server.fixture_token)

    def do_GET(self):
        if not self.authorized():
            self.reply(401, {'error': 'unauthorized'})
        elif self.path == '/health':
            self.reply(200, {'status': 'ok'})
        elif self.path == '/v1/models':
            self.reply(200, {'data': [{'id': 'fixture-model'}]})
        else:
            self.reply(404, {'error': 'not found'})

    def do_POST(self):
        if not self.authorized():
            self.reply(401, {'error': 'unauthorized'})
            return
        if self.path != '/v1/chat/completions':
            self.reply(404, {'error': 'not found'})
            return
        try:
            size = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= size <= 1024 * 1024:
                raise ValueError('invalid request size')
            payload = json.loads(self.rfile.read(size))
            if payload.get('model') != 'fixture-model':
                raise ValueError('invalid model')
        except (TypeError, ValueError):
            self.reply(400, {'error': 'invalid request'})
            return
        self.reply(200, {'id': 'fixture-completion', 'object': 'chat.completion',
                         'model': 'fixture-model',
                         'choices': [{'index': 0, 'message': {'role': 'assistant',
                                                             'content': 'A safe fixture response.'},
                                      'finish_reason': 'stop'}]})

    def log_message(self, *args):
        pass


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Disposable GitHub-hosted runner required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--token-file', required=True, type=Path)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Fixture)
    server.fixture_token = args.token_file.read_text(encoding='utf-8').strip()
    if not server.fixture_token:
        raise ValueError('Empty fixture token')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
