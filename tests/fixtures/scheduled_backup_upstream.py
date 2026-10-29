"""Disposable deterministic HTTP fixture; this is not a real LLM."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            self.reply(200, {'status': 'ok'})
        elif self.path == '/v1/models':
            self.reply(200, {'data': [{'id': 'test-model'}]})
        else:
            self.reply(404, {'error': 'not found'})

    def do_POST(self):
        if self.path != '/v1/chat/completions':
            self.reply(404, {'error': 'not found'})
            return
        try:
            size = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= size <= 1024 * 1024:
                raise ValueError('invalid size')
            data = json.loads(self.rfile.read(size))
            if data.get('model') != 'test-model':
                raise ValueError('invalid model')
        except (TypeError, ValueError):
            self.reply(400, {'error': 'invalid request'})
            return
        self.reply(200, {'id': 'fixture', 'object': 'chat.completion', 'model': 'test-model',
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
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
