"""Disposable network-namespace test fixture; not shipped in a release."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        body=b'fixture-ok'
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, *_):
        pass


def server():
    httpd=HTTPServer(('198.18.192.2',8000),Handler)
    print('READY',flush=True)
    httpd.serve_forever()


def client():
    connection=http.client.HTTPConnection('198.18.192.2',8000,timeout=5)
    connection.request('GET','/first')
    response=connection.getresponse()
    if response.status!=200 or response.read()!=b'fixture-ok':raise RuntimeError('first')
    local_port=connection.sock.getsockname()[1]
    print('FIRST',flush=True)
    if sys.stdin.readline()!='next\n':raise RuntimeError('signal')
    connection.request('GET','/second')
    response=connection.getresponse()
    if (response.status!=200 or response.read()!=b'fixture-ok' or connection.sock is None
            or connection.sock.getsockname()[1]!=local_port):raise RuntimeError('second')
    print('SECOND',flush=True)
    connection.close()


if __name__=='__main__':
    if sys.argv[1:] == ['server']:server()
    elif sys.argv[1:] == ['client']:client()
    else:raise SystemExit(2)
