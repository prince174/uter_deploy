"""One streaming HTTP request for the disposable proxy drain experiment."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
import time


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length','3')
        self.end_headers()
        self.wfile.write(b'A');self.wfile.flush()
        deadline=time.monotonic()+15
        while not Path(sys.argv[2]).exists():
            if time.monotonic()>=deadline:raise TimeoutError
            time.sleep(.05)
        self.wfile.write(b'BC');self.wfile.flush()

    def log_message(self, *_):
        pass


def server():
    httpd=HTTPServer(('198.18.192.2',8000),Handler)
    print('READY',flush=True)
    httpd.serve_forever()


def client():
    connection=http.client.HTTPConnection('198.18.192.2',8080,timeout=15)
    connection.request('GET','/slow')
    response=connection.getresponse()
    if response.status!=200 or response.read(1)!=b'A':raise RuntimeError('first byte')
    print('STREAM',flush=True)
    if response.read()!=b'BC':raise RuntimeError('remaining bytes')
    print('COMPLETE',flush=True)
    connection.close()


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='server':server()
    elif sys.argv[1:]==['client']:client()
    else:raise SystemExit(2)
