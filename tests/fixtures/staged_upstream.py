"""Disposable deterministic LLM: one marked response waits for a CI signal."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import time

SIGNALS=Path(os.environ['UTER_STAGED_SIGNALS'])


class Handler(BaseHTTPRequestHandler):
    def reply(self,value):
        raw=json.dumps(value).encode();self.send_response(200)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        self.end_headers();self.wfile.write(raw)

    def do_GET(self):self.reply({'status':'ok','data':[{'id':'test-model'}]})

    def do_POST(self):
        size=int(self.headers['Content-Length'])
        if not 0<=size<=1048576:raise ValueError
        raw=self.rfile.read(size)
        if len(raw)!=size:raise ValueError
        data=json.loads(raw)
        messages=json.dumps(data)
        if 'fixture-staged-drain' in messages:
            (SIGNALS/'entered').write_text('entered',encoding='ascii')
            deadline=time.monotonic()+55
            while not (SIGNALS/'release').exists():
                if time.monotonic()>=deadline:raise TimeoutError
                time.sleep(.05)
        text='Contact alice@example.com for help.' if 'fixture-output-pii' in messages else 'TechCorp offers software solutions.'
        self.reply({'id':'fixture-completion','object':'chat.completion','model':'test-model',
                    'choices':[{'index':0,'message':{'role':'assistant','content':text},'finish_reason':'stop'}]})

    def log_message(self,*args):pass


ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
