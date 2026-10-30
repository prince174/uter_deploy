"""Disposable synthetic-only GitHub-hosted Docker netns experiment; not an updater."""
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid

REDIS = 'redis:7.4.2-alpine@sha256:02419de7eddf55aa5bcf49efb74e88fa8d931b4d77c07eff8a6b2144472b6952'
PYTHON = 'python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
LABEL = 'io.uter-deploy.synthetic-netns'
OLD, NEW = 'synthetic-old-only', 'synthetic-new-only'
TIMEOUT = 40


def guard(env):
    if (env.get('GITHUB_ACTIONS') != 'true' or env.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or env.get('RUNNER_OS') != 'Linux' or env.get('DOCKER_HOST')
            or env.get('DOCKER_CONTEXT', 'default') not in ('', 'default')):
        raise RuntimeError('requires disposable GitHub-hosted Linux runner, default Docker context')


def cmd(args, data=None, timeout=TIMEOUT):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError('synthetic command failed: ' + args[0])
    return result.stdout.decode().strip()


def docker(*args):
    return cmd(['docker', '--context', 'default', *args])


def safe_cleanup(kind, ident, owner):
    if not re.fullmatch(r'[0-9a-f]{64}', ident):
        raise RuntimeError('invalid resource id')
    template = '{{.Id}} {{index .Config.Labels "' + LABEL + '"}}' if kind == 'container' else '{{.Id}} {{index .Labels "' + LABEL + '"}}'
    value = docker('inspect' if kind == 'container' else 'network', *([] if kind == 'container' else ['inspect']), '--format', template, ident)
    if value != ident + ' ' + owner:
        raise RuntimeError('resource ownership verification failed')
    docker('rm', '-f', ident) if kind == 'container' else docker('network', 'rm', ident)


# A long-lived unprivileged host process demonstrates that the old connection breaks.
OLD_CLIENT = r'''
import socket,sys
s=socket.create_connection((sys.argv[1],6379),timeout=3)
s.settimeout(3)
def req(*items):
 b=b'*%d\r\n'%len(items)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in items)
 s.sendall(b); return s.recv(1024)
assert req('AUTH','synthetic-old-only').startswith(b'+OK')
assert req('SET','synthetic:old','1').startswith(b'+OK')
print('READY',flush=True)
sys.stdin.readline()
try:
 r=req('SET','synthetic:old','2')
 assert r == b''
except (OSError,ConnectionError): pass
print('CLOSED',flush=True)
'''
# Real, minimal HTTP probe: guardrail calls new loopback Redis and separate LLM.
GUARD = r'''
import http.server,socket,urllib.request
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_GET(self):
  try:
   s=socket.create_connection(('127.0.0.1',6379),timeout=3);s.settimeout(3)
   def r(*xs):
    b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
    s.sendall(b);return s.recv(1024)
   assert r('AUTH','synthetic-new-only').startswith(b'+OK')
   assert r('SET','synthetic:new','1').startswith(b'+OK')
   assert urllib.request.urlopen('http://llm:8080',timeout=3).read()==b'llm-ok'
   self.send_response(200);self.end_headers();self.wfile.write(b'guard-ok')
  except Exception:
   self.send_response(503);self.end_headers()
http.server.HTTPServer(('0.0.0.0',8000),H).serve_forever()
'''
LLM = r'''
import http.server
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'llm-ok')
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
'''
PROBE = r'''
import socket,sys
for pwd in ('synthetic-old-only','synthetic-new-only'):
 try:
  s=socket.create_connection((sys.argv[1],6379),timeout=2);s.settimeout(2)
  def r(*xs):
   b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
   s.sendall(b);return s.recv(1024)
  if r('AUTH',pwd).startswith(b'+OK') and r('SET','synthetic:attacker','1').startswith(b'+OK'):
   raise SystemExit(1)
  # A reachable Redis is a failed isolation, even if authentication fails.
  raise SystemExit(2)
 except (ConnectionRefusedError,TimeoutError,socket.timeout):pass
print('BLOCKED')
'''
AGENT = "import urllib.request; assert urllib.request.urlopen('http://guardrail:8000',timeout=5).read()==b'guard-ok'; print('CHAIN_OK')"


def main():
    guard(os.environ)
    if cmd(['docker', 'context', 'show']) != 'default':
        raise RuntimeError('nondefault context')
    # Refuse remote daemon masquerading as default context.
    details = json.loads(cmd(['docker', 'context', 'inspect', 'default']))
    if len(details) != 1 or details[0]['Endpoints']['docker']['Host'] != 'unix:///var/run/docker.sock':
        raise RuntimeError('default context must use local Linux socket')
    owner = uuid.uuid4().hex
    net = None
    containers = []
    process = None
    uncertain_resource = False
    try:
        try:
            net = docker('network', 'create', '--label', f'{LABEL}={owner}', 'uter-synthetic-netns-' + owner)
        except (RuntimeError, subprocess.TimeoutExpired):
            uncertain_resource = True
            raise
        if not re.fullmatch(r'[0-9a-f]{64}', net):
            uncertain_resource = True
            raise RuntimeError('unexpected network identifier')
        def start(*args):
            nonlocal uncertain_resource
            try:
                ident = docker('run', '-d', '--label', f'{LABEL}={owner}', *args)
            except (RuntimeError, subprocess.TimeoutExpired):
                uncertain_resource = True
                raise
            if not re.fullmatch(r'[0-9a-f]{64}', ident):
                uncertain_resource = True
                raise RuntimeError('unexpected container identifier')
            containers.append(ident)
            return ident
        def ip(ident):
            return docker('inspect', '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', ident)
        old = start('--network', net, '--tmpfs', '/data', REDIS, 'redis-server', '--bind', '0.0.0.0', '--requirepass', OLD, '--save', '', '--appendonly', 'no')
        for _ in range(100):
            try:
                if docker('exec', old, 'redis-cli', '-a', OLD, 'PING') == 'PONG': break
            except RuntimeError: pass
            time.sleep(.1)
        else: raise RuntimeError('old synthetic Redis not ready')
        process = subprocess.Popen(['sudo', '-n', '-u', 'nobody', 'python3', '-u', '-c', OLD_CLIENT, ip(old)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        # A bounded select avoids an unattended hang if the fixture fails.
        import selectors
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(10) or process.stdout.readline().strip() != 'READY':
            raise RuntimeError('unprivileged old socket fixture did not start')
        # The old instance is synthetic, without persistence; stop it to break all old sockets.
        docker('stop', '-t', '5', old)
        if docker('inspect', '--format', '{{.State.Running}}', old) != 'false':
            raise RuntimeError('old Redis is still running')
        process.stdin.write('check\n'); process.stdin.flush()
        if not selector.select(10) or process.stdout.readline().strip() != 'CLOSED':
            raise RuntimeError('old connection remained usable')
        if process.wait(timeout=5): raise RuntimeError('old client failed')
        process = None
        safe_cleanup('container', old, owner); containers.remove(old)
        llm = start('--network', net, '--network-alias', 'llm', PYTHON, 'python', '-u', '-c', LLM)
        new = start('--network', net, '--network-alias', 'guardrail', '--tmpfs', '/data', REDIS, 'redis-server', '--bind', '127.0.0.1', '--requirepass', NEW, '--save', '', '--appendonly', 'no')
        guardrail = start('--network', 'container:' + new, PYTHON, 'python', '-u', '-c', GUARD)
        if json.loads(docker('inspect', '--format', '{{json .HostConfig.PortBindings}}', new)):
            raise RuntimeError('Redis unexpectedly publishes host ports')
        if docker('inspect', '--format', '{{.HostConfig.NetworkMode}}', guardrail) != 'container:' + new:
            raise RuntimeError('probe does not share the Redis network namespace')
        for _ in range(100):
            try:
                output = docker('exec', guardrail, 'python', '-c', AGENT.replace('http://guardrail:8000','http://127.0.0.1:8000'))
                if output == 'CHAIN_OK': break
            except RuntimeError: pass
            time.sleep(.2)
        else: raise RuntimeError('guardrail Redis/LLM chain failed')
        if docker('exec', new, 'redis-cli', '-a', NEW, '--raw', 'CONFIG', 'GET', 'bind') != 'bind\n127.0.0.1':
            raise RuntimeError('Redis bind is not restricted to IPv4 loopback')
        new_ip = ip(new)
        if cmd(['sudo', '-n', '-u', 'nobody', 'python3', '-c', PROBE, new_ip]) != 'BLOCKED':
            raise RuntimeError('unprivileged host reached new Redis')
        outsider = start('--network', net, PYTHON, 'python', '-c', 'import time; time.sleep(600)')
        if docker('exec', outsider, 'python', '-c', PROBE, new_ip) != 'BLOCKED':
            raise RuntimeError('external container reached new Redis')
        if docker('exec', outsider, 'python', '-c', AGENT) != 'CHAIN_OK':
            raise RuntimeError('agent to guardrail to Redis and LLM failed')
        # Check independently that the requested synthetic write was made by the guardrail probe.
        if docker('exec', new, 'redis-cli', '-a', NEW, 'GET', 'synthetic:new') != '1':
            raise RuntimeError('guardrail did not write to Redis')
        if docker('exec', new, 'redis-cli', '-a', NEW, 'EXISTS', 'synthetic:attacker') != '0':
            raise RuntimeError('external synthetic write succeeded')
    finally:
        if process is not None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=5)
        cleanup_errors = []
        for ident in reversed(containers):
            try: safe_cleanup('container', ident, owner)
            except Exception: cleanup_errors.append('container')
        if net and re.fullmatch(r'[0-9a-f]{64}', net):
            try: safe_cleanup('network', net, owner)
            except Exception: cleanup_errors.append('network')
        if uncertain_resource:
            cleanup_errors.append('unknown resource after Docker error')
        if cleanup_errors:
            raise RuntimeError('synthetic cleanup unconfirmed: ' + ', '.join(cleanup_errors))
    print('Synthetic netns test passed: old socket closed, external writes blocked, agent/guardrail/Redis/LLM chain works; cleanup verified.')


if __name__ == '__main__':
    try: main()
    except RuntimeError as exc:
        raise SystemExit('Synthetic netns experiment failed: ' + str(exc))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise SystemExit('Synthetic netns experiment failed: ' + type(exc).__name__)
