"""Experimental Compose-like Redis fence lifecycle on a disposable runner only.

This synthetic experiment is not an updater, fence proof, or recovery procedure.
Docker is intentionally restarted only on a fresh GitHub-hosted Linux VM.
"""
import json
import os
import re
import selectors
import signal
import subprocess
import time
import uuid
from scripts import experimental_netns_probe as common

REDIS = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
PYTHON = common.PYTHON
LABEL = 'io.uter-deploy.synthetic-compose-fence'
PASSWORD = common.OLD
CLIENT = common.OLD_CLIENT.replace("except (OSError,ConnectionError): pass", "except TimeoutError: raise\nexcept (OSError,ConnectionError): pass")

def docker(*args, timeout=common.TIMEOUT):
    return common.cmd(['docker', '--context', 'default', *args], timeout=timeout)

def cleanup(kind, ident, owner):
    if kind == 'volume':
        if not re.fullmatch(r'uter-synthetic-compose-fence-[0-9a-f]{32}', ident): raise RuntimeError('invalid volume')
        val = docker('volume', 'inspect', '--format', '{{index .Labels "'+LABEL+'"}}', ident)
        if val != owner: raise RuntimeError('volume ownership mismatch')
        docker('volume', 'rm', ident)
    else:
        if not re.fullmatch(r'[0-9a-f]{64}', ident): raise RuntimeError('invalid id')
        template = '{{.Id}} {{index .Config.Labels "'+LABEL+'"}}' if kind == 'container' else '{{.Id}} {{index .Labels "'+LABEL+'"}}'
        val = docker('inspect' if kind == 'container' else 'network', *([] if kind == 'container' else ['inspect']), '--format', template, ident)
        if val != ident+' '+owner: raise RuntimeError('resource ownership mismatch')
        docker('rm', '-f', ident) if kind == 'container' else docker('network', 'rm', ident)

def inspect(ident):
    # Explicit allowlist: no env or secret values are returned.
    fmt = '{"running":{{json .State.Running}},"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}},"error":{{json .State.Error}},"restart":{{json .HostConfig.RestartPolicy.Name}},"network":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}},"mode":{{json .HostConfig.NetworkMode}}}'
    return json.loads(docker('inspect', '--format', fmt, ident))

def assert_detached(state):
    if state.get('running') is not True or state.get('restart') != 'no' or state.get('network') or state.get('ports'):
        raise RuntimeError('Redis is not verifiably disconnected with restart disabled')

def main():
    common.guard(os.environ)
    if common.cmd(['docker', 'context', 'show']) != 'default': raise RuntimeError('nondefault context')
    details=json.loads(common.cmd(['docker','context','inspect','default']))
    if len(details)!=1 or details[0]['Endpoints']['docker']['Host'] != 'unix:///var/run/docker.sock':
        raise RuntimeError('unexpected Docker endpoint')
    owner=uuid.uuid4().hex
    net=None;volume=None;containers=[];process=None;uncertain=False
    try:
        uncertain=True
        net=docker('network','create','--label',f'{LABEL}={owner}','uter-synthetic-compose-fence-'+owner)
        if not re.fullmatch(r'[0-9a-f]{64}',net): raise RuntimeError('network ID invalid')
        uncertain=False
        volume='uter-synthetic-compose-fence-'+owner
        uncertain=True
        if docker('volume','create','--label',f'{LABEL}={owner}',volume)!=volume: raise RuntimeError('volume ID invalid')
        uncertain=False
        def start(*args):
            nonlocal uncertain
            uncertain=True
            ident=docker('run','-d','--label',f'{LABEL}={owner}',*args)
            if not re.fullmatch(r'[0-9a-f]{64}',ident): raise RuntimeError('container ID invalid')
            containers.append(ident);uncertain=False
            return ident
        init=start('--network','none','--user','0','--mount',f'type=volume,source={volume},target=/data',PYTHON,'python','-c','import os,time;os.chmod("/data",0o777);time.sleep(600)')
        for _ in range(50):
            try:
                if docker('exec',init,'python','-c','import os;print(oct(os.stat("/data").st_mode & 0o777))')=='0o777': break
            except RuntimeError: pass
            time.sleep(.1)
        else: raise RuntimeError('fixture volume not prepared')
        cleanup('container',init,owner);containers.remove(init)
        old=start('--network',net,'--network-alias','redis','--restart','unless-stopped','--mount',f'type=volume,source={volume},target=/data', REDIS,'redis-server','--bind','0.0.0.0','--requirepass',PASSWORD,'--appendonly','yes','--appendfsync','always','--save','')
        for _ in range(100):
            try:
                if docker('exec',old,'redis-cli','-a',PASSWORD,'PING')=='PONG': break
            except RuntimeError: pass
            time.sleep(.1)
        else: raise RuntimeError('Redis not ready')
        oldip=docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',old)
        process=subprocess.Popen(['sudo','-n','-u','nobody','python3','-u','-c',CLIENT,oldip], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
        if not selector.select(10) or process.stdout.readline().strip()!='READY': raise RuntimeError('old client fixture failed')
        docker('update','--restart=no',old)
        docker('network','disconnect',net,old)
        assert_detached(inspect(old))
        # Disconnect does not itself prove that Redis discarded established
        # sockets. Kill all normal clients after network disconnection, then
        # reconnect only in this synthetic test to probe the prior connection.
        killed=docker('exec',old,'redis-cli','-a',PASSWORD,'CLIENT','KILL','TYPE','normal','SKIPME','yes')
        if not killed.isdigit() or int(killed)<1: raise RuntimeError('old Redis connection was not killed')
        docker('network','connect','--alias','redis',net,old)
        newip=docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',old)
        if newip!=oldip: raise RuntimeError('old address changed; socket test inconclusive')
        if common.cmd(['sudo','-n','-u','nobody','python3','-c',
                       'import socket,sys;s=socket.create_connection((sys.argv[1],6379),timeout=3);s.close();print("REACHABLE")',oldip])!='REACHABLE':
            raise RuntimeError('reconnected network not reachable')
        process.stdin.write('check\n');process.stdin.flush()
        if not selector.select(10) or process.stdout.readline().strip()!='CLOSED': raise RuntimeError('old client stayed connected')
        if process.wait(timeout=5): raise RuntimeError('old client failed')
        process=None
        docker('network','disconnect',net,old)
        assert_detached(inspect(old))
        if docker('exec',old,'redis-cli','-a',PASSWORD,'GET','synthetic:old')!='1': raise RuntimeError('fenced data mismatch')
        if common.cmd(['sudo','-n','-u','nobody','python3','-c',common.PROBE,oldip])!='BLOCKED': raise RuntimeError('old network reachable')
        # Hosted VM only: restarting dockerd exercises uncertain/crash state.
        common.cmd(['sudo','-n','systemctl','restart','docker'],timeout=120)
        for _ in range(120):
            try:
                docker('info',timeout=5);break
            except (RuntimeError,subprocess.TimeoutExpired): time.sleep(.5)
        else: raise RuntimeError('Docker did not return')
        state=inspect(old)
        if state.get('restart') != 'no': raise RuntimeError('restart policy changed')
        if state.get('running'):
            assert_detached(state)
            # A live-restore configuration is safe only if still detached.
            docker('stop','-t','20',old,timeout=45)
        ended=inspect(old)
        if ended.get('running') is not False or ended.get('exit') != 0 or ended.get('oom') is not False or ended.get('error'):
            raise RuntimeError('old Redis did not stop gracefully')
        replacement=start('--network','none','--mount',f'type=volume,source={volume},target=/data',REDIS,'redis-server','--bind','127.0.0.1','--requirepass',PASSWORD,'--appendonly','yes','--appendfsync','always','--save','')
        for _ in range(100):
            try:
                if docker('exec',replacement,'redis-cli','-a',PASSWORD,'GET','synthetic:old')=='1': break
            except RuntimeError: pass
            time.sleep(.1)
        else: raise RuntimeError('AOF content not preserved on detached replacement')
        if common.cmd(['sudo','-n','-u','nobody','python3','-c',common.PROBE,oldip])!='BLOCKED': raise RuntimeError('replacement was reachable externally')
        docker('stop','-t','20',replacement,timeout=45)
        cleanup('container',replacement,owner);containers.remove(replacement)
        # Recovery here is synthetic: reconnect old container and verify preserved state.
        docker('start',old,timeout=45)
        for _ in range(100):
            try:
                if docker('exec',old,'redis-cli','-a',PASSWORD,'GET','synthetic:old')=='1': break
            except RuntimeError: pass
            time.sleep(.1)
        else: raise RuntimeError('old Redis recovery failed')
        # Endpoint connection may require explicit reconnection after a daemon restart.
        state=inspect(old)
        if not state.get('network'): docker('network','connect','--alias','redis',net,old)
        if not inspect(old).get('network'): raise RuntimeError('network recovery failed')
    finally:
        if process is not None:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=5)
        errors=[]
        for ident in reversed(containers):
            try: cleanup('container',ident,owner)
            except Exception: errors.append('container')
        if net:
            try: cleanup('network',net,owner)
            except Exception: errors.append('network')
        if volume:
            try: cleanup('volume',volume,owner)
            except Exception: errors.append('volume')
        if uncertain: errors.append('unknown resource')
        if errors: raise RuntimeError('synthetic cleanup unconfirmed: '+', '.join(errors))
    print('Synthetic disconnect, Docker restart, AOF replacement and recovery passed; no production fence established.')

if __name__=='__main__':
    try: main()
    except RuntimeError as exc: raise SystemExit('Synthetic Compose fence probe failed: '+str(exc))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as exc:
        raise SystemExit('Synthetic Compose fence probe failed: '+type(exc).__name__)
