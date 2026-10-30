"""Synthetic Kubernetes Redis shutdown/loopback experiment; NOT an updater.

Only runs on disposable GitHub-hosted runners with an isolated kind cluster.
No result from this experiment is accepted as an installation fence or proof.
"""
import json
import os
import re
import selectors
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from scripts import experimental_netns_probe as safe

REDIS = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
PYTHON = 'python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
NODE = 'kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0'
PASS = 'synthetic-only-password'
LABEL = 'app=synthetic-redis'
OLD_CLIENT = r'''
import socket,sys
s=socket.create_connection(('synthetic-redis',6379),timeout=10);s.settimeout(10)
def req(*xs):
 b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
 s.sendall(b);return s.recv(1024)
assert req('AUTH','synthetic-only-password').startswith(b'+OK')
assert req('SET','synthetic:pre-fence','before').startswith(b'+OK')
print('READY',flush=True);sys.stdin.readline()
try:
 r=req('SET','synthetic:pre-fence','after')
 if r: raise RuntimeError('old socket accepted data')
except (ConnectionError, OSError): pass
print('CLOSED',flush=True)
'''
EXTERNAL = r'''
import socket,sys
try:
 s=socket.create_connection((sys.argv[1],6379),timeout=3)
 s.close();raise SystemExit(1)
except (ConnectionRefusedError,TimeoutError,socket.timeout):print('BLOCKED')
'''


def command(argv, *, env, data=None, timeout=180):
    p = subprocess.run(argv, input=data, env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=timeout)
    if p.returncode:
        raise RuntimeError('synthetic command failed: ' + str(argv[0]))
    return p.stdout.decode('utf-8').strip()


def marker_valid(marker, old_uid):
    """Only a synthetic fixture assertion, never a real-world proof."""
    return bool(re.fullmatch(r'[a-z0-9-]{1,64}', old_uid) and marker == old_uid)


def deployment(hanging=False, bind='0.0.0.0'):
    # UIDs are synthetic and the markers are not authenticated. The deliberate
    # hang models a failed graceful termination, not a safe recovery protocol.
    prestop = 'sleep 30' if hanging else (
        'redis-cli -a "$SYNTHETIC_PASSWORD" --no-auth-warning shutdown save && '
        'printf "%s" "$POD_UID" > "/data/marker-$POD_UID"')
    return {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'synthetic-redis'},
            'spec':{'replicas':1,'strategy':{'type':'Recreate'},
                    'selector':{'matchLabels':{'app':'synthetic-redis'}},
                    'template':{'metadata':{'labels':{'app':'synthetic-redis'}},
                      'spec':{'automountServiceAccountToken':False, 'terminationGracePeriodSeconds':5 if hanging else 30,
                              'securityContext':{'fsGroup':1000},
                              'containers':[{'name':'redis','image':REDIS,
                                 'command':['redis-server'],
                                 'args':['--appendonly','yes','--appendfsync','always','--dir','/data',
                                         '--bind',bind,'--requirepass',PASS],
                                 'env':[{'name':'SYNTHETIC_PASSWORD','value':PASS},
                                        {'name':'POD_UID','valueFrom':{'fieldRef':{'fieldPath':'metadata.uid'}}}],
                                 'lifecycle':{'preStop':{'exec':{'command':['sh','-ec',prestop]}}},
                                 'readinessProbe':{'exec':{'command':['sh','-ec',
                                      'REDISCLI_AUTH="$SYNTHETIC_PASSWORD" redis-cli -h 127.0.0.1 ping | grep -q PONG']},
                                      'periodSeconds':2},
                                 'volumeMounts':[{'name':'data','mountPath':'/data'}]}],
                              'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'synthetic-data'}}]}}}}


def main():
    safe.guard(os.environ)
    if safe.cmd(['docker', 'context', 'show']) != 'default':
        raise RuntimeError('nondefault Docker context')
    details=json.loads(safe.cmd(['docker','context','inspect','default']))
    if len(details)!=1 or details[0]['Endpoints']['docker']['Host']!='unix:///var/run/docker.sock':
        raise RuntimeError('Docker context must use local socket')
    cluster='uter-kf-'+uuid.uuid4().hex[:12]
    namespace='synthetic-'+uuid.uuid4().hex[:12]
    attempted=False
    proc=None
    with tempfile.TemporaryDirectory(prefix='uter-kube-fence-ci-') as tmp:
        env=os.environ.copy();env['KUBECONFIG']=str(Path(tmp)/'kubeconfig')
        env.pop('DOCKER_HOST',None);env['DOCKER_CONTEXT']='default'
        kube=['kubectl','--context','kind-'+cluster,'-n',namespace]
        def call(*args, data=None, timeout=180):
            return command([str(x) for x in args],env=env,data=data,timeout=timeout)
        def k(*args, data=None, timeout=180): return call(*(kube+list(args)),data=data,timeout=timeout)
        def apply(obj): k('apply','-f','-',data=json.dumps(obj).encode())
        def ready(): k('rollout','status','deployment/synthetic-redis','--timeout=180s')
        def current():
            pods=json.loads(k('get','pods','-l',LABEL,'-o','json'))['items']
            active=[p for p in pods if not p['metadata'].get('deletionTimestamp')]
            if len(active)!=1 or active[0].get('status',{}).get('phase')!='Running':
                raise RuntimeError('unexpected synthetic Redis pods')
            p=active[0]
            return p['metadata']['name'],p['metadata']['uid'],p['status']['podIP']
        def redis(pod,*args):
            return k('exec',pod,'-c','redis','--','redis-cli','-a',PASS,'--no-auth-warning','--raw',*args)
        def marker(pod, uid):
            if not re.fullmatch(r'[a-z0-9-]{1,64}',uid): raise RuntimeError('invalid synthetic UID')
            return k('exec',pod,'-c','redis','--','sh','-ec',
                     'p="/data/marker-$1"; if [ -f "$p" ]; then cat "$p"; else printf missing; fi',
                     'sh',uid)
        def set_template(hanging,bind):
            desired=deployment(hanging,bind)['spec']['template']
            for _ in range(5):
                obj=json.loads(k('get','deployment/synthetic-redis','-o','json'))
                ops=[{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
                     {'op':'replace','path':'/spec/template','value':desired}]
                try:
                    k('patch','deployment/synthetic-redis','--type=json','-p',json.dumps(ops))
                    return
                except RuntimeError: time.sleep(.3)
            raise RuntimeError('synthetic deployment patch failed')
        def external_blocked(ip):
            if k('exec','client','--','python','-c',EXTERNAL,ip)!='BLOCKED':
                raise RuntimeError('synthetic Redis was externally reachable')
        try:
            if cluster in call('kind','get','clusters').splitlines():
                raise RuntimeError('synthetic cluster name already exists')
            attempted=True
            call('kind','create','cluster','--name',cluster,'--image',NODE,'--wait','180s',timeout=300)
            call('kubectl','--context','kind-'+cluster,'create','namespace',namespace)
            apply({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'synthetic-data'},
                   'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'32Mi'}}}})
            apply(deployment())
            apply({'apiVersion':'v1','kind':'Service','metadata':{'name':'synthetic-redis'},
                   'spec':{'selector':{'app':'synthetic-redis'},'ports':[{'port':6379}]}})
            apply({'apiVersion':'v1','kind':'Pod','metadata':{'name':'client'},
                   'spec':{'automountServiceAccountToken':False,'containers':[{'name':'client','image':PYTHON,
                           'command':['python','-c','import time;time.sleep(900)']}]}})
            ready();k('wait','--for=condition=Ready','pod/client','--timeout=180s')
            old,old_uid,_=current()
            proc=subprocess.Popen(kube+['exec','-i','client','--','python','-u','-c',OLD_CLIENT],
                                  env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
            if not selector.select(20) or proc.stdout.readline().strip()!='READY':
                raise RuntimeError('synthetic established connection failed')
            set_template(False,'127.0.0.1');ready()
            new,new_uid,ip=current()
            if new_uid==old_uid or old in [p['metadata']['name'] for p in json.loads(k('get','pods','-l',LABEL,'-o','json'))['items']]:
                raise RuntimeError('old synthetic pod still exists')
            proc.stdin.write('check\n');proc.stdin.flush()
            if not selector.select(20) or proc.stdout.readline().strip()!='CLOSED' or proc.wait(timeout=5):
                raise RuntimeError('old synthetic connection did not close')
            proc=None
            if not marker_valid(marker(new,old_uid),old_uid): raise RuntimeError('synthetic shutdown marker missing')
            if redis(new,'CONFIG','GET','bind')!='bind\n127.0.0.1' or redis(new,'GET','synthetic:pre-fence')!='before':
                raise RuntimeError('synthetic AOF state or bind mismatch')
            external_blocked(ip)
            k('rollout','restart','deployment/synthetic-redis');ready()
            restarted,restarted_uid,ip=current()
            if restarted_uid==new_uid or redis(restarted,'GET','synthetic:pre-fence')!='before':
                raise RuntimeError('synthetic fenced restart failed')
            external_blocked(ip)
            set_template(False,'0.0.0.0');ready()
            restored,_,_=current()
            if redis(restored,'GET','synthetic:pre-fence')!='before': raise RuntimeError('synthetic rollback lost data')
            # Introduce an intentionally hanging synthetic preStop, then trigger a
            # rollout: lack of a marker is a mandatory failure, not an isolation proof.
            set_template(True,'0.0.0.0');ready();hung,hung_uid,_=current()
            set_template(False,'127.0.0.1');ready();after,_,_=current()
            if marker_valid(marker(after,hung_uid),hung_uid):
                raise RuntimeError('synthetic hung shutdown incorrectly accepted')
        finally:
            if proc is not None:
                proc.kill();proc.wait(timeout=10)
            if attempted:
                # Unique cluster had been verified absent; only this named cluster
                # and its private kubeconfig are touched, never another context.
                try: call('kind','delete','cluster','--name',cluster,timeout=180)
                except Exception: raise RuntimeError('synthetic cluster cleanup unconfirmed') from None
    print('Synthetic Kubernetes loopback/AOF lifecycle and hung-shutdown rejection passed; cluster cleanup confirmed.')


if __name__=='__main__':
    try: main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit('Synthetic Kubernetes fence experiment failed: '+type(error).__name__)
