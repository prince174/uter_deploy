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
PHASE = 'initialization'
OLD_CLIENT = r'''
import socket,sys,time
for attempt in range(40):
 try:
  s=socket.create_connection((sys.argv[1],6379),timeout=2);break
 except (OSError,TimeoutError):time.sleep(.25)
else:raise SystemExit('FIXTURE_CONNECTION_FAILED')
s.settimeout(10)
def req(*xs):
 b=b'*%d\r\n'%len(xs)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in xs)
 s.sendall(b);return s.recv(1024)
if not req('AUTH','synthetic-only-password').startswith(b'+OK'):raise SystemExit('FIXTURE_AUTH_FAILED')
if not req('SET','synthetic:pre-fence','before').startswith(b'+OK'):raise SystemExit('FIXTURE_WRITE_FAILED')
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


def termination_observed(pod, old_uid, original_container_id, *, forced=False):
    """Classify a synthetic Pod observation, not proof of durable AOF."""
    if forced or not isinstance(pod, dict): return False
    meta=pod.get('metadata',{});status=pod.get('status',{})
    if meta.get('uid')!=old_uid or not meta.get('deletionTimestamp'): return False
    containers=status.get('containerStatuses',[])
    if len(containers)!=1: return False
    item=containers[0]
    term=item.get('state',{}).get('terminated',{})
    return bool(item.get('name')=='redis' and item.get('containerID')==original_container_id
                and type(item.get('restartCount')) is int and item['restartCount']==0
                and type(term.get('exitCode')) is int and term['exitCode']==0
                and type(term.get('signal',0)) is int and term.get('signal',0)==0
                and term.get('reason')=='Completed')


def original_deployment(bind='0.0.0.0'):
    """Synthetic copy of the 0.1.6 Redis PID 1 command; no supervisor/hook."""
    # The loopback option is the experimental template change. Other fields
    # are a minimal fixture, not the signed release Helm chart.
    original = ('exec redis-server --appendonly yes --dir /data --maxmemory 256mb '
                '--maxmemory-policy noeviction --requirepass "$REDIS_PASSWORD"')
    if bind == '127.0.0.1': original += ' --bind 127.0.0.1'
    elif bind != '0.0.0.0': raise ValueError('unsupported synthetic bind')
    return {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'original-redis'},
            'spec':{'replicas':1,'strategy':{'type':'Recreate'},
                    'selector':{'matchLabels':{'app':'original-redis'}},
                    'template':{'metadata':{'labels':{'app':'original-redis'}},
                      'spec':{'automountServiceAccountToken':False,'securityContext':{'fsGroup':1000},
                              'containers':[{'name':'redis','image':REDIS,'command':['sh','-ec'],
                                'args':[original], 'env':[{'name':'REDIS_PASSWORD','value':PASS}],
                                'readinessProbe':{'exec':{'command':['sh','-ec',
                                  'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping | grep -q PONG']},
                                  'periodSeconds':2},
                                'volumeMounts':[{'name':'data','mountPath':'/data'}]}],
                              'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'original-data'}}]}}}}


def client_failure_category(stderr):
    """Expose only fixed synthetic categories, never the raw kubectl error."""
    for marker in ('FIXTURE_CONNECTION_FAILED', 'FIXTURE_AUTH_FAILED', 'FIXTURE_WRITE_FAILED'):
        if marker.encode() in stderr:
            return marker
    if b'Error from server' in stderr: return 'KUBECTL_EXEC_FAILED'
    if b'Traceback' in stderr: return 'FIXTURE_EXCEPTION'
    return 'NO_FIXED_DIAGNOSTIC'


def deployment(hanging=False, bind='0.0.0.0'):
    # UIDs are synthetic and the markers are not authenticated. The deliberate
    # hang models a failed graceful termination, not a safe recovery protocol.
    prestop = 'sleep 30' if hanging else (
        'printf "%s" "$POD_UID" > "/data/intent-$POD_UID"; '
        'exec redis-cli -a "$SYNTHETIC_PASSWORD" --no-auth-warning shutdown save')
    # Synthetic supervisor keeps PID 1 alive after the child Redis exits and
    # records an observed zero exit + shutdown intent. The released Uter image
    # does not use this wrapper; its marker is not a production trust anchor.
    supervisor = ('redis-server --appendonly yes --appendfsync always --dir /data '
                  '--bind "$SYNTHETIC_BIND" --requirepass "$SYNTHETIC_PASSWORD" & '
                  'child=$!; if wait "$child"; then rc=0; else rc=$?; fi; '
                  'if [ "$rc" -eq 0 ] && [ -f "/data/intent-$POD_UID" ]; then '
                  'printf "%s" "$POD_UID" > "/data/marker-$POD_UID"; fi; exit "$rc"')
    return {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'synthetic-redis'},
            'spec':{'replicas':1,'strategy':{'type':'Recreate'},
                    'selector':{'matchLabels':{'app':'synthetic-redis'}},
                    'template':{'metadata':{'labels':{'app':'synthetic-redis'}},
                      'spec':{'automountServiceAccountToken':False, 'terminationGracePeriodSeconds':5 if hanging else 30,
                              'securityContext':{'fsGroup':1000},
                              'containers':[{'name':'redis','image':REDIS,
                                 'command':['sh','-ec'], 'args':[supervisor],
                                 'env':[{'name':'SYNTHETIC_PASSWORD','value':PASS},
                                        {'name':'SYNTHETIC_BIND','value':bind},
                                        {'name':'POD_UID','valueFrom':{'fieldRef':{'fieldPath':'metadata.uid'}}}],
                                 'lifecycle':{'preStop':{'exec':{'command':['sh','-ec',prestop]}}},
                                 'readinessProbe':{'exec':{'command':['sh','-ec',
                                      'REDISCLI_AUTH="$SYNTHETIC_PASSWORD" redis-cli -h 127.0.0.1 ping | grep -q PONG']},
                                      'periodSeconds':2},
                                 'volumeMounts':[{'name':'data','mountPath':'/data'}]}],
                              'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'synthetic-data'}}]}}}}


def main():
    global PHASE
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
        def original_ready(): k('rollout','status','deployment/original-redis','--timeout=180s')
        def original_pod():
            pods=json.loads(k('get','pods','-l','app=original-redis','-o','json'))['items']
            active=[p for p in pods if not p['metadata'].get('deletionTimestamp')]
            if len(active)!=1 or active[0].get('status',{}).get('phase')!='Running':
                raise RuntimeError('unexpected original synthetic pods')
            return active[0]
        def finalizer(pod, action):
            name=pod['metadata']['name'];uid=pod['metadata']['uid']
            for _ in range(5):
                obj=json.loads(k('get','pod/'+name,'-o','json'))
                meta=obj['metadata']; fs=meta.get('finalizers',[])
                if meta['uid']!=uid or not isinstance(fs,list): raise RuntimeError('synthetic finalizer identity changed')
                op=[{'op':'test','path':'/metadata/uid','value':uid},
                    {'op':'test','path':'/metadata/resourceVersion','value':meta['resourceVersion']}]
                if action=='add':
                    if fs: raise RuntimeError('unexpected synthetic finalizer')
                    op.append({'op':'add','path':'/metadata/finalizers','value':[owned_finalizer]})
                else:
                    if fs.count(owned_finalizer)!=1: raise RuntimeError('synthetic finalizer missing')
                    op.append({'op':'remove','path':'/metadata/finalizers/'+str(fs.index(owned_finalizer))})
                try:
                    k('patch','pod/'+name,'--type=json','-p',json.dumps(op));return
                except RuntimeError: time.sleep(.3)
            raise RuntimeError('synthetic finalizer patch failed')
        def await_termination(pod, *, forced=False, limit=120):
            name=pod['metadata']['name'];uid=pod['metadata']['uid']
            statuses=pod.get('status',{}).get('containerStatuses',[])
            if len(statuses)!=1: raise RuntimeError('synthetic original container identity missing')
            cid=statuses[0].get('containerID')
            if not cid: raise RuntimeError('synthetic original container ID missing')
            deadline=time.monotonic()+limit
            while time.monotonic()<deadline:
                obs=json.loads(k('get','pod/'+name,'-o','json'))
                if obs.get('metadata',{}).get('uid')!=uid:
                    raise RuntimeError('synthetic original pod UID changed')
                statuses=obs.get('status',{}).get('containerStatuses',[])
                if len(statuses)!=1: raise RuntimeError('synthetic termination status unavailable')
                terminated=statuses[0].get('state',{}).get('terminated')
                if terminated is not None:
                    return termination_observed(obs,uid,cid,forced=forced)
                time.sleep(.5)
            return False
        def patch_original_loopback():
            desired=original_deployment('127.0.0.1')['spec']['template']
            for _ in range(5):
                obj=json.loads(k('get','deployment/original-redis','-o','json'))
                ops=[{'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
                     {'op':'replace','path':'/spec/template','value':desired}]
                try:
                    k('patch','deployment/original-redis','--type=json','-p',json.dumps(ops));return
                except RuntimeError: time.sleep(.3)
            raise RuntimeError('original synthetic deployment patch failed')
        owned_finalizer='uter.io/experimental-'+uuid.uuid4().hex
        protected=[]
        try:
            if cluster in call('kind','get','clusters').splitlines():
                raise RuntimeError('synthetic cluster name already exists')
            attempted=True
            PHASE='cluster-create'
            call('kind','create','cluster','--name',cluster,'--image',NODE,'--wait','180s',timeout=300)
            PHASE='fixtures-create'
            call('kubectl','--context','kind-'+cluster,'create','namespace',namespace)
            apply({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'synthetic-data'},
                   'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'32Mi'}}}})
            apply(deployment())
            apply({'apiVersion':'v1','kind':'Service','metadata':{'name':'synthetic-redis'},
                   'spec':{'selector':{'app':'synthetic-redis'},'ports':[{'port':6379}]}})
            apply({'apiVersion':'v1','kind':'Pod','metadata':{'name':'client'},
                   'spec':{'automountServiceAccountToken':False,'containers':[{'name':'client','image':PYTHON,
                           'command':['python','-c','import time;time.sleep(900)']}]}})
            PHASE='fixtures-ready'
            ready();k('wait','--for=condition=Ready','pod/client','--timeout=180s')
            old,old_uid,old_ip=current()
            if redis(old,'PING')!='PONG': raise RuntimeError('synthetic old Redis not ready')
            PHASE='old-client-connect'
            proc=subprocess.Popen(kube+['exec','-i','client','--','python','-u','-c',OLD_CLIENT,old_ip],
                                  env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
            if not selector.select(30) or proc.stdout.readline().strip()!=b'READY':
                if proc.poll() is None: proc.kill()
                _, diagnostic=proc.communicate(timeout=10)
                proc=None
                raise RuntimeError('synthetic established connection failed: '+client_failure_category(diagnostic))
            PHASE='fenced-rollout'
            set_template(False,'127.0.0.1');ready()
            new,new_uid,ip=current()
            if new_uid==old_uid or old in [p['metadata']['name'] for p in json.loads(k('get','pods','-l',LABEL,'-o','json'))['items']]:
                raise RuntimeError('old synthetic pod still exists')
            PHASE='old-client-disconnect'
            proc.stdin.write(b'check\n');proc.stdin.flush()
            if not selector.select(20) or proc.stdout.readline().strip()!=b'CLOSED' or proc.wait(timeout=5):
                raise RuntimeError('old synthetic connection did not close')
            proc=None
            PHASE='shutdown-marker-and-aof'
            if not marker_valid(marker(new,old_uid),old_uid): raise RuntimeError('synthetic shutdown marker missing')
            if redis(new,'CONFIG','GET','bind')!='bind\n127.0.0.1' or redis(new,'GET','synthetic:pre-fence')!='before':
                raise RuntimeError('synthetic AOF state or bind mismatch')
            PHASE='fenced-connectivity'
            external_blocked(ip)
            PHASE='fenced-restart'
            k('rollout','restart','deployment/synthetic-redis');ready()
            restarted,restarted_uid,ip=current()
            if restarted_uid==new_uid or redis(restarted,'GET','synthetic:pre-fence')!='before':
                raise RuntimeError('synthetic fenced restart failed')
            external_blocked(ip)
            PHASE='synthetic-rollback'
            set_template(False,'0.0.0.0');ready()
            restored,_,_=current()
            if redis(restored,'GET','synthetic:pre-fence')!='before': raise RuntimeError('synthetic rollback lost data')
            # Introduce an intentionally hanging synthetic preStop, then trigger a
            # rollout: lack of a marker is a mandatory failure, not an isolation proof.
            PHASE='hanging-shutdown'
            set_template(True,'0.0.0.0');ready();hung,hung_uid,_=current()
            set_template(False,'127.0.0.1');ready();after,_,_=current()
            if marker_valid(marker(after,hung_uid),hung_uid):
                raise RuntimeError('synthetic hung shutdown incorrectly accepted')
            PHASE='original-create'
            apply({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'original-data'},
                   'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'32Mi'}}}})
            apply(original_deployment());original_ready()
            original=original_pod();original_name=original['metadata']['name'];original_uid=original['metadata']['uid']
            if k('exec',original_name,'-c','redis','--','cat','/proc/1/comm')!='redis-server':
                raise RuntimeError('original synthetic Redis is not PID 1')
            if redis(original_name,'SET','synthetic:original-data','before')!='OK':
                raise RuntimeError('original synthetic data setup failed')
            proc=subprocess.Popen(kube+['exec','-i','client','--','python','-u','-c',OLD_CLIENT,
                                        original['status']['podIP']],env=env,stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
            if not selector.select(30) or proc.stdout.readline().strip()!=b'READY':
                if proc.poll() is None: proc.kill()
                _, diagnostic=proc.communicate(timeout=10);proc=None
                raise RuntimeError('original synthetic client failed: '+client_failure_category(diagnostic))
            PHASE='original-finalizer'
            finalizer(original,'add');protected.append(original)
            PHASE='original-loopback-rollout'
            patch_original_loopback()
            if not await_termination(original):
                raise RuntimeError('original synthetic termination was not observed as clean')
            proc.stdin.write(b'check\n');proc.stdin.flush()
            if not selector.select(20) or proc.stdout.readline().strip()!=b'CLOSED' or proc.wait(timeout=5):
                raise RuntimeError('original synthetic connection did not close')
            proc=None
            # Observation of exit status is only an experiment; no production
            # conclusion about fsync or the authority of AOF is inferred.
            finalizer(original,'remove');protected.remove(original)
            original_ready();replacement=original_pod();replacement_name=replacement['metadata']['name']
            if replacement['metadata']['uid']==original_uid:
                raise RuntimeError('original synthetic pod did not change')
            if redis(replacement_name,'CONFIG','GET','bind')!='bind\n127.0.0.1':
                raise RuntimeError('original synthetic replacement bind mismatch')
            if redis(replacement_name,'GET','synthetic:original-data')!='before':
                raise RuntimeError('original synthetic AOF state was not preserved')
            info=redis(replacement_name,'INFO','persistence')
            if 'aof_enabled:1' not in info or 'aof_last_write_status:ok' not in info:
                raise RuntimeError('original synthetic AOF not healthy')
            if 'DB loaded from append only file' not in k('logs',replacement_name,'-c','redis'):
                raise RuntimeError('original synthetic AOF load was not observed')
            external_blocked(replacement['status']['podIP'])
            PHASE='original-force-delete'
            finalizer(replacement,'add');protected.append(replacement)
            k('delete','pod/'+replacement_name,'--grace-period=0','--force','--wait=false')
            if await_termination(replacement,forced=True,limit=30):
                raise RuntimeError('forced synthetic shutdown was incorrectly accepted')
            finalizer(replacement,'remove');protected.remove(replacement)
        finally:
            if proc is not None:
                proc.kill();proc.wait(timeout=10)
            cleanup_problem=False
            for pod in reversed(protected):
                try: finalizer(pod,'remove')
                except Exception: cleanup_problem=True
            if attempted:
                # Unique cluster had been verified absent; only this named cluster
                # and its private kubeconfig are touched, never another context.
                try: call('kind','delete','cluster','--name',cluster,timeout=180)
                except Exception: cleanup_problem=True
            if cleanup_problem: raise RuntimeError('synthetic cleanup unconfirmed')
    print('Synthetic Kubernetes loopback/AOF lifecycle and hung-shutdown rejection passed; cluster cleanup confirmed.')


if __name__=='__main__':
    try: main()
    except RuntimeError as error:
        raise SystemExit('Synthetic Kubernetes fence experiment failed at '+PHASE+': '+str(error))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit('Synthetic Kubernetes fence experiment failed at '+PHASE+': '+type(error).__name__)
