"""Restricted, disposable-CI-only rollout of the published Redis Pod.

This is not an updater or production fence. It deliberately has no automatic
recovery, no admission/RBAC/GitOps guarantee and no authorization to migrate.
Mutating requests have unknown outcome on any error: journal/finalizer remain.
"""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

import uterctl
from scripts import (adopt_backup_ci, kubernetes_fence_finalizer as finalizer,
                     kubernetes_redis_identity as identity,
                     kubernetes_redis_identity_ci as snapshot,
                     kubernetes_redis_shutdown as shutdown,
                     backup_snapshot, backup_store, install_recovery, redis_fence_journal as journal)

ROOT=Path(__file__).resolve().parents[1]
SITE=snapshot.SITE
CONTEXT=snapshot.CONTEXT
DEPLOYMENT=SITE+'-redis'
LOOPBACK_COMMAND=identity.COMMAND+' --bind 127.0.0.1'
CI_KEY='uter:ci-loopback-probe'
CI_VALUE='ci-loopback-value'
PYTHON_IMAGE='python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
PHASE='GUARD'
CLIENT_PROCESS=None
CLIENT_PROGRAM=r'''
import os,socket,sys
s=socket.create_connection((sys.argv[1],6379),timeout=10);s.settimeout(10)
def req(*items):
 b=b'*%d\r\n'%len(items)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in items)
 s.sendall(b);return s.recv(1024)
if not req('AUTH',os.environ['REDIS_PASSWORD']).startswith(b'+OK'):raise SystemExit(2)
if not req('PING').startswith(b'+PONG'):raise SystemExit(3)
print('READY',flush=True);sys.stdin.readline()
try:
 if req('PING') != b'': raise SystemExit(4)
except TimeoutError: raise
except OSError: pass
print('CLOSED',flush=True)
'''


class KubernetesLoopbackCIError(ValueError):
    pass


def _ci_kube_command(args, *, timeout=30):
    """Bound CI kubectl watches without truncating their requested duration."""
    if timeout not in (30,150,210,330):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
    request_timeout='20s' if timeout==30 else '0'
    command=['kubectl','--context',CONTEXT,'--namespace',SITE,
             '--request-timeout='+request_timeout,*args]
    try:
        adopt_backup_ci.runner_guard(os.environ, ROOT)
        if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'
                or os.environ.get('BACKEND')!='kubernetes'):
            raise ValueError
        return install_recovery.run_readonly(command,timeout=timeout).strip()
    except Exception:
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_COMMAND') from None


def guard(home,bundle,key,manifest):
    """Reject any target other than the explicitly owned hosted-runner fixture."""
    try:
        adopt_backup_ci.runner_guard(os.environ, ROOT)
        if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true' or os.environ.get('BACKEND')!='kubernetes'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true' or os.environ.get('DOCKER_HOST')
                or os.environ.get('DOCKER_CONTEXT') not in (None,'','default')):
            raise ValueError
        home=Path(home).resolve(strict=True);bundle=Path(bundle).resolve(strict=True);key=Path(key).resolve(strict=True)
        if (not home.is_relative_to(ROOT/'work') or not bundle.is_relative_to(ROOT/'work')
                or not key.is_relative_to(ROOT/'work') or uterctl.verify(bundle,key)!=manifest
                or manifest.get('version')!='0.1.6'):
            raise ValueError
        cfg=uterctl.read(home/'install.json')
        if cfg.get('name')!=SITE or cfg.get('backend')!='kubernetes' or cfg.get('context')!=CONTEXT:
            raise ValueError
        snapshot.verify(manifest)
    except Exception:
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_GUARD') from None


def deployment_patch(uid,resource_version):
    if (not isinstance(uid,str) or not identity.UUID.fullmatch(uid) or not isinstance(resource_version,str)
            or not re.fullmatch(r'[0-9]{1,32}',resource_version)):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_PATCH_INVALID')
    # UID and resourceVersion close races between read and write. Tests on the
    # exact strategy, command and args protect the persisted template boundary.
    return [{'op':'test','path':'/metadata/uid','value':uid},
            {'op':'test','path':'/metadata/resourceVersion','value':resource_version},
            {'op':'test','path':'/spec/strategy/type','value':'Recreate'},
            {'op':'test','path':'/spec/template/spec/containers/0/name','value':'redis'},
            {'op':'test','path':'/spec/template/spec/containers/0/command','value':['sh','-ec']},
            {'op':'test','path':'/spec/template/spec/containers/0/args','value':[identity.COMMAND]},
            {'op':'replace','path':'/spec/template/spec/containers/0/args','value':[LOOPBACK_COMMAND]}]


def request_loopback(home,bundle,key,plan,operation,api,manifest):
    """Request loopback only after checking journal, Pod and Deployment again.

    Caller must first run guard(), hold the controller lock, stop application
    writers, durably persist the finalizer plan and successfully hold it. Neither
    the return value nor a successful patch establish a fence. The function is
    not connected to the normal update controller.
    """
    try:
        guard(home,bundle,key,manifest)
        finalizer._validate_plan(plan)
        finalizer._check_journal(home,plan,operation,'isolating')
        token=finalizer._token(operation)
        if api.context!=CONTEXT or api.namespace!=SITE:
            raise ValueError
        finalizer._verify_live(plan,api.get(plan['pod']),[token])
        for service in ('guardrail','agent'):
            dep=snapshot._query(['-n',SITE,'get','deployment',SITE+'-'+service])
            if type(dep.get('spec',{}).get('replicas')) is not int or dep['spec']['replicas']!=0:
                raise ValueError
            pods=snapshot._query(['-n',SITE,'get','pods','-l',
                'app.kubernetes.io/instance='+SITE+',app.kubernetes.io/name='+service])
            if pods.get('items')!=[]:
                raise ValueError
        snapshot.verify(manifest)
        deploy=snapshot._query(['-n',SITE,'get','deployment',DEPLOYMENT])
        meta=deploy['metadata']
        if (meta.get('name')!=DEPLOYMENT or meta.get('namespace')!=SITE
                or deploy.get('spec',{}).get('replicas')!=1):
            raise ValueError
        patch=deployment_patch(meta['uid'],meta['resourceVersion'])
        # The journal remains isolating before and after the request. On an API
        # timeout no compensating patch or finalizer removal is attempted.
        api._call(['--request-timeout=20s','patch','deployment/'+DEPLOYMENT,
                   '--type=json','-p',json.dumps(patch,separators=(',',':'))])
    except Exception:
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_REQUEST_UNCERTAIN') from None
    return {'result':'loopback_requested','redis_isolated':False,'safe_to_upgrade':False}


def observe_old_process(home,plan,operation,api):
    """Read-only observation; it intentionally does not release the finalizer."""
    return shutdown.observe(home,plan,operation,api)


def _verify(home,bundle,key,manifest):
    """Exercise only a signed installation on an explicitly disposable runner.

    The reconnect and removal below are CI fixture cleanup, not production
    rollback. An error never triggers a compensating patch or finalizer removal.
    The surrounding CI harness owns the ephemeral cluster and cleans it up.
    """
    global PHASE,CLIENT_PROCESS
    PHASE='GUARD'
    guard(home,bundle,key,manifest)
    home=Path(home).resolve(strict=True)
    api=finalizer.Kubectl(context=CONTEXT,namespace=SITE)
    def k(*args,timeout=30):
        return _ci_kube_command(list(args),timeout=timeout)
    def redis(command):
        if command not in ('exists','write','read','delete','bind','aof'):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
        commands={'exists':'EXISTS '+CI_KEY, 'write':'SET '+CI_KEY+' '+CI_VALUE,
                  'read':'GET '+CI_KEY, 'delete':'DEL '+CI_KEY,'bind':'CONFIG GET bind','aof':'INFO persistence'}
        return k('exec','deployment/'+DEPLOYMENT,'-c','redis','--','sh','-ec',
                 'export REDISCLI_AUTH="$REDIS_PASSWORD"; exec redis-cli --raw '+commands[command])
    def pods(service):
        return snapshot._query(['-n',SITE,'get','pods','-l',
                                'app.kubernetes.io/instance='+SITE+',app.kubernetes.io/name='+service])['items']
    def wait_no_writers():
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            if not pods('guardrail') and not pods('agent'): return
            time.sleep(.5)
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_WRITERS')
    def rollout():
        k('rollout','status','deployment/'+DEPLOYMENT,'--timeout=180s',timeout=210)
    with uterctl.locked(home):
        PHASE='FIXTURE'
        if redis('exists')!='0': raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_FIXTURE_EXISTS')
        if redis('write')!='OK': raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_WRITE')
        PHASE='STOP_WRITERS'
        k('scale','deployment/'+SITE+'-guardrail','deployment/'+SITE+'-agent','--replicas=0')
        wait_no_writers()
        original=pods('redis')
        if len(original)!=1: raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POD')
        pod=original[0];name=pod['metadata']['name'];uid=pod['metadata']['uid']
        ip=pod['status']['podIP']
        if not re.fullmatch(r'[0-9.]{7,15}',ip): raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POD')
        PHASE='CLIENT_CREATE'
        probe_spec={'spec':{'automountServiceAccountToken':False,'containers':[{'name':'uter-ci-loopback-probe',
                    'image':PYTHON_IMAGE,'command':['python','-c','import time;time.sleep(600)'],
                    'env':[{'name':'REDIS_PASSWORD','valueFrom':{'secretKeyRef':{'name':SITE+'-redis-secret','key':'password'}}}]}]}}
        k('run','uter-ci-loopback-probe','--image='+PYTHON_IMAGE,'--restart=Never',
          '--overrides='+json.dumps(probe_spec,separators=(',',':')))
        PHASE='CLIENT_READY'
        k('wait','--for=condition=Ready','pod/uter-ci-loopback-probe','--timeout=180s',timeout=210)
        PHASE='CLIENT_EXEC'
        CLIENT_PROCESS=subprocess.Popen(['kubectl','--context',CONTEXT,'-n',SITE,'exec','-i',
                         'pod/uter-ci-loopback-probe','--','python','-u','-c',CLIENT_PROGRAM,ip],
                         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                         start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(CLIENT_PROCESS.stdout,selectors.EVENT_READ)
        if not selector.select(20) or CLIENT_PROCESS.stdout.readline().strip()!=b'READY':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT')
        PHASE='HOLD'
        plan=finalizer.plan_from_pod(CONTEXT,SITE,name,pod)
        finalizer.persist_plan(home,plan)
        record=journal.create(home,backend='kubernetes',site=SITE,resource=uid,
                              plan_sha256=finalizer.plan_hash(plan))
        operation=record['operation']
        finalizer.hold(home,plan,operation,api)
        PHASE='PATCH'
        request_loopback(home,bundle,key,plan,operation,api,manifest)
        PHASE='TERMINATION'
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                observed=observe_old_process(home,plan,operation,api)
                if observed['result']=='termination_observed': break
            except shutdown.ShutdownObservationError:
                time.sleep(.5)
        else: raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_TERMINATION_UNVERIFIED')
        CLIENT_PROCESS.stdin.write(b'check\n');CLIENT_PROCESS.stdin.flush()
        if not selector.select(20) or CLIENT_PROCESS.stdout.readline().strip()!=b'CLOSED':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT_NOT_CLOSED')
        if CLIENT_PROCESS.wait(timeout=10)!=0:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT_NOT_CLOSED')
        CLIENT_PROCESS=None
        # This removal is exclusively CI fixture cleanup after observation. It
        # must not be reused as a real-world safe finalizer release.
        old=api.get(name);meta=old['metadata'];token=finalizer._token(operation)
        if (meta.get('uid')!=uid or meta.get('finalizers')!=[token]
                or not re.fullmatch(r'[0-9]{1,32}',meta.get('resourceVersion',''))):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_FINALIZER')
        ops=[{'op':'test','path':'/metadata/uid','value':uid},
             {'op':'test','path':'/metadata/resourceVersion','value':meta['resourceVersion']},
             {'op':'test','path':'/metadata/finalizers','value':[token]},
             {'op':'remove','path':'/metadata/finalizers/0'}]
        api.patch(name,ops)
        PHASE='POD'
        rollout()
        new=pods('redis')
        if (len(new)!=1 or new[0]['metadata']['uid']==uid or redis('bind')!='bind\n127.0.0.1'
                or redis('read')!=CI_VALUE):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_STATE')
        persistence={line.strip() for line in redis('aof').splitlines()}
        if 'aof_enabled:1' not in persistence or 'aof_last_write_status:ok' not in persistence:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_AOF')
        ip=new[0]['status']['podIP']
        if not re.fullmatch(r'[0-9.]{7,15}',ip): raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POD')
        probe=('import socket,sys\n'
               's=socket.socket();s.settimeout(3)\n'
               'try: s.connect((sys.argv[1],6379))\n'
               'except (ConnectionRefusedError,TimeoutError): print("BLOCKED");sys.exit(0)\n'
               'raise SystemExit(1)')
        if k('exec','pod/uter-ci-loopback-probe','--','python','-c',probe,ip)!='BLOCKED':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_REACHABLE')
        PHASE='SNAPSHOT'
        with tempfile.TemporaryDirectory(prefix='kube-loopback-snapshot-',dir=ROOT/'work') as temp:
            site={'backend':'helm','name':SITE,'namespace':SITE,'context':CONTEXT};secret=os.urandom(32)
            writer=backup_store.BackupWriter(Path(temp)/'set',secret,home,site,manifest['version'])
            cmd=['kubectl','--context',CONTEXT,'-n',SITE,'exec','deployment/'+DEPLOYMENT,'-c','redis','--',
                 'sh','-ec','export REDISCLI_AUTH="$REDIS_PASSWORD"; exec redis-cli --rdb -']
            check=['kubectl','--context',CONTEXT,'-n',SITE,'exec','-i','deployment/'+DEPLOYMENT,
                   '-c','redis','--','redis-check-rdb','/dev/stdin']
            backup_snapshot.process_component(writer,'redis',cmd,prefix=b'REDIS')
            backup_snapshot.verify_redis_snapshot(writer,check)
        # Test-only reconnect: guarded by exact Deployment UID, current RV and
        # loopback args, after which synthetic data is verified and removed.
        PHASE='RECONNECT_PATCH'
        dep=snapshot._query(['-n',SITE,'get','deployment',DEPLOYMENT]);meta=dep['metadata']
        if not isinstance(meta.get('resourceVersion'),str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion']):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_RECONNECT')
        ops=[{'op':'test','path':'/metadata/uid','value':meta['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':meta['resourceVersion']},
             {'op':'test','path':'/spec/template/spec/containers/0/args','value':[LOOPBACK_COMMAND]},
             {'op':'replace','path':'/spec/template/spec/containers/0/args','value':[identity.COMMAND]}]
        api._call(['--request-timeout=20s','patch','deployment/'+DEPLOYMENT,'--type=json',
                   '-p',json.dumps(ops,separators=(',',':'))])
        PHASE='RECONNECT_ROLLOUT'
        rollout()
        PHASE='RECONNECT_DATA'
        if redis('read')!=CI_VALUE or redis('delete')!='1':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_DATA')
        PHASE='RECONNECT_PROBE'
        k('delete','pod/uter-ci-loopback-probe','--wait=true','--timeout=120s',timeout=150)
        PHASE='RECONNECT_JOURNAL'
        saved=journal.read(home)
        if saved['operation']!=operation or saved['phase']!='isolating':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
        (home/journal.NAME).unlink();(home/finalizer.PLAN_NAME).unlink()
        PHASE='RECONNECT_WRITERS'
        k('scale','deployment/'+SITE+'-guardrail','deployment/'+SITE+'-agent','--replicas=1')
        for service in ('guardrail','agent'):
            k('rollout','status','deployment/'+SITE+'-'+service,'--timeout=300s',timeout=330)
    return {'result':'signed_ci_loopback_exercised','production_fence':False,'safe_to_upgrade':False}


def verify(home,bundle,key,manifest):
    global CLIENT_PROCESS
    try:
        return _verify(home,bundle,key,manifest)
    except Exception:
        # Never expose API data, names, command text or secret-related details.
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_UNVERIFIED') from None
    finally:
        if CLIENT_PROCESS is not None:
            try: os.killpg(CLIENT_PROCESS.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: CLIENT_PROCESS.wait(timeout=10)
            except subprocess.TimeoutExpired: pass
            CLIENT_PROCESS=None
