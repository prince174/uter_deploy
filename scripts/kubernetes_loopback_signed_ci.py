"""Restricted, disposable-CI-only rollout of the published Redis Pod.

This is not an updater or production fence. It deliberately has no automatic
recovery, no admission/RBAC/GitOps guarantee and no authorization to migrate.
Mutating requests have unknown outcome on any error: journal/finalizer remain.
"""
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import tempfile
import time

import uterctl
from scripts import (adopt_backup_ci, kubernetes_fence_finalizer as finalizer,
                     kubernetes_loopback_intent as loopback_intent,
                     kubernetes_loopback_recovery as loopback_recovery,
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
secret=os.environ.get('REDIS_PASSWORD')
if not secret:raise SystemExit('CI_CLIENT_MISSING_ENV')
try:s=socket.create_connection((sys.argv[1],6379),timeout=10)
except OSError:raise SystemExit('CI_CLIENT_CONNECT')
s.settimeout(10)
def req(*items):
 b=b'*%d\r\n'%len(items)+b''.join(b'$%d\r\n'%len(x.encode())+x.encode()+b'\r\n' for x in items)
 s.sendall(b);return s.recv(1024)
if not req('AUTH',secret).startswith(b'+OK'):raise SystemExit('CI_CLIENT_AUTH')
if not req('PING').startswith(b'+PONG'):raise SystemExit('CI_CLIENT_PING')
print('READY',flush=True);sys.stdin.readline()
try:
 if req('PING') != b'': raise SystemExit(4)
except TimeoutError: raise
except OSError: pass
print('CLOSED',flush=True)
'''


class KubernetesLoopbackCIError(ValueError):
    pass


def _client_failure(stderr):
    """Return fixed categories only; raw kubectl output is never published."""
    for code in ('CI_CLIENT_MISSING_ENV','CI_CLIENT_CONNECT','CI_CLIENT_AUTH','CI_CLIENT_PING'):
        if code.encode() in stderr: return code.removeprefix('CI_')
    return 'CLIENT_EXEC'


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


def _ci_delete_uid(kind,name,uid):
    """Delete only one observed synthetic object with a server UID precondition."""
    global PHASE
    patterns={'pod':r'uter-ci-loopback-probe', 'policy':r'uter-ci-loopback-policy-[0-9a-f]{16}'}
    if (kind not in patterns or not isinstance(name,str) or not re.fullmatch(patterns[kind],name)
            or not isinstance(uid,str) or not identity.UUID.fullmatch(uid)):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
    resource=('api/v1/namespaces/'+SITE+'/pods/' if kind=='pod' else
              'apis/networking.k8s.io/v1/namespaces/'+SITE+'/networkpolicies/')+name
    options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid}}
    try:
        with tempfile.NamedTemporaryFile(mode='w',prefix='kube-delete-options-',dir=ROOT/'work',encoding='utf-8') as fp:
            json.dump(options,fp,separators=(',',':'));fp.flush();os.fsync(fp.fileno())
            raw=_ci_kube_command(['delete','--raw=/'+resource,'-f',fp.name])
    except Exception:
        PHASE='DELETE_POLICY_COMMAND' if kind=='policy' else 'DELETE_POD_COMMAND'
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLEANUP_UNCERTAIN') from None
    try:
        response=json.loads(raw)
        status_ok=(isinstance(response,dict) and response.get('kind')=='Status'
                   and response.get('status')=='Success')
        metadata=response.get('metadata',{}) if isinstance(response,dict) else {}
        pod_ok=(kind=='pod' and response.get('kind')=='Pod' and isinstance(metadata,dict)
                and metadata.get('name')==name and metadata.get('namespace')==SITE
                and metadata.get('uid')==uid and isinstance(metadata.get('deletionTimestamp'),str)
                and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z',
                                 metadata['deletionTimestamp']))
        if not status_ok and not pod_ok:
            raise ValueError
    except Exception:
        PHASE='DELETE_POLICY_RESPONSE' if kind=='policy' else 'DELETE_POD_RESPONSE'
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLEANUP_UNCERTAIN') from None
    # A successful DELETE can leave an object terminating. Check until the
    # observed UID is gone; a replacement UID is never deleted by this helper.
    prefix='DELETE_POLICY_VERIFY' if kind=='policy' else 'DELETE_POD_VERIFY'
    PHASE=prefix+'_GET'
    # A Pod normally has a 30-second termination grace period; the previous
    # 30-second bound could expire before Kubernetes finished graceful deletion.
    # Retain UID preconditions and require the old UID to disappear.
    deadline=time.monotonic()+(90 if kind=='pod' else 30)
    try:
        while True:
            PHASE=prefix+'_GET'
            raw=_ci_kube_command(['get', 'networkpolicy' if kind=='policy' else 'pod', name,
                                  '--ignore-not-found=true','-o','json'])
            if not raw: break
            PHASE=prefix+'_FORMAT'
            current=json.loads(raw)
            # Do not yet treat any List as absence: distinguish this finite
            # shape for disposable-CI observation before changing semantics.
            if (isinstance(current,dict) and current.get('apiVersion')=='v1'
                    and current.get('kind')=='List' and current.get('items')==[]):
                PHASE=prefix+'_EMPTY_LIST'
                raise ValueError
            if not isinstance(current,dict) or current.get('kind')!=('Pod' if kind=='pod' else 'NetworkPolicy'):
                raise ValueError
            meta=current.get('metadata') if isinstance(current,dict) else None
            if (not isinstance(meta,dict) or meta.get('name')!=name or meta.get('namespace')!=SITE
                    or not isinstance(meta.get('uid'),str) or not identity.UUID.fullmatch(meta['uid'])):
                raise ValueError
            if meta['uid']!=uid: break
            PHASE=prefix+'_TIMEOUT'
            if time.monotonic()>=deadline: raise ValueError
            time.sleep(0.5)
    except Exception:
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLEANUP_UNCERTAIN') from None


def _ci_clear_killed_child_lock(home,pid):
    """Only for this hosted fixture after the parent reaped its own child.

    This is not an algorithm for recovering an installation's stale lock.
    The CI fixture is exclusively controlled by the parent process.
    """
    adopt_backup_ci.runner_guard(os.environ,ROOT)
    if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
            or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'
            or os.environ.get('BACKEND')!='kubernetes' or type(pid) is not int or pid<=1
            or not Path(home).resolve(strict=True).is_relative_to(ROOT/'work')):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_STALE_LOCK')
    directory=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('operation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(fd);data=os.read(fd,64)
            current=os.stat('operation.lock',dir_fd=directory,follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or info.st_mode&0o077 or data!=str(pid).encode()
                    or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino)):
                raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_STALE_LOCK')
            os.unlink('operation.lock',dir_fd=directory);os.fsync(directory)
        finally:os.close(fd)
    except OSError:raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_STALE_LOCK') from None
    finally:os.close(directory)


def _ci_crash_recovery_after_patch(home,plan,operation,api):
    """SIGKILL a locked fixture controller after API success, before response.

    The child alone owns the fixture lock. Parent only clears that lock after
    waitpid of its child; neither this clearance nor parent recovery is a
    production stale-lock protocol. No user-controlled callbacks are accepted.
    """
    global PHASE
    adopt_backup_ci.runner_guard(os.environ,ROOT)
    if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
            or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'
            or os.environ.get('BACKEND')!='kubernetes'
            or not Path(home).resolve(strict=True).is_relative_to(ROOT/'work')):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_GUARD')
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        os.close(readfd)
        try:
            with uterctl.locked(home):
                real_patch=api.patch_deployment
                def patch_and_pause(name,ops):
                    real_patch(name,ops)
                    os.write(writefd,b'R')
                    while True:signal.pause()
                api.patch_deployment=patch_and_pause
                loopback_recovery.request(home,plan,operation,api)
            os._exit(12)
        except BaseException:os._exit(13)
    os.close(writefd);reaped=False
    try:
        import select
        if not select.select([readfd],[],[],120)[0] or os.read(readfd,1)!=b'R':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CRASH_NOT_READY')
        os.kill(pid,signal.SIGKILL)
        waited,status=os.waitpid(pid,0);reaped=True
        if waited!=pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CRASH_NOT_KILLED')
    finally:
        os.close(readfd)
        if not reaped:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:os.waitpid(pid,0)
            except ChildProcessError:pass
    PHASE='CRASH_STALE_LOCK'
    _ci_clear_killed_child_lock(home,pid)


def _ci_confirm_identity_health(cluster_uid,pvc_uid,manifest,redis):
    """CI-only consistency and Redis health observation; no resume authority."""
    try:
        if (snapshot._query(['get','namespace','kube-system'])['metadata']['uid']!=cluster_uid
                or snapshot._query(['-n',SITE,'get','persistentvolumeclaim',SITE+'-redis'])['metadata']['uid']!=pvc_uid):
            raise ValueError
        snapshot.verify(manifest)
        if redis('ping')!='PONG':raise ValueError
        persistence={line.strip() for line in redis('aof').splitlines()}
        if 'aof_enabled:1' not in persistence or 'aof_last_write_status:ok' not in persistence:
            raise ValueError
    except Exception:raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_IDENTITY') from None


def _ci_probe_policy(operation_label):
    if not isinstance(operation_label,str) or not re.fullmatch(r'[0-9a-f]{32}',operation_label):
        raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
    name='uter-ci-loopback-policy-'+operation_label[:16]
    label={'uter.io/ci-redis-probe':operation_label}
    policy={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
            'metadata':{'name':name,'namespace':SITE,'labels':label},
            'spec':{'podSelector':{'matchLabels':{'app.kubernetes.io/instance':SITE,
                                                   'app.kubernetes.io/name':'redis'}},
                    'policyTypes':['Ingress'],'ingress':[{'from':[{'podSelector':{'matchLabels':label}}],
                                                          'ports':[{'protocol':'TCP','port':6379}]}]}}
    return policy


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
        deployment_patch(meta['uid'],meta['resourceVersion'])
        record=loopback_intent.prepare(home,plan,operation,api)
        if record['uid']!=meta['uid'] or record['original_rv']!=meta['resourceVersion']:
            raise ValueError
        # Fault injection on this explicitly disposable CI cluster: the API
        # patch succeeds and the caller then observes an exception. The
        # read-only classifier must observe the target spec without retrying.
        real_patch=api.patch_deployment
        calls={'attempted':0,'succeeded':0}
        def timeout_after_success(name,ops):
            calls['attempted']+=1
            real_patch(name,ops)
            calls['succeeded']+=1
            raise TimeoutError('synthetic after-success fault')
        api.patch_deployment=timeout_after_success
        try:
            try:
                loopback_intent.request(home,plan,operation,api)
            except loopback_intent.LoopbackIntentError:
                pass
            else:
                raise ValueError
            if calls!={'attempted':1,'succeeded':1}:
                raise ValueError
            try:
                loopback_intent._reject_existing_attempt(home)
            except loopback_intent.LoopbackIntentError:
                pass
            else:
                raise ValueError
            try:
                loopback_intent.request(home,plan,operation,api)
            except loopback_intent.LoopbackIntentError:
                pass
            else:
                raise ValueError
            if calls!={'attempted':1,'succeeded':1}:
                raise ValueError
        finally:
            api.patch_deployment=real_patch
        if loopback_intent.classify(home,plan,operation,api)!= {
                'state':'loopback_spec_observed','redis_isolated':False,'safe_to_update':False}:
            raise ValueError
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
        if command not in ('exists','write','read','delete','bind','aof','ping'):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
        commands={'exists':'EXISTS '+CI_KEY, 'write':'SET '+CI_KEY+' '+CI_VALUE,
                  'read':'GET '+CI_KEY, 'delete':'DEL '+CI_KEY,'bind':'CONFIG GET bind',
                  'aof':'INFO persistence','ping':'PING'}
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
        PHASE='PINNED_PREFLIGHT'
        from scripts import kubernetes_pinned_preflight_ci
        result=kubernetes_pinned_preflight_ci.verify(home,bundle,key,manifest)
        if result!={'result':'sealed_pinned_queries_exercised','cluster_authenticated':False,'safe_to_update':False}:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_IDENTITY')
        # CI-only baseline observed in the same cluster; this is not an
        # independently authenticated identity for a production installation.
        PHASE='BASELINE_IDENTITY'
        cluster_uid=snapshot._query(['get','namespace','kube-system'])['metadata']['uid']
        pvc_uid=snapshot._query(['-n',SITE,'get','persistentvolumeclaim',SITE+'-redis'])['metadata']['uid']
        if not identity.UUID.fullmatch(cluster_uid) or not identity.UUID.fullmatch(pvc_uid):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_IDENTITY')
        PHASE='FIXTURE'
        if redis('exists')!='0': raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_FIXTURE_EXISTS')
        if redis('write')!='OK': raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_WRITE')
        original=pods('redis')
        if len(original)!=1: raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POD')
        pod=original[0];name=pod['metadata']['name'];uid=pod['metadata']['uid']
        ip=pod['status']['podIP']
        if not re.fullmatch(r'[0-9.]{7,15}',ip): raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POD')
        plan=finalizer.plan_from_pod(CONTEXT,SITE,name,pod)
        finalizer.persist_plan(home,plan)
        record=journal.create(home,backend='kubernetes',site=SITE,resource=uid,
                              plan_sha256=finalizer.plan_hash(plan))
        operation=record['operation']
        PHASE='STOP_WRITERS'
        try:quiesce_key=kubernetes_pinned_preflight_ci.quiesce_writers(home,bundle,key,manifest,operation)
        except kubernetes_pinned_preflight_ci.PinnedCITestError as error:
            allowed={'WRITER_TERMINATION_POD_FETCH','WRITER_TERMINATION_IDENTITY','WRITER_TERMINATION_CONTAINER',
                     'WRITER_TERMINATION_TERMINATED_STATE','WRITER_TERMINATION_EXIT_CODE','WRITER_TERMINATION_SIGNAL',
                     'WRITER_TERMINATION_REASON','WRITER_TERMINATION_UNVERIFIED'}
            if error.stage in allowed:PHASE=error.stage
            raise
        wait_no_writers()
        PHASE='CLIENT_CREATE'
        operation_label=secrets.token_hex(16)
        policy=_ci_probe_policy(operation_label)
        policy_name=policy['metadata']['name']
        probe_label={'uter.io/ci-redis-probe':operation_label}
        with tempfile.NamedTemporaryFile(mode='w',prefix='kube-probe-policy-',dir=ROOT/'work',encoding='utf-8') as fp:
            json.dump(policy,fp,separators=(',',':'));fp.flush();os.fsync(fp.fileno())
            k('create','-f',fp.name)
        actual=snapshot._query(['-n',SITE,'get','networkpolicy',policy_name])
        pm=actual['metadata'];policy_uid=pm['uid']
        if (pm.get('name')!=policy_name or pm.get('namespace')!=SITE or pm.get('labels')!=probe_label
                or not isinstance(policy_uid,str) or not identity.UUID.fullmatch(policy_uid)):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_POLICY')
        probe_spec={'spec':{'automountServiceAccountToken':False,'containers':[{'name':'uter-ci-loopback-probe',
                    'image':PYTHON_IMAGE,'command':['python','-c','import time;time.sleep(600)'],
                    'env':[{'name':'REDIS_PASSWORD','valueFrom':{'secretKeyRef':{'name':SITE+'-redis-secret','key':'password'}}}]}]},
                    'metadata':{'labels':probe_label}}
        k('run','uter-ci-loopback-probe','--image='+PYTHON_IMAGE,'--restart=Never',
          '--overrides='+json.dumps(probe_spec,separators=(',',':')))
        PHASE='CLIENT_READY'
        k('wait','--for=condition=Ready','pod/uter-ci-loopback-probe','--timeout=180s',timeout=210)
        probe=snapshot._query(['-n',SITE,'get','pod','uter-ci-loopback-probe'])
        probe_meta=probe['metadata'];probe_uid=probe_meta['uid']
        if (probe_meta.get('name')!='uter-ci-loopback-probe' or probe_meta.get('namespace')!=SITE
                or probe_meta.get('labels',{}).get('uter.io/ci-redis-probe')!=operation_label
                or not isinstance(probe_uid,str) or not identity.UUID.fullmatch(probe_uid)):
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT')
        PHASE='CLIENT_EXEC'
        CLIENT_PROCESS=subprocess.Popen(['kubectl','--context',CONTEXT,'-n',SITE,'exec','-i',
                         'pod/uter-ci-loopback-probe','--','python','-u','-c',CLIENT_PROGRAM,ip],
                         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(CLIENT_PROCESS.stdout,selectors.EVENT_READ)
        if not selector.select(20) or CLIENT_PROCESS.stdout.readline().strip()!=b'READY':
            try: os.killpg(CLIENT_PROCESS.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: CLIENT_PROCESS.wait(timeout=10)
            except subprocess.TimeoutExpired:
                raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT') from None
            os.set_blocking(CLIENT_PROCESS.stderr.fileno(),False)
            try: diagnostic=os.read(CLIENT_PROCESS.stderr.fileno(),4096)
            except BlockingIOError: diagnostic=b''
            PHASE=_client_failure(diagnostic)
            CLIENT_PROCESS.stdin.close();CLIENT_PROCESS.stdout.close();CLIENT_PROCESS.stderr.close()
            CLIENT_PROCESS=None
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT')
        PHASE='HOLD'
        finalizer.hold(home,plan,operation,api)
        PHASE='PATCH'
        request_loopback(home,bundle,key,plan,operation,api,manifest)
        PHASE='TERMINATION'
        deadline=time.monotonic()+120
        shutdown_stage='UNVERIFIED'
        while time.monotonic()<deadline:
            try:
                observed=observe_old_process(home,plan,operation,api)
                if observed['result']=='termination_observed': break
            except shutdown.ShutdownObservationError as error:
                shutdown_stage=error.stage
                time.sleep(.5)
        else:
            allowed={'PLAN','POD_FETCH','POD_IDENTITY','POD_SPEC','POD_STATUS',
                     'CONTAINER','TERMINATED_STATE','EXIT_CODE','SIGNAL','REASON'}
            PHASE='TERMINATION_'+(shutdown_stage if shutdown_stage in allowed else 'UNVERIFIED')
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_TERMINATION_UNVERIFIED')
        CLIENT_PROCESS.stdin.write(b'check\n');CLIENT_PROCESS.stdin.flush()
        if not selector.select(20) or CLIENT_PROCESS.stdout.readline().strip()!=b'CLOSED':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT_NOT_CLOSED')
        if CLIENT_PROCESS.wait(timeout=10)!=0:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_CLIENT_NOT_CLOSED')
        CLIENT_PROCESS.stdin.close();CLIENT_PROCESS.stdout.close();CLIENT_PROCESS.stderr.close()
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
        # Persist a reverse intent while still holding the fixture lock.
        PHASE='RECONNECT_PATCH'
        loopback_recovery.prepare(home,plan,operation,api)
    # The child acquires its own lock and is killed after the API confirms the
    # reverse PATCH but before its controller sees the response. Fixture-only
    # stale lock cleanup follows waitpid; this is not production recovery.
    PHASE='CRASH_PATCH'
    _ci_crash_recovery_after_patch(home,plan,operation,api)
    with uterctl.locked(home):
        PHASE='CRASH_CLASSIFY'
        if loopback_recovery.classify(home,plan,operation,api)!= {
                'state':'original_spec_observed','redis_healthy':False,'safe_to_resume':False}:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_RECONNECT')
        # A possibly in-flight API request must never be replayed.
        calls=[];real_patch=api.patch_deployment
        def reject_retry(name,ops):calls.append(1);raise ValueError
        api.patch_deployment=reject_retry
        try:
            try:loopback_recovery.request(home,plan,operation,api)
            except loopback_recovery.RecoveryError:pass
            else:raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_RECONNECT')
        finally:api.patch_deployment=real_patch
        if calls:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_RECONNECT')
        PHASE='RECONNECT_ROLLOUT'
        rollout()
        PHASE='RECONNECT_IDENTITY'
        _ci_confirm_identity_health(cluster_uid,pvc_uid,manifest,redis)
        PHASE='RECONNECT_DATA'
        if redis('read')!=CI_VALUE or redis('delete')!='1':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_DATA')
        PHASE='RECONNECT_POLICY_NEGATIVE'
        wrong_uid='00000000-0000-0000-0000-000000000000'
        if policy_uid==wrong_uid: raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_ARGUMENT')
        try: _ci_delete_uid('policy',policy_name,wrong_uid)
        except KubernetesLoopbackCIError: pass
        else: raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_UID_PRECONDITION')
        PHASE='RECONNECT_POLICY_NEGATIVE'
        check=snapshot._query(['-n',SITE,'get','networkpolicy',policy_name])
        if check.get('metadata',{}).get('uid')!=policy_uid:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_UID_PRECONDITION')
        PHASE='RECONNECT_POLICY_DELETE'
        _ci_delete_uid('policy',policy_name,policy_uid)
        PHASE='RECONNECT_POD_DELETE'
        _ci_delete_uid('pod','uter-ci-loopback-probe',probe_uid)
        PHASE='RECONNECT_JOURNAL'
        saved=journal.read(home)
        if saved['operation']!=operation or saved['phase']!='isolating':
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
        recorded=loopback_intent._read(home)
        if recorded['operation']!=operation:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
        recovered,_=loopback_recovery._record(home,plan,operation,api)
        if recovered['operation']!=operation:
            raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
        from scripts import kubernetes_writer_quiesce
        writer_plan=kubernetes_writer_quiesce._read(home,kubernetes_writer_quiesce.NAME,quiesce_key)
        if writer_plan.get('operation')!=operation:raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
        writer_files=[]
        for service in kubernetes_writer_quiesce.SERVICES:
            marker='kubernetes-writer-'+service+'-attempt.json'
            expected={'schema':1,'operation':operation,'service':service,
                      'plan_sha256':kubernetes_writer_quiesce._hash(writer_plan)}
            if kubernetes_writer_quiesce._read(home,marker,quiesce_key)!=expected:
                raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
            podfile='kubernetes-writer-pod-'+service+'.json'
            pod_plan=kubernetes_writer_quiesce._read(home,podfile,quiesce_key)
            if (pod_plan.get('operation')!=operation or pod_plan.get('service')!=service
                    or pod_plan.get('writer_plan_sha256')!=kubernetes_writer_quiesce._hash(writer_plan)):
                raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
            digest=kubernetes_writer_quiesce._hash(pod_plan)
            held='kubernetes-writer-hold-'+service+'-attempt.json'
            released='kubernetes-writer-release-'+service+'-attempt.json'
            observed='kubernetes-writer-observed-'+service+'.json'
            for name in (held,released):
                if kubernetes_writer_quiesce._read(home,name,quiesce_key)!= {'operation':operation,'pod_plan_sha256':digest}:
                    raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
            observation=kubernetes_writer_quiesce._read(home,observed,quiesce_key)
            if (set(observation)!={'operation','pod_plan_sha256','resource_version'} or observation['operation']!=operation
                    or observation['pod_plan_sha256']!=digest or not isinstance(observation['resource_version'],str)
                    or not re.fullmatch(r'[0-9]{1,32}',observation['resource_version'])):
                raise KubernetesLoopbackCIError('KUBE_LOOPBACK_CI_JOURNAL')
            writer_files.extend((marker,podfile,held,released,observed))
        for name in writer_files:(home/name).unlink()
        (home/kubernetes_writer_quiesce.NAME).unlink()
        (home/loopback_recovery.ATTEMPT_NAME).unlink()
        (home/loopback_recovery.NAME).unlink()
        (home/loopback_intent.ATTEMPT_NAME).unlink()
        (home/loopback_intent.NAME).unlink()
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
            for stream in (CLIENT_PROCESS.stdin,CLIENT_PROCESS.stdout,CLIENT_PROCESS.stderr):
                if stream is not None:
                    try: stream.close()
                    except OSError: pass
            CLIENT_PROCESS=None
