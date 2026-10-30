"""Journaled, namespace-scoped Pod-finalizer primitive; this is NOT a fence.

The caller must hold uterctl's installation operation lock and use a private,
durably saved plan. This module never starts/stops workloads, changes network
settings, verifies Kubernetes access control, or authorizes an update. A failed
or timed-out mutating request has an unknown outcome and is never retried here.
The caller must retain the journal and reconcile it with the API on recovery.
"""
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import time

from scripts import redis_fence_journal as journal

FIELDS = frozenset(('schema','context','namespace','pod','uid','resource_version',
                    'container_id','spec_sha256'))
MAX_OUTPUT = 2 * 1024 * 1024
PLAN_NAME = 'redis-fence-plan.json'
MAX_PLAN_BYTES = 4096
API_TIMEOUT = 30
REAP_TIMEOUT = 5


class FinalizerError(ValueError):
    """A fixed category, never raw API output or Pod content."""


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                     ensure_ascii=True).encode()).hexdigest()


def _validate_plan(plan):
    if not isinstance(plan,dict) or set(plan)!=FIELDS or type(plan['schema']) is not int or plan['schema']!=1:
        raise FinalizerError('KUBE_FINALIZER_PLAN_INVALID')
    for field in ('namespace','pod'):
        if not isinstance(plan[field],str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',plan[field]):
            raise FinalizerError('KUBE_FINALIZER_PLAN_INVALID')
    if (not isinstance(plan['context'],str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,252}',plan['context'])
            or not isinstance(plan['uid'],str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',plan['uid'])
            or not isinstance(plan['resource_version'],str) or not re.fullmatch(r'[0-9]{1,32}',plan['resource_version'])
            or not isinstance(plan['container_id'],str) or not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}',plan['container_id'])
            or not isinstance(plan['spec_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',plan['spec_sha256'])):
        raise FinalizerError('KUBE_FINALIZER_PLAN_INVALID')
    return plan


def plan_hash(plan):
    return _digest(_validate_plan(plan))


def persist_plan(directory, plan):
    """Create a private plan before journal creation; never overwrite it."""
    raw=(json.dumps(_validate_plan(plan),sort_keys=True,separators=(',',':'))+'\n').encode()
    fd=journal._directory(directory)
    try:
        try:
            handle=os.open(PLAN_NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(handle,'wb') as target:
                os.fchmod(target.fileno(),0o600);target.write(raw);target.flush();os.fsync(target.fileno())
            os.fsync(fd)
        except OSError:
            # The file may exist after an uncertain fsync failure; preserve it.
            raise FinalizerError('KUBE_FINALIZER_PLAN_WRITE_UNCERTAIN') from None
    finally:os.close(fd)


def read_plan(directory):
    fd=journal._directory(directory)
    try:
        try:
            handle=os.open(PLAN_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(handle,'rb') as source:
                info=os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                        or info.st_mode & 0o077 or info.st_size>MAX_PLAN_BYTES):
                    raise FinalizerError('KUBE_FINALIZER_PLAN_UNSAFE')
                raw=source.read(MAX_PLAN_BYTES+1)
            if len(raw)>MAX_PLAN_BYTES:raise FinalizerError('KUBE_FINALIZER_PLAN_UNSAFE')
            return _validate_plan(json.loads(raw))
        except FinalizerError:raise
        except (OSError,ValueError,TypeError,UnicodeError):
            raise FinalizerError('KUBE_FINALIZER_PLAN_UNREADABLE') from None
    finally:os.close(fd)


def plan_from_pod(context, namespace, name, pod):
    try:
        meta=pod['metadata']; spec=pod['spec']; status=pod['status']
        containers=status['containerStatuses']
        if (meta['namespace']!=namespace or meta['name']!=name or meta.get('deletionTimestamp')
                or meta.get('finalizers',[]) or status['phase']!='Running' or len(containers)!=1):
            raise ValueError
        item=containers[0]
        if (item['name']!='redis' or type(item['restartCount']) is not int or item['restartCount']!=0
                or not isinstance(item['state'].get('running'),dict)):
            raise ValueError
        plan={'schema':1,'context':context,'namespace':namespace,'pod':name,'uid':meta['uid'],
              'resource_version':meta['resourceVersion'],'container_id':item['containerID'],
              'spec_sha256':_digest(spec)}
        return _validate_plan(plan)
    except (KeyError, TypeError, ValueError, IndexError):
        raise FinalizerError('KUBE_FINALIZER_POD_UNSUPPORTED') from None


class Kubectl:
    """Explicit context/namespace, selected Pod and namespace Redis Deployment."""
    def __init__(self, *, context, namespace, env=None):
        self.context=context;self.namespace=namespace;self.env=env

    def _call(self, args):
        process=None
        try:
            if os.name!='posix' or not hasattr(os,'waitid'):
                raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
            process=subprocess.Popen(['kubectl','--context='+self.context,'--namespace='+self.namespace,*args],
                                     env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL,bufsize=0,start_new_session=True)
            deadline=time.monotonic()+API_TIMEOUT;output=bytearray()
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0: raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
                ready,_,_=select.select([process.stdout],[],[],remaining)
                if not ready: raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
                chunk=os.read(process.stdout.fileno(),min(65536,MAX_OUTPUT+1-len(output)))
                if not chunk: break
                output.extend(chunk)
                if len(output)>MAX_OUTPUT: raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
            # Observe exit without reaping: the group leader PID cannot be reused
            # before remaining credential-plugin descendants have been killed.
            while True:
                if os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT): break
                if time.monotonic()>=deadline: raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
                time.sleep(.02)
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            if process.wait(timeout=REAP_TIMEOUT):
                raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN')
            return bytes(output)
        except (OSError,subprocess.SubprocessError,ChildProcessError):
            raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN') from None
        finally:
            if process is not None:
                try:
                    # Do not inspect/reap before signalling the owned process group.
                    if process.returncode is None:
                        try: os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                        try:process.wait(timeout=REAP_TIMEOUT)
                        except subprocess.TimeoutExpired:
                            raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN') from None
                finally:process.stdout.close()

    def get(self, name):
        try: return json.loads(self._call(['--request-timeout=20s','get','pod/'+name,'-o','json']))
        except (ValueError,UnicodeError): raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN') from None

    def patch(self, name, ops):
        self._call(['--request-timeout=20s','patch','pod/'+name,'--type=json','-p',json.dumps(ops,separators=(',',':'))])

    def get_deployment(self, name):
        if name != self.namespace + '-redis':
            raise FinalizerError('KUBE_FINALIZER_ARGUMENT_INVALID')
        try:
            return json.loads(self._call(['--request-timeout=20s','get','deployment/'+name,'-o','json']))
        except (ValueError,UnicodeError):
            raise FinalizerError('KUBE_FINALIZER_API_UNCERTAIN') from None

    def patch_deployment(self, name, ops):
        if name != self.namespace + '-redis':
            raise FinalizerError('KUBE_FINALIZER_ARGUMENT_INVALID')
        self._call(['--request-timeout=20s','patch','deployment/'+name,'--type=json',
                    '-p',json.dumps(ops,separators=(',',':'))])


def _check_journal(directory, plan, operation, expected):
    if read_plan(directory)!=plan:
        raise FinalizerError('KUBE_FINALIZER_PLAN_MISMATCH')
    state=journal.read(directory)
    if (state['backend']!='kubernetes' or state['site']!=plan['namespace'] or state['resource']!=plan['uid']
            or state['operation']!=operation or state['plan_sha256']!=plan_hash(plan) or state['phase']!=expected):
        raise FinalizerError('KUBE_FINALIZER_JOURNAL_MISMATCH')
    return state


def _token(operation):
    if not isinstance(operation,str) or not re.fullmatch(r'[0-9a-f]{32}',operation):
        raise FinalizerError('KUBE_FINALIZER_OPERATION_INVALID')
    return 'uter.io/redis-fence-'+operation


def _verify_live(plan, pod, expected_finalizers, *, expect_original_rv=False):
    try:
        meta=pod['metadata'];state=pod['status'];statuses=state['containerStatuses'];spec=pod['spec']
        if (meta['name']!=plan['pod'] or meta['namespace']!=plan['namespace'] or meta['uid']!=plan['uid']
                or meta.get('deletionTimestamp') or meta.get('finalizers',[])!=expected_finalizers
                or not isinstance(meta['resourceVersion'],str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
                or (expect_original_rv and meta['resourceVersion']!=plan['resource_version'])
                or _digest(spec)!=plan['spec_sha256'] or state['phase']!='Running' or len(statuses)!=1):
            raise ValueError
        c=statuses[0]
        if (c['name']!='redis' or c['containerID']!=plan['container_id'] or type(c['restartCount']) is not int
                or c['restartCount']!=0 or not isinstance(c['state'].get('running'),dict)):
            raise ValueError
        return meta['resourceVersion']
    except (KeyError,TypeError,ValueError,IndexError):
        raise FinalizerError('KUBE_FINALIZER_STATE_CHANGED') from None


def hold(directory, plan, operation, api):
    """Hold our finalizer only. The result does not prove Redis isolation."""
    _validate_plan(plan);token=_token(operation);_check_journal(directory,plan,operation,'prepared')
    if api.context!=plan['context'] or api.namespace!=plan['namespace']:
        raise FinalizerError('KUBE_FINALIZER_CONTEXT_MISMATCH')
    _verify_live(plan,api.get(plan['pod']),[],expect_original_rv=True)
    # Durable intent precedes the only mutation. Any following exception leaves
    # the journal in isolating; the caller must not infer the mutation outcome.
    journal.advance(directory,operation=operation,expected='prepared',next_phase='isolating')
    ops=[{'op':'test','path':'/metadata/uid','value':plan['uid']},
         {'op':'test','path':'/metadata/resourceVersion','value':plan['resource_version']},
         {'op':'add','path':'/metadata/finalizers','value':[token]}]
    api.patch(plan['pod'],ops)
    _verify_live(plan,api.get(plan['pod']),[token])
    return {'result':'finalizer_held','redis_isolated':False}


def release_unchanged(directory, plan, operation, api):
    """Remove only our finalizer while the exact original Pod is still running.

    A terminating/restarted/changed Pod must be handled by a separate recovery
    procedure. Never mark the wider fence transaction restored here.
    """
    _validate_plan(plan);token=_token(operation);_check_journal(directory,plan,operation,'isolating')
    if api.context!=plan['context'] or api.namespace!=plan['namespace']:
        raise FinalizerError('KUBE_FINALIZER_CONTEXT_MISMATCH')
    rv=_verify_live(plan,api.get(plan['pod']),[token])
    journal.advance(directory,operation=operation,expected='isolating',next_phase='aborting')
    ops=[{'op':'test','path':'/metadata/uid','value':plan['uid']},
         {'op':'test','path':'/metadata/resourceVersion','value':rv},
         {'op':'test','path':'/metadata/finalizers','value':[token]},
         {'op':'remove','path':'/metadata/finalizers/0'}]
    api.patch(plan['pod'],ops)
    _verify_live(plan,api.get(plan['pod']),[])
    return {'result':'own_finalizer_removed','redis_isolated':False,'transaction_restored':False}
