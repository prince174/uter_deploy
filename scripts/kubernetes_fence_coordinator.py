"""Profile-bound Kubernetes session for a narrowly scoped fence coordinator.

This does not start a fence, create a backup or authorize an update. A profile
must be provided and independently verified by an administrator. The selected
control plane, nodes, admission/RBAC, CNI and CSI and privileged operators are
trusted; the profile and point-in-time checks do not establish those premises.
"""
from contextlib import ExitStack,contextmanager
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys

import uterctl
from scripts import (backup_installation, backup_snapshot, kubernetes_fence_pin as pin,
                     kubernetes_fence_profile_store as store,
                     kubernetes_pinned_preflight as preflight, kubernetes_sealed_config as sealed,
                     kubernetes_trusted_kubectl as kubectl_binary, redis_fence_journal as journal)


class CoordinatorError(ValueError):pass


def _executor_identity(bundle,key):
    """Authenticate the running isolated executor and all loaded local modules.

    A trusted launcher, interpreter, dependencies and protected bundle are
    prerequisites: code cannot authenticate itself before it starts executing.
    """
    if not sys.flags.isolated:raise CoordinatorError('KUBE_EXECUTOR_ISOLATION_REQUIRED')
    root=Path(bundle).resolve(strict=True);key=Path(key).resolve(strict=True)
    if root!=Path(uterctl.ROOT).resolve(strict=True):raise CoordinatorError('KUBE_EXECUTOR_ROOT_CHANGED')
    manifest=uterctl.verify(root,key)
    package=sys.modules.get('scripts')
    if package is None or tuple(getattr(package,'__path__',()))!=(str(root/'scripts'),):
        raise CoordinatorError('KUBE_EXECUTOR_MODULE_UNTRUSTED')
    for name,module in tuple(sys.modules.items()):
        if name=='uterctl':expected=root/'uterctl.py'
        elif name.startswith('scripts.'):
            expected=root/'scripts'/(name.split('.',1)[1].replace('.','/')+'.py')
        else:continue
        actual=getattr(module,'__file__',None)
        if not actual or Path(actual).resolve(strict=True)!=expected.resolve(strict=True):
            raise CoordinatorError('KUBE_EXECUTOR_MODULE_UNTRUSTED')
    return (manifest,hashlib.sha256(backup_installation.safe_file(root/'checksums.json',limit=1024*1024)).hexdigest(),
            hashlib.sha256(backup_installation.safe_file(key,limit=65536)).hexdigest())


def _pod_name(site,name):
    return (isinstance(name,str) and re.fullmatch(re.escape(site)+r'-(?:redis|guardrail|agent)-[a-z0-9-]{1,64}',name) is not None)


def _query_allowed(site,args):
    if not isinstance(args,list) or not all(isinstance(x,str) for x in args):return False
    if args in (['get','namespace','kube-system'],['get','namespace',site],['get','pvc',site+'-redis'],
                ['get','pvc',site+'-guardrail']):return True
    if len(args)==3 and args[:2]==['get','deployment'] and args[2] in tuple(site+'-'+x for x in ('redis','guardrail','agent')):return True
    if len(args)==3 and args[:2]==['get','pod'] and _pod_name(site,args[2]):return True
    if (len(args)==3 and args[:2]==['get','replicaset']
            and re.fullmatch(re.escape(site)+r'-(?:redis|guardrail|agent)-[a-z0-9]{1,32}',args[2])):return True
    if len(args)==4 and args[:3]==['get','pods','-l']:
        return args[3] in tuple('app.kubernetes.io/instance='+site+',app.kubernetes.io/name='+x
                                for x in ('redis','guardrail','agent'))
    return False


def _base_tests(ops):
    if not isinstance(ops,list) or len(ops) not in (3,4):return False
    first,second=ops[:2]
    return (isinstance(first,dict) and set(first)=={'op','path','value'} and first['op']=='test'
            and first['path']=='/metadata/uid' and isinstance(first['value'],str) and pin.identity.UUID.fullmatch(first['value'])
            and isinstance(second,dict) and set(second)=={'op','path','value'} and second['op']=='test'
            and second['path']=='/metadata/resourceVersion' and isinstance(second['value'],str)
            and re.fullmatch(r'[0-9]{1,32}',second['value']) is not None)


def _pod_patch_allowed(site,name,ops):
    if not _pod_name(site,name) or not _base_tests(ops):return False
    service=next((x for x in ('redis','guardrail','agent') if name.startswith(site+'-'+x+'-')),None)
    if len(ops)==3:
        item=ops[2]
        if not isinstance(item,dict) or set(item)!={'op','path','value'} or item['op']!='add' or item['path']!='/metadata/finalizers':return False
        value=item['value']
    else:
        item,last=ops[2:]
        if (not isinstance(item,dict) or set(item)!={'op','path','value'} or item['op']!='test'
                or item['path']!='/metadata/finalizers' or last!={'op':'remove','path':'/metadata/finalizers/0'}):return False
        value=item['value']
    if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],str):return False
    if service=='redis':return re.fullmatch(r'uter\.io/redis-fence-[0-9a-f]{32}',value[0]) is not None
    return re.fullmatch(r'uter\.io/writer-fence-[0-9a-f]{32}-'+service,value[0]) is not None


def _deployment_patch_allowed(site,name,ops):
    if not _base_tests(ops) or len(ops)!=4:return False
    third,fourth=ops[2:]
    if not isinstance(third,dict) or not isinstance(fourth,dict):return False
    if name in (site+'-guardrail',site+'-agent'):
        return (type(third.get('value')) is int and type(fourth.get('value')) is int
                and third=={'op':'test','path':'/spec/replicas','value':1}
                and fourth=={'op':'replace','path':'/spec/replicas','value':0})
    if name!=site+'-redis':return False
    from scripts import kubernetes_redis_identity as redis_identity
    original=[redis_identity.COMMAND];loopback=[redis_identity.COMMAND+' --bind 127.0.0.1']
    path='/spec/template/spec/containers/0/args'
    return ((third=={'op':'test','path':path,'value':original} and fourth=={'op':'replace','path':path,'value':loopback})
            or (third=={'op':'test','path':path,'value':loopback} and fourth=={'op':'replace','path':path,'value':original}))


class _BoundAPI:
    """Recheck the signed operator profile around every selected API request."""
    def __init__(self,owner,api):
        self.owner=owner;self._api=api;self.context=api.context;self.namespace=api.namespace

    def _invoke(self,name,*args,authorization=None):
        self.owner._scope()
        if authorization is not None:
            self.owner._authorize(*authorization)
            self.owner._scope()  # Validate any lazily imported modules before mutation.
        value=getattr(self._api,name)(*args)
        self.owner._scope()  # Unknown result if the identity changed during a request.
        return value

    def _call(self,args):
        if (not isinstance(args,list) or len(args)<4 or args[0]!='--request-timeout=20s'):
            raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        if args[-2:]==['-o','json'] and _query_allowed(self.namespace,args[1:-2]):
            return self._invoke('_call',args)
        try:
            if len(args)!=6 or args[1]!='patch' or args[3:5]!=['--type=json','-p']:raise ValueError
            kind,separator,name=args[2].partition('/')
            ops=json.loads(args[5])
            if not separator or not ((kind=='pod' and _pod_patch_allowed(self.namespace,name,ops))
                    or (kind=='deployment' and _deployment_patch_allowed(self.namespace,name,ops))):raise ValueError
        except (ValueError,TypeError,AttributeError):raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED') from None
        return self._invoke('_call',args,authorization=(kind,name,ops))

    def get(self,name):
        if not _pod_name(self.namespace,name):raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        return self._invoke('get',name)
    def patch(self,name,ops):
        if not _pod_patch_allowed(self.namespace,name,ops):raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        return self._invoke('patch',name,ops,authorization=('pod',name,ops))
    def get_deployment(self,name):
        if name!=self.namespace+'-redis':raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        return self._invoke('get_deployment',name)
    def patch_deployment(self,name,ops):
        if not _deployment_patch_allowed(self.namespace,name,ops):raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        return self._invoke('patch_deployment',name,ops,authorization=('deployment',name,ops))


class BoundSession:
    """Pinned session, not a Redis fence or a backup capability."""
    def __init__(self,inner,profile_path,key_path,record,digest,key_digest,executor=None):
        self._inner=inner;self._profile_path=profile_path;self._key_path=key_path
        self._record=copy.deepcopy(record);self._profile_digest=digest;self._key_digest=key_digest
        self.home=inner.home;self.site=inner.site;self.manifest=copy.deepcopy(inner.manifest)
        self.profile=copy.deepcopy(inner.profile);self.inventory_digest=inner.inventory_digest
        self.config_sha256=inner.config_sha256;self.key_digest=inner.key_digest
        self.writer_uids=copy.deepcopy(record['writer_uids']);self.api=_BoundAPI(self,inner.api)
        self._executor=executor

    def _guard(self):
        try:
            backup_snapshot._require_legacy_operation_lock(self.home)
            sealed.verify_sealed(self._inner.config_fd,self.config_sha256)
            raw=backup_installation.safe_file(self._key_path,private=True,limit=32)
            if len(raw)!=32 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),self._key_digest):raise ValueError
            current,digest=store.read(self._profile_path,raw)
            if not hmac.compare_digest(digest,self._profile_digest) or current!=self._record:raise ValueError
            if (self._inner.profile!=self.profile or self._inner.manifest!=self.manifest
                    or self._inner.inventory_digest!=self.inventory_digest or self._inner.key_digest!=self.key_digest
                    or self._inner.config_sha256!=self.config_sha256):raise ValueError
            if (hashlib.sha256(backup_installation.safe_file(self._inner.publisher_key,limit=65536)).hexdigest()!=self.key_digest
                    or hashlib.sha256(backup_installation.safe_file(self._inner.bundle/'checksums.json',limit=1024*1024)).hexdigest()!=self.inventory_digest
                    or uterctl.verify(self._inner.bundle,self._inner.publisher_key)!=self.manifest):raise ValueError
            if self._executor is not None:
                root,key,identity=self._executor
                if _executor_identity(root,key)!=identity:raise ValueError
                api=self._inner.api
                if api.binary_sha256!=self._record['kubectl_sha256']:raise ValueError
                kubectl_binary.verify(api.binary_fd,api.binary_sha256)
        except Exception:raise CoordinatorError('KUBE_OPERATOR_PROFILE_CHANGED') from None

    def _scope(self):
        """Compare live pinned namespace/PVC/Deployment around a request."""
        try:
            self._guard()
            system=self._inner._query(['get','namespace','kube-system'])
            namespace=self._inner._query(['get','namespace',self.site])
            pvc=self._inner._query(['get','pvc',self.site+'-redis'])
            deployment=self._inner._query(['get','deployment',self.site+'-redis'])
            if namespace.get('metadata',{}).get('name')!=self.site:raise ValueError
            pin.verify_resources(self.profile,kube_system=system,namespace=namespace,pvc=pvc,deployment=deployment)
            if self._record['schema']==2:
                audit=self._inner._query(['get','pvc',self.site+'-guardrail'])
                if (audit.get('kind')!='PersistentVolumeClaim'
                        or audit.get('metadata',{}).get('name')!=self.site+'-guardrail'
                        or audit.get('metadata',{}).get('namespace')!=self.site
                        or audit.get('metadata',{}).get('uid')!=self._record['audit_pvc_uid']
                        or audit.get('metadata',{}).get('deletionTimestamp')
                        or audit.get('status',{}).get('phase')!='Bound'):raise ValueError
            self._guard()
        except Exception:raise CoordinatorError('KUBE_OPERATOR_SCOPE_UNVERIFIED') from None

    def _authorize(self,kind,name,ops):
        """Require an exact durable write-ahead marker for any mutation."""
        try:
            if self._executor is None:raise ValueError
            if self._record['schema']!=2:raise ValueError
            state=journal.read(self.home);operation=state['operation']
            if state['backend']!='kubernetes' or state['site']!=self.site:raise ValueError
            uid=ops[0]['value']
            if kind=='deployment' and name in (self.site+'-guardrail',self.site+'-agent'):
                from scripts import kubernetes_writer_quiesce as writers
                service=name.rsplit('-',1)[1]
                key=backup_installation.safe_file(self._key_path,private=True,limit=32)
                plan=writers._bound(self.home,self,operation,key);entry=plan['writers'][service]
                marker=writers._read(self.home,'kubernetes-writer-'+service+'-attempt.json',key)
                if (uid!=self.writer_uids[service] or uid!=entry['uid'] or ops[1]['value']!=entry['rv']
                        or marker!={'schema':1,'operation':operation,'service':service,'plan_sha256':writers._hash(plan)}):
                    raise ValueError
                return
            if kind=='pod' and name.startswith(self.site+'-redis-'):
                from scripts import kubernetes_fence_finalizer as finalizer
                plan=finalizer.read_plan(self.home)
                finalizer._check_journal(self.home,plan,operation,'isolating')
                if name!=plan['pod'] or uid!=plan['uid'] or ops[2].get('value')!=[finalizer._token(operation)]:raise ValueError
                if len(ops)==3:
                    if ops[1]['value']!=plan['resource_version']:raise ValueError
                else:
                    from scripts import kubernetes_redis_finalizer_release as redis_release
                    from scripts import kubernetes_writer_quiesce as writers
                    key=backup_installation.safe_file(self._key_path,private=True,limit=32)
                    marker=writers._read(self.home,redis_release.MARKER,key)
                    if marker!={'operation':operation,'pod_plan_sha256':finalizer.plan_hash(plan),
                               'resource_version':ops[1]['value']}:raise ValueError
                return
            if kind=='pod':
                from scripts import kubernetes_writer_finalizer as writer
                from scripts import kubernetes_writer_quiesce as writers
                service=next(x for x in writers.SERVICES if name.startswith(self.site+'-'+x+'-'))
                key=backup_installation.safe_file(self._key_path,private=True,limit=32)
                record,_=writer._record(self.home,self,operation,service,key)
                if (name!=record['pod'] or uid!=record['uid']
                        or ops[2].get('value')!=[writer._token(operation,service)]):raise ValueError
                if len(ops)==3 and ops[1]['value']!=record['rv']:raise ValueError
                digest=writers._hash(record)
                marker=('kubernetes-writer-hold-'+service+'-attempt.json' if len(ops)==3
                        else 'kubernetes-writer-release-'+service+'-attempt.json')
                if writers._read(self.home,marker,key)!={'operation':operation,'pod_plan_sha256':digest}:raise ValueError
                if len(ops)==4:
                    observed=writers._read(self.home,'kubernetes-writer-observed-'+service+'.json',key)
                    if (observed.get('operation')!=operation or observed.get('pod_plan_sha256')!=digest
                            or observed.get('resource_version')!=ops[1]['value']):raise ValueError
                return
            if kind=='deployment' and name==self.site+'-redis':
                if state['phase']!='isolating' or uid!=self.profile['redis_deployment_uid']:raise ValueError
                path=ops[2]['value']
                from scripts import kubernetes_loopback_intent as forward
                from scripts import kubernetes_fence_finalizer as finalizer
                plan=finalizer.read_plan(self.home)
                forward._bound(self.home,plan,operation,self.api)
                if path==[forward.identity.COMMAND]:
                    record=forward._read(self.home)
                    marker=json.loads(backup_installation.safe_file(self.home/forward.ATTEMPT_NAME,private=True,limit=4096))
                    if (record['operation']!=operation or record['uid']!=uid or record['original_rv']!=ops[1]['value']
                            or marker!={'operation':operation,'intent_sha256':forward._hash(record)}):raise ValueError
                else:
                    from scripts import kubernetes_loopback_recovery as recovery
                    record,_=recovery._record(self.home,plan,operation,self.api)
                    marker=json.loads(backup_installation.safe_file(self.home/recovery.ATTEMPT_NAME,private=True,limit=4096))
                    if (record['uid']!=uid or record['resource_version']!=ops[1]['value']
                            or marker!={'operation':operation,'intent_sha256':forward._hash(record)}):raise ValueError
                return
            raise ValueError
        except Exception:raise CoordinatorError('KUBE_OPERATOR_MUTATION_UNAUTHORIZED') from None

    def _query(self,args):
        if not _query_allowed(self.site,args):raise CoordinatorError('KUBE_OPERATOR_REQUEST_REJECTED')
        self._guard();value=self._inner._query(args);self._guard();return value

    def reverify(self):
        self._guard();value=self._inner.reverify();self._guard();return value


@contextmanager
def checked_session(home,bundle,publisher_key,kubeconfig_path,profile_path,backup_key_path,*,executor_bundle=None,
                    executor_key=None,kubectl_path=None):
    """Establish a profile-bound, sealed API connection under an existing lock.

    Configuration, pin and backup key must be separate trusted private files;
    no credential is printed or written to a temporary file. An absent or
    changed profile never permits any cluster mutation. The calling coordinator
    must still establish the actual Redis fence and independently verify data.
    """
    try:
        home=backup_installation.private_directory(home)
        config=backup_installation.checked_existing_path(kubeconfig_path)
        profile=backup_installation.checked_existing_path(profile_path)
        key_path=backup_installation.checked_existing_path(backup_key_path)
        publisher=backup_installation.checked_existing_path(publisher_key)
        signed_bundle=Path(bundle).resolve(strict=True)
        if (len({config,profile,key_path,publisher})!=4
                or any(x.is_relative_to(home) or x.is_relative_to(signed_bundle) for x in (config,profile,key_path))):
            raise ValueError
        key=backup_installation.safe_file(key_path,private=True,limit=32)
        if len(key)!=32:raise ValueError
        raw=backup_installation.safe_file(config,private=True,limit=pin.MAX_CONFIG)
        record,digest=store.read(profile,key)
        key_digest=hashlib.sha256(key).hexdigest()
        if (executor_bundle is None)!=(executor_key is None):raise ValueError
        executor=None
        if executor_bundle is not None:
            if record['schema']!=2 or kubectl_path is None:raise ValueError
            executor_root=Path(executor_bundle).resolve(strict=True)
            executor_key_path=backup_installation.checked_existing_path(executor_key)
            if executor_key_path in (config,profile,key_path) or executor_key_path.is_relative_to(home):raise ValueError
            executor=(executor_root,executor_key_path,_executor_identity(executor_root,executor_key_path))
    except Exception:raise CoordinatorError('KUBE_OPERATOR_PROFILE_UNVERIFIED') from None
    with ExitStack() as stack:
        try:
            if executor is None:
                if kubectl_path is not None:raise ValueError
                inner=stack.enter_context(preflight.checked_session(home,bundle,publisher_key,raw,record['api']))
            else:
                binary_fd=kubectl_binary.open_binary(kubectl_path,record['kubectl_sha256'])
                stack.callback(os.close,binary_fd)
                inner=stack.enter_context(preflight.checked_session(home,bundle,publisher_key,raw,record['api'],
                    binary_fd=binary_fd,binary_sha256=record['kubectl_sha256']))
            if (inner.site!=record['site'] or inner.manifest.get('version')!=record['release_version']
                    or inner.inventory_digest!=record['inventory_sha256'] or inner.key_digest!=record['publisher_sha256']):
                raise ValueError
            session=BoundSession(inner,profile,key_path,record,digest,key_digest,executor)
            session.reverify()
        except CoordinatorError:raise
        except Exception:raise CoordinatorError('KUBE_OPERATOR_SESSION_UNVERIFIED') from None
        yield session
