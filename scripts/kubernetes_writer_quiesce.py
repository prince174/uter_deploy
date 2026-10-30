"""Experimental one-shot Kubernetes writer quiescence under a pinned session.

The supplied writer UIDs must have been independently provisioned by a trusted
administrator. Cluster administrators, nodes, CNI/CSI and all actors able to
exec, rescale or alter pods remain trusted. Stopping these two Deployments does
not exclude external writers, is not a Redis fence, and cannot authorize backup,
release or update. Any uncertain result retains the journal and marker.
"""
import copy
import hashlib
import hmac
import json
import os
import re
import stat

from scripts import backup_crypto, kubernetes_fence_finalizer as finalizer
from scripts import kubernetes_redis_identity as identity, redis_fence_journal as journal

NAME='kubernetes-writer-plan.json'
MAX_BYTES=8192
SERVICES=('guardrail','agent')


class QuiesceError(ValueError):pass


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def _hash(value):return hashlib.sha256(_canonical(value)).hexdigest()


def _key(key):
    if not isinstance(key,bytes) or len(key)!=32:raise QuiesceError('KUBE_WRITER_KEY_INVALID')
    return backup_crypto.derive_key(key,b'kubernetes-writer-quiesce-v1')


def _write(home,name,record,key):
    envelope={'record':record,'mac':hmac.new(_key(key),_canonical(record),hashlib.sha256).hexdigest()}
    raw=_canonical(envelope)+b'\n'
    if len(raw)>MAX_BYTES:raise QuiesceError('KUBE_WRITER_RECORD_INVALID')
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:
                os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
        except OSError:raise QuiesceError('KUBE_WRITER_WRITE_UNCERTAIN') from None
    finally:os.close(directory)


def _read(home,name,key):
    directory=journal._directory(home)
    try:
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077
                        or info.st_nlink!=1 or info.st_size>MAX_BYTES):raise ValueError
                raw=stream.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise ValueError
            value=json.loads(raw)
            if not isinstance(value,dict) or set(value)!={'record','mac'} or not isinstance(value['record'],dict):raise ValueError
            expected=hmac.new(_key(key),_canonical(value['record']),hashlib.sha256).hexdigest()
            if not isinstance(value['mac'],str) or not hmac.compare_digest(value['mac'],expected):raise ValueError
            return value['record']
        except QuiesceError:raise
        except (OSError,ValueError,UnicodeError,TypeError):raise QuiesceError('KUBE_WRITER_RECORD_UNVERIFIED') from None
    finally:os.close(directory)


def _deployment(session,service,pinned_uid):
    try:
        if service not in SERVICES or not isinstance(pinned_uid,str) or not identity.UUID.fullmatch(pinned_uid):raise ValueError
        value=session._query(['get','deployment',session.site+'-'+service])
        meta=value['metadata'];spec=value['spec'];template=spec['template'];pod=template['spec']
        labels={'app.kubernetes.io/instance':session.site,'app.kubernetes.io/name':service}
        if (value.get('kind')!='Deployment' or meta.get('name')!=session.site+'-'+service
                or meta.get('namespace')!=session.site or meta.get('uid')!=pinned_uid or meta.get('deletionTimestamp')
                or not isinstance(meta.get('resourceVersion'),str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
                or type(spec.get('replicas')) is not int or spec['replicas'] not in (0,1)
                or spec.get('strategy',{}).get('type')!='Recreate'
                or spec.get('selector',{}).get('matchLabels')!=labels
                or any(template.get('metadata',{}).get('labels',{}).get(k)!=v for k,v in labels.items())
                or pod.get('hostNetwork',False) is not False or pod.get('hostPID',False) is not False
                or pod.get('hostIPC',False) is not False or pod.get('automountServiceAccountToken') is not False
                or pod.get('initContainers') not in (None,[]) or pod.get('ephemeralContainers') not in (None,[])):
            raise ValueError
        containers=pod['containers']
        if (not isinstance(containers,list) or len(containers)!=1 or containers[0].get('name')!=service
                or containers[0].get('image')!=session.manifest['images'][service]):raise ValueError
        return meta,spec
    except Exception:raise QuiesceError('KUBE_WRITER_DEPLOYMENT_UNVERIFIED') from None


def prepare(home,session,operation,writer_uids,key):
    """Bind an authenticated writer plan to an already prepared Redis journal."""
    try:
        session.reverify()
        rec=journal.read(home)
        pod_plan=finalizer.read_plan(home)
        finalizer._check_journal(home,pod_plan,operation,'prepared')
        if (rec['backend']!='kubernetes' or rec['phase']!='prepared' or rec['operation']!=operation
                or rec['site']!=session.site or not isinstance(writer_uids,dict) or set(writer_uids)!=set(SERVICES)
                or len(set(writer_uids.values()))!=2 or pod_plan['context']!=session.api.context
                or pod_plan['namespace']!=session.site):raise ValueError
        finalizer._verify_live(pod_plan,session.api.get(pod_plan['pod']),[],expect_original_rv=True)
        plan={'schema':1,'operation':operation,'site':session.site,'context':session.api.context,
              'redis_plan_sha256':rec['plan_sha256'],'redis_uid':rec['resource'],
              'manifest_sha256':_hash(session.manifest),'profile_sha256':_hash(session.profile),
              'inventory_sha256':session.inventory_digest,'config_sha256':session.config_sha256,
              'key_sha256':session.key_digest,'writers':{}}
        for service in SERVICES:
            meta,spec=_deployment(session,service,writer_uids[service])
            if spec['replicas']!=1:raise ValueError
            stopped=copy.deepcopy(spec);stopped['replicas']=0
            plan['writers'][service]={'uid':writer_uids[service],'rv':meta['resourceVersion'],
                                      'before':_hash(spec),'stopped':_hash(stopped)}
        session.reverify()
        _write(home,NAME,plan,key)
        return {'result':'writer_plan_recorded','redis_isolated':False,'safe_to_update':False}
    except QuiesceError:raise
    except Exception:raise QuiesceError('KUBE_WRITER_PREPARE_UNVERIFIED') from None


def _bound(home,session,operation,key):
    plan=_read(home,NAME,key)
    try:
        rec=journal.read(home)
        pod_plan=finalizer.read_plan(home)
        finalizer._check_journal(home,pod_plan,operation,'prepared')
        if (set(plan)!={'schema','operation','site','context','redis_plan_sha256','redis_uid','writers',
                       'manifest_sha256','profile_sha256','inventory_sha256','config_sha256','key_sha256'}
                or type(plan['schema']) is not int or plan['schema']!=1 or plan['operation']!=operation
                or plan['site']!=session.site or plan['context']!=session.api.context
                or pod_plan['context']!=session.api.context or pod_plan['namespace']!=session.site
                or rec['backend']!='kubernetes' or rec['phase']!='prepared' or rec['operation']!=operation
                or rec['plan_sha256']!=plan['redis_plan_sha256'] or rec['resource']!=plan['redis_uid']
                or plan['manifest_sha256']!=_hash(session.manifest) or plan['profile_sha256']!=_hash(session.profile)
                or plan['inventory_sha256']!=session.inventory_digest or plan['config_sha256']!=session.config_sha256
                or plan['key_sha256']!=session.key_digest
                or not isinstance(plan['writers'],dict) or set(plan['writers'])!=set(SERVICES)):
            raise ValueError
        for service in SERVICES:
            entry=plan['writers'][service]
            if (not isinstance(entry,dict) or set(entry)!={'uid','rv','before','stopped'}
                    or not isinstance(entry['uid'],str) or not identity.UUID.fullmatch(entry['uid'])
                    or not isinstance(entry['rv'],str) or not re.fullmatch(r'[0-9]{1,32}',entry['rv'])
                    or any(not isinstance(entry[k],str) or not re.fullmatch(r'[0-9a-f]{64}',entry[k]) for k in ('before','stopped'))):
                raise ValueError
        return plan
    except (ValueError,KeyError,TypeError):raise QuiesceError('KUBE_WRITER_PLAN_UNVERIFIED') from None


def classify(home,session,operation,service,key):
    """Observe a writer's deployment only, never infer a Redis fence."""
    plan=_bound(home,session,operation,key)
    if service not in SERVICES:raise QuiesceError('KUBE_WRITER_SERVICE_INVALID')
    try:
        session.reverify();entry=plan['writers'][service];meta,spec=_deployment(session,service,entry['uid'])
        digest=_hash(spec)
        if digest==entry['before'] and meta['resourceVersion']==entry['rv']:state='running_spec_observed'
        elif digest==entry['stopped']:state='stopped_spec_observed'
        else:raise ValueError
        return {'state':state,'writers_quiesced':False,'redis_isolated':False,'safe_to_update':False}
    except Exception:raise QuiesceError('KUBE_WRITER_RESULT_UNCERTAIN') from None


def stop(home,session,operation,service,key):
    """Issue at most one exact UID/RV/replicas guarded scale-to-zero PATCH."""
    plan=_bound(home,session,operation,key)
    if service not in SERVICES:raise QuiesceError('KUBE_WRITER_SERVICE_INVALID')
    try:
        marker='kubernetes-writer-'+service+'-attempt.json'
        if os.path.lexists(os.path.join(home,marker)):raise ValueError
        if classify(home,session,operation,service,key)['state']!='running_spec_observed':raise ValueError
        from scripts import kubernetes_writer_finalizer
        kubernetes_writer_finalizer.assert_held(home,session,operation,service,key)
        entry=plan['writers'][service]
        _write(home,marker,{'schema':1,'operation':operation,'service':service,'plan_sha256':_hash(plan)},key)
        ops=[{'op':'test','path':'/metadata/uid','value':entry['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':entry['rv']},
             {'op':'test','path':'/spec/replicas','value':1},
             {'op':'replace','path':'/spec/replicas','value':0}]
        session.api._call(['--request-timeout=20s','patch','deployment/'+session.site+'-'+service,
                           '--type=json','-p',json.dumps(ops,separators=(',',':'))])
        if classify(home,session,operation,service,key)['state']!='stopped_spec_observed':raise ValueError
    except Exception:raise QuiesceError('KUBE_WRITER_STOP_UNCERTAIN') from None
    return {'state':'stopped_spec_observed','writers_quiesced':False,'redis_isolated':False,'safe_to_update':False}


def observe_stopped(home,session,operation,key):
    """Point-in-time observation only; never a continuous exclusion proof."""
    _bound(home,session,operation,key)
    try:
        from scripts import kubernetes_writer_finalizer
        for service in SERVICES:
            if classify(home,session,operation,service,key)['state']!='stopped_spec_observed':raise ValueError
            pod_plan,_=kubernetes_writer_finalizer._record(home,session,operation,service,key)
            observed=_read(home,'kubernetes-writer-observed-'+service+'.json',key)
            released=_read(home,'kubernetes-writer-release-'+service+'-attempt.json',key)
            digest=_hash(pod_plan)
            if (set(observed)!={'operation','pod_plan_sha256','resource_version'}
                    or observed['operation']!=operation or observed['pod_plan_sha256']!=digest
                    or not isinstance(observed['resource_version'],str)
                    or not re.fullmatch(r'[0-9]{1,32}',observed['resource_version'])
                    or released!={'operation':operation,'pod_plan_sha256':digest}):raise ValueError
            deployment=session._query(['get','deployment',session.site+'-'+service])
            generation=deployment['metadata']['generation'];status=deployment.get('status',{})
            if (type(generation) is not int or status.get('observedGeneration')!=generation
                    or any(type(status.get(field,0)) is not int or status.get(field,0)!=0
                           for field in ('replicas','readyReplicas','availableReplicas','updatedReplicas'))):raise ValueError
            labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name='+service
            pods=session._query(['get','pods','-l',labels])['items']
            if not isinstance(pods,list) or pods:raise ValueError
        session.reverify()
        return {'writers_stopped_observed':True,'continuous_exclusion':False,
                'old_writer_termination_observed':True,'unforced_deletion_verified':False,'audit_durability_verified':False,
                'redis_isolated':False,'safe_to_backup':False,'safe_to_update':False}
    except Exception:raise QuiesceError('KUBE_WRITERS_NOT_QUIESCED') from None
