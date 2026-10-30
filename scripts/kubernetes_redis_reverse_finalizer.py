"""Experimental one-shot finalizer on the current isolated Redis Pod.

This is a conservative building block for reverse rollout, not writer-resume or
data/durability proof. A failed or timed-out mutation is never retried.
"""
import hmac
import re

from scripts import (backup_installation, kubernetes_backup_coordinator as backup,
                     kubernetes_fence_finalizer as original, kubernetes_loopback_snapshot as loopback,
                     kubernetes_redis_identity as identity, kubernetes_writer_quiesce as storage,
                     redis_fence_journal as journal)

PLAN='kubernetes-redis-reverse-pod.json'
HOLD='kubernetes-redis-reverse-hold-attempt.json'
RELEASE='kubernetes-redis-reverse-release-attempt.json'
OBSERVED='kubernetes-redis-reverse-termination.json'


class ReverseFinalizerError(ValueError):pass


def _token(operation):
    if not isinstance(operation,str) or not re.fullmatch(r'[0-9a-f]{32}',operation):raise ValueError
    return 'uter.io/redis-fence-'+operation


def _record(session,operation,key):
    value=storage._read(session.home,PLAN,key);state=journal.read(session.home)
    receipt=storage._read(session.home,backup.RECEIPT,key)
    fields={'schema','operation','site','pod','uid','rv','container_id','spec_sha256',
            'profile_sha256','receipt_sha256','old_uid'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or value['operation']!=operation or state['phase']!='isolating' or state['operation']!=operation
            or value['site']!=session.site or value['old_uid']!=state['resource']
            or value['profile_sha256']!=session._profile_digest or value['receipt_sha256']!=storage._hash(receipt)
            or not re.fullmatch(re.escape(session.site)+r'-redis-[a-z0-9-]{1,64}',value['pod'])
            or not identity.UUID.fullmatch(value['uid']) or value['uid']==value['old_uid']
            or not re.fullmatch(r'[0-9]{1,32}',value['rv'])
            or not re.fullmatch(r'(?:containerd|cri-o|docker)://[0-9a-f]{64}',value['container_id'])
            or not re.fullmatch(r'[0-9a-f]{64}',value['spec_sha256'])):raise ValueError
    return value


def prepare(session,operation,pod_name,pod_uid,destination,key):
    """Record exact loopback Pod after strict backup receipt verification."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if not hmac.compare_digest(backup_installation.safe_file(session._key_path,private=True,limit=32),key):raise ValueError
        backup.verify_receipt(session,operation,pod_name,pod_uid,destination)
        observed=loopback._observe(session,operation,pod_name,pod_uid)
        pod=session._query(['get','pod',pod_name]);meta=pod['metadata'];status=pod['status']['containerStatuses'][0]
        if (meta['uid']!=pod_uid or meta.get('deletionTimestamp') or meta.get('finalizers',[])!=[]
                or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
                or original._digest(pod['spec'])!=observed['pod_spec_sha256']
                or status['containerID']!=observed['container_id']):raise ValueError
        state=journal.read(session.home);receipt=storage._read(session.home,backup.RECEIPT,key)
        value={'schema':1,'operation':operation,'site':session.site,'pod':pod_name,'uid':pod_uid,
               'rv':meta['resourceVersion'],'container_id':status['containerID'],'spec_sha256':observed['pod_spec_sha256'],
               'profile_sha256':session._profile_digest,'receipt_sha256':storage._hash(receipt),'old_uid':state['resource']}
        storage._write(session.home,PLAN,value,key)
        if _record(session,operation,key)!=value:raise ValueError
        return {'reverse_pod_plan_saved':True,'safe_to_resume':False}
    except Exception:raise ReverseFinalizerError('KUBE_REVERSE_POD_PLAN_UNVERIFIED') from None


def _pod(session,record,operation,*,held,terminated):
    pod=session.api.get(record['pod']);meta=pod['metadata'];state=pod['status'];items=state['containerStatuses']
    token=_token(operation)
    if (pod.get('kind')!='Pod' or meta.get('name')!=record['pod'] or meta.get('namespace')!=session.site or meta.get('uid')!=record['uid']
            or meta.get('finalizers',[])!=([token] if held else [])
            or not isinstance(meta.get('resourceVersion'),str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
            or original._digest(pod['spec'])!=record['spec_sha256'] or not isinstance(items,list) or len(items)!=1):raise ValueError
    container=items[0]
    if (container.get('name')!='redis' or container.get('containerID')!=record['container_id']
            or type(container.get('restartCount')) is not int or container['restartCount']!=0
            or container.get('lastState',{}) not in ({},None)):raise ValueError
    if terminated:
        t=container.get('state',{}).get('terminated')
        if (not isinstance(meta.get('deletionTimestamp'),str) or not meta['deletionTimestamp']
                or not isinstance(t,dict) or type(t.get('exitCode')) is not int or t['exitCode']!=0
                or type(t.get('signal',0)) is not int or t.get('signal',0)!=0 or t.get('reason')!='Completed'
                or state.get('phase') not in ('Running','Succeeded')):raise ValueError
    elif (meta.get('deletionTimestamp') or state.get('phase')!='Running' or container.get('ready') is not True
          or not isinstance(container.get('state',{}).get('running'),dict)):raise ValueError
    return meta['resourceVersion']


def hold(session,operation,key):
    try:
        session._scope();record=_record(session,operation,key)
        loopback._observe(session,operation,record['pod'],record['uid'])
        rv=_pod(session,record,operation,held=False,terminated=False)
        if rv!=record['rv']:raise ValueError
        storage._write(session.home,HOLD,{'operation':operation,'plan_sha256':storage._hash(record)},key)
        ops=[{'op':'test','path':'/metadata/uid','value':record['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':rv},
             {'op':'add','path':'/metadata/finalizers','value':[_token(operation)]}]
        session.api.patch(record['pod'],ops)
        _pod(session,record,operation,held=True,terminated=False)
        return {'reverse_finalizer_held':True,'safe_to_resume':False}
    except Exception:raise ReverseFinalizerError('KUBE_REVERSE_HOLD_UNCERTAIN') from None


def observe(session,operation,key):
    try:
        session._scope();record=_record(session,operation,key)
        rv=_pod(session,record,operation,held=True,terminated=True)
        return {'termination_observed':True,'resource_version':rv,'aof_durable':False,'safe_to_resume':False}
    except Exception:raise ReverseFinalizerError('KUBE_REVERSE_TERMINATION_UNVERIFIED') from None


def release(session,operation,key):
    try:
        record=_record(session,operation,key);result=observe(session,operation,key);rv=result['resource_version']
        digest=storage._hash(record)
        storage._write(session.home,OBSERVED,{'operation':operation,'plan_sha256':digest,'rv':rv},key)
        storage._write(session.home,RELEASE,{'operation':operation,'plan_sha256':digest},key)
        ops=[{'op':'test','path':'/metadata/uid','value':record['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':rv},
             {'op':'test','path':'/metadata/finalizers','value':[_token(operation)]},
             {'op':'remove','path':'/metadata/finalizers/0'}]
        session.api.patch(record['pod'],ops)
        return {'reverse_finalizer_release_requested':True,'safe_to_resume':False}
    except Exception:raise ReverseFinalizerError('KUBE_REVERSE_RELEASE_UNCERTAIN') from None
