"""One-shot writer Pod finalizers and termination observation, not a fence.

Only the strict pinned-session quiescence experiment may call this code. A
zero-exit observation does not prove audit-file fsync or CSI durability. Any
ambiguous request leaves its marker and finalizer for inspection; there is no
automatic replay or authorization to capture data or update.
"""
import json
import re

from scripts import kubernetes_fence_finalizer as common
from scripts import kubernetes_writer_quiesce as writers
from scripts import kubernetes_redis_identity as identity


class WriterFinalizerError(ValueError):
    def __init__(self,code,stage='UNVERIFIED'):
        super().__init__(code);self.stage=stage


def _name(service):
    if service not in writers.SERVICES:raise WriterFinalizerError('KUBE_WRITER_FINALIZER_SERVICE')
    return 'kubernetes-writer-pod-'+service+'.json'


def _token(operation,service):
    if not isinstance(operation,str) or not re.fullmatch(r'[0-9a-f]{32}',operation):
        raise WriterFinalizerError('KUBE_WRITER_FINALIZER_OPERATION')
    _name(service)
    return 'uter.io/writer-fence-'+operation+'-'+service


def _pod(session,record,expected_finalizers,*,deleting=None,original_rv=False,terminated=False):
    stage='POD_FETCH'
    try:
        pod=session._query(['get','pod',record['pod']]);meta=pod['metadata'];status=pod['status']
        statuses=status['containerStatuses']
        labels={'app.kubernetes.io/instance':session.site,'app.kubernetes.io/name':record['service']}
        stage='IDENTITY'
        if (pod.get('kind')!='Pod' or meta.get('name')!=record['pod'] or meta.get('namespace')!=session.site
                or meta.get('uid')!=record['uid'] or meta.get('finalizers',[])!=expected_finalizers
                or not isinstance(meta.get('resourceVersion'),str)
                or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
                or (original_rv and meta['resourceVersion']!=record['rv'])
                or (deleting is True and not meta.get('deletionTimestamp'))
                or (deleting is False and meta.get('deletionTimestamp'))
                or common._digest(pod['spec'])!=record['spec_sha256']
                or any(meta.get('labels',{}).get(k)!=v for k,v in labels.items())
                or status.get('phase') not in ('Running','Succeeded') or not isinstance(statuses,list) or len(statuses)!=1):
            raise ValueError
        container=statuses[0]
        stage='CONTAINER'
        if (container.get('name')!=record['service'] or container.get('containerID')!=record['container_id']
                or type(container.get('restartCount')) is not int or container['restartCount']!=0
                or container.get('lastState',{}) not in ({},None)):raise ValueError
        if terminated:
            stage='TERMINATED_STATE'
            term=container['state']['terminated']
            if not isinstance(term,dict):raise ValueError
            stage='EXIT_CODE'
            if type(term.get('exitCode')) is not int or term['exitCode']!=0:raise ValueError
            stage='SIGNAL'
            if type(term.get('signal',0)) is not int or term.get('signal',0)!=0:raise ValueError
            stage='REASON'
            if term.get('reason')!='Completed':raise ValueError
        elif (container.get('ready') is not True or not isinstance(container.get('state',{}).get('running'),dict)):
            raise ValueError
        return meta['resourceVersion']
    except Exception:raise WriterFinalizerError('KUBE_WRITER_POD_UNVERIFIED',stage) from None


def _record(home,session,operation,service,key):
    plan=writers._bound(home,session,operation,key)
    value=writers._read(home,_name(service),key)
    try:
        if (set(value)!={'schema','operation','service','pod','uid','rv','spec_sha256','container_id','writer_plan_sha256'}
                or type(value['schema']) is not int or value['schema']!=1 or value['operation']!=operation
                or value['service']!=service or value['writer_plan_sha256']!=writers._hash(plan)
                or not isinstance(value['pod'],str) or not re.fullmatch(re.escape(session.site+'-'+service)+r'-[a-z0-9-]{1,64}',value['pod'])
                or not isinstance(value['uid'],str) or not identity.UUID.fullmatch(value['uid'])
                or not isinstance(value['rv'],str) or not re.fullmatch(r'[0-9]{1,32}',value['rv'])
                or not isinstance(value['spec_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',value['spec_sha256'])
                or not isinstance(value['container_id'],str) or not re.fullmatch(r'(?:containerd|docker|cri-o)://[0-9a-f]{64}',value['container_id'])):
            raise ValueError
        return value,plan
    except (ValueError,TypeError,KeyError):raise WriterFinalizerError('KUBE_WRITER_POD_PLAN_INVALID') from None


def prepare(home,session,operation,service,key):
    """Capture a single live Pod with an exact ReplicaSet/Deployment lineage."""
    try:
        plan=writers._bound(home,session,operation,key);session.reverify();entry=plan['writers'][service]
        labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name='+service
        pods=session._query(['get','pods','-l',labels])['items']
        if not isinstance(pods,list) or len(pods)!=1:raise ValueError
        pod=pods[0];meta=pod['metadata'];statuses=pod['status']['containerStatuses']
        if (pod.get('kind')!='Pod' or meta.get('namespace')!=session.site or meta.get('deletionTimestamp')
                or meta.get('finalizers',[])!=[] or not isinstance(meta.get('uid'),str)
                or not identity.UUID.fullmatch(meta['uid']) or not isinstance(meta.get('name'),str)
                or not re.fullmatch(re.escape(session.site+'-'+service)+r'-[a-z0-9-]{1,64}',meta['name'])
                or not isinstance(meta.get('resourceVersion'),str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])
                or not isinstance(statuses,list) or len(statuses)!=1):raise ValueError
        owners=[x for x in meta.get('ownerReferences',[]) if x.get('kind')=='ReplicaSet' and x.get('controller') is True]
        if len(owners)!=1 or not re.fullmatch(re.escape(session.site+'-'+service)+r'-[a-z0-9]{1,32}',owners[0]['name']):raise ValueError
        rs=session._query(['get','replicaset',owners[0]['name']]);rsmeta=rs['metadata']
        common_owner=[x for x in rsmeta.get('ownerReferences',[]) if x.get('kind')=='Deployment' and x.get('controller') is True]
        if (rs.get('kind')!='ReplicaSet' or rsmeta.get('name')!=owners[0]['name'] or rsmeta.get('namespace')!=session.site
                or rsmeta.get('uid')!=owners[0]['uid'] or len(common_owner)!=1
                or common_owner[0].get('name')!=session.site+'-'+service or common_owner[0].get('uid')!=entry['uid']):raise ValueError
        item=statuses[0]
        containers=pod['spec'].get('containers')
        if (not isinstance(containers,list) or len(containers)!=1 or containers[0].get('name')!=service
                or containers[0].get('image')!=session.manifest['images'][service]
                or pod['spec'].get('hostNetwork',False) is not False or pod['spec'].get('hostPID',False) is not False
                or pod['spec'].get('hostIPC',False) is not False or pod['spec'].get('automountServiceAccountToken') is not False
                or pod['spec'].get('initContainers') not in (None,[]) or pod['spec'].get('ephemeralContainers') not in (None,[])):
            raise ValueError
        value={'schema':1,'operation':operation,'service':service,'pod':meta['name'],'uid':meta['uid'],
               'rv':meta['resourceVersion'],'spec_sha256':common._digest(pod['spec']),
               'container_id':item['containerID'],'writer_plan_sha256':writers._hash(plan)}
        # Validate UID/identity and readiness before persisting a plan.
        _pod(session,value,[],deleting=False,original_rv=True)
        writers._write(home,_name(service),value,key)
        return {'result':'writer_pod_plan_recorded','termination_verified':False,'safe_to_backup':False}
    except WriterFinalizerError:raise
    except Exception:raise WriterFinalizerError('KUBE_WRITER_POD_PREPARE_UNCERTAIN') from None


def hold(home,session,operation,service,key):
    record,_=_record(home,session,operation,service,key);token=_token(operation,service)
    try:
        session.reverify();rv=_pod(session,record,[],deleting=False,original_rv=True)
        writers._write(home,'kubernetes-writer-hold-'+service+'-attempt.json',
                       {'operation':operation,'pod_plan_sha256':writers._hash(record)},key)
        ops=[{'op':'test','path':'/metadata/uid','value':record['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':rv},
             {'op':'add','path':'/metadata/finalizers','value':[token]}]
        session.api._call(['--request-timeout=20s','patch','pod/'+record['pod'],'--type=json',
                           '-p',json.dumps(ops,separators=(',',':'))])
        _pod(session,record,[token],deleting=False)
        return {'result':'writer_finalizer_observed','termination_verified':False,'safe_to_backup':False}
    except Exception:raise WriterFinalizerError('KUBE_WRITER_HOLD_UNCERTAIN') from None


def assert_held(home,session,operation,service,key):
    record,_=_record(home,session,operation,service,key)
    if writers._read(home,'kubernetes-writer-hold-'+service+'-attempt.json',key)!= {
            'operation':operation,'pod_plan_sha256':writers._hash(record)}:
        raise WriterFinalizerError('KUBE_WRITER_HOLD_UNVERIFIED')
    _pod(session,record,[_token(operation,service)],deleting=False)


def observe(home,session,operation,service,key):
    record,_=_record(home,session,operation,service,key)
    try:
        session.reverify();rv=_pod(session,record,[_token(operation,service)],deleting=True,terminated=True)
        return {'result':'writer_termination_observed','pod_uid':record['uid'],'resource_version':rv,
                'audit_durability_verified':False,'safe_to_backup':False}
    except WriterFinalizerError as error:
        raise WriterFinalizerError('KUBE_WRITER_TERMINATION_UNVERIFIED',error.stage) from None
    except Exception:raise WriterFinalizerError('KUBE_WRITER_TERMINATION_UNVERIFIED') from None


def release(home,session,operation,service,key):
    """Record observation and issue at most one exact finalizer removal."""
    record,_=_record(home,session,operation,service,key)
    try:
        result=observe(home,session,operation,service,key);token=_token(operation,service)
        writers._write(home,'kubernetes-writer-observed-'+service+'.json',
                       {'operation':operation,'pod_plan_sha256':writers._hash(record),
                        'resource_version':result['resource_version']},key)
        writers._write(home,'kubernetes-writer-release-'+service+'-attempt.json',
                       {'operation':operation,'pod_plan_sha256':writers._hash(record)},key)
        ops=[{'op':'test','path':'/metadata/uid','value':record['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':result['resource_version']},
             {'op':'test','path':'/metadata/finalizers','value':[token]},
             {'op':'remove','path':'/metadata/finalizers/0'}]
        session.api._call(['--request-timeout=20s','patch','pod/'+record['pod'],'--type=json',
                           '-p',json.dumps(ops,separators=(',',':'))])
        return {'result':'writer_finalizer_release_requested','termination_verified':True,
                'audit_durability_verified':False,'safe_to_backup':False}
    except Exception:raise WriterFinalizerError('KUBE_WRITER_RELEASE_UNCERTAIN') from None
