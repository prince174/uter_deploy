"""Persist and recheck the two signed writer-stop observations for audit."""
import re

from scripts import (kubernetes_fence_finalizer as finalizer,
                     kubernetes_writer_quiesce as writers, redis_fence_journal as journal)

NAME='kubernetes-audit-writers-stopped.json'


class WriterGuardError(ValueError):pass


def seal(session,operation,key):
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        writers.observe_stopped(session.home,session,operation,key)
        plan=writers._bound(session.home,session,operation,key)
        value={'schema':1,'operation':operation,'writer_plan_sha256':writers._hash(plan)}
        writers._write(session.home,NAME,value,key)
        return {'writer_stop_evidence_saved':True,'safe_to_backup':False}
    except Exception:raise WriterGuardError('KUBE_AUDIT_WRITERS_UNVERIFIED') from None


def verify(session,operation,key):
    """Recheck authenticated evidence and live stopped writers after rollout."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        session._scope();state=journal.read(session.home);pod_plan=finalizer.read_plan(session.home)
        finalizer._check_journal(session.home,pod_plan,operation,'isolating')
        plan=writers._read(session.home,writers.NAME,key)
        evidence=writers._read(session.home,NAME,key)
        if (evidence!={'schema':1,'operation':operation,'writer_plan_sha256':writers._hash(plan)}
                or plan['operation']!=operation or plan['site']!=session.site
                or plan['context']!=session.api.context or plan['redis_plan_sha256']!=finalizer.plan_hash(pod_plan)
                or plan['redis_uid']!=state['resource'] or plan['manifest_sha256']!=writers._hash(session.manifest)
                or plan['profile_sha256']!=writers._hash(session.profile)
                or plan['inventory_sha256']!=session.inventory_digest or plan['config_sha256']!=session.config_sha256
                or plan['key_sha256']!=session.key_digest or set(plan['writers'])!=set(writers.SERVICES)):
            raise ValueError
        for service in writers.SERVICES:
            entry=plan['writers'][service]
            if entry['uid']!=session.writer_uids[service]:raise ValueError
            meta,spec=writers._deployment(session,service,entry['uid'])
            if writers._hash(spec)!=entry['stopped']:raise ValueError
            observed=writers._read(session.home,'kubernetes-writer-observed-'+service+'.json',key)
            pod=writers._read(session.home,'kubernetes-writer-pod-'+service+'.json',key)
            digest=writers._hash(pod)
            release=writers._read(session.home,'kubernetes-writer-release-'+service+'-attempt.json',key)
            if (pod['operation']!=operation or pod['service']!=service or pod['writer_plan_sha256']!=writers._hash(plan)
                    or set(observed)!={'operation','pod_plan_sha256','resource_version'}
                    or observed['operation']!=operation or observed['pod_plan_sha256']!=digest
                    or not isinstance(observed['resource_version'],str)
                    or not re.fullmatch(r'[0-9]{1,32}',observed['resource_version'])
                    or release!={'operation':operation,'pod_plan_sha256':digest}):raise ValueError
            deployment=session._query(['get','deployment',session.site+'-'+service])
            generation=meta['generation'];status=deployment.get('status',{})
            if (deployment.get('metadata',{}).get('resourceVersion')!=meta['resourceVersion']
                    or deployment.get('metadata',{}).get('uid')!=meta['uid']
                    or type(generation) is not int or status.get('observedGeneration')!=generation
                    or any(type(status.get(field,0)) is not int or status.get(field,0)!=0
                           for field in ('replicas','readyReplicas','availableReplicas','updatedReplicas'))):raise ValueError
            labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name='+service
            if session._query(['get','pods','-l',labels]).get('items')!=[]:raise ValueError
        session._scope()
        return {'writers_stopped_observed':True,'continuous_exclusion':False,'safe_to_backup':False}
    except Exception:raise WriterGuardError('KUBE_AUDIT_WRITERS_UNVERIFIED') from None
