"""Experimental read-only Redis ACL inspection bound to a Kubernetes journal.

This is not wired to uterctl. The supplied Redis transport is a trusted fixture;
operation intents must already exist, be write-once and be HMAC-authenticated.
No observation permits retry, restore, backup or update.
"""
import os
import hmac
from pathlib import Path

from scripts import (backup_installation, kubernetes_fence_coordinator as coordinator, kubernetes_fence_finalizer as finalizer,
                     maintenance_evidence, redis_acl_experiment)


class InspectionError(ValueError):
    pass


def _verify_plan_pod(session, plan):
    labels='app.kubernetes.io/instance='+session.site+',app.kubernetes.io/name=redis'
    pods=session._query(['get','pods','-l',labels])['items']
    if not isinstance(pods,list) or len(pods)!=1: raise ValueError
    pod=session._query(['get','pod',plan['pod']]);meta=pod['metadata'];statuses=pod['status']['containerStatuses']
    if (pods[0].get('metadata',{}).get('uid')!=plan['uid'] or pods[0].get('metadata',{}).get('name')!=plan['pod']
            or meta.get('uid')!=plan['uid']
            or meta.get('name')!=plan['pod'] or meta.get('namespace')!=session.site or meta.get('deletionTimestamp')
            or finalizer._digest(pod['spec'])!=plan['spec_sha256'] or pod['status'].get('phase')!='Running'
            or not isinstance(statuses,list) or len(statuses)!=1):
        raise ValueError
    status=statuses[0]
    if (status.get('name')!='redis' or status.get('containerID')!=plan['container_id']
            or type(status.get('restartCount')) is not int or status['restartCount']!=0
            or not isinstance(status.get('state',{}).get('running'),dict)):
        raise ValueError


def inspect(session, operation, key, execute, *, admin_user, expected_run_id, expected_client_id,
            profile='minimal-ci'):
    """Verify prepared scope, authenticated intent(s) and a trusted fixture connection."""
    try:
        if type(session) is not coordinator.BoundSession or session._executor is None:
            raise ValueError
        session._guard()
        session.reverify()
        configured=backup_installation.safe_file(session._key_path,private=True,limit=32)
        if not isinstance(key,bytes) or len(key)!=32 or not hmac.compare_digest(configured,key):
            raise ValueError
        plan=finalizer.read_plan(session.home)
        state=finalizer._check_journal(session.home,plan,operation,'prepared')
        if state['site'] != session.site or state['resource'] != plan['uid']:
            raise ValueError
        _verify_plan_pod(session,plan)
        def guard():
            session._guard()
            return True
        recorder=maintenance_evidence.Recorder(session.home,key,operation=operation,backend='kubernetes',
            plan_sha256=finalizer.plan_hash(plan),lock_guard=guard)
        before=recorder._read_scope(session.site,plan['uid'])
        base={'schema':1,'operation':operation,'backend':'kubernetes','site':session.site,
              'resource':plan['uid'],'plan_sha256':finalizer.plan_hash(plan),
              'admin_user':admin_user,'run_id':expected_run_id,'client_id':expected_client_id,'profile':profile}
        stages=[]
        for stage in ('disable-default','kill-default'):
            name='redis-acl-intent-'+stage+'.json'
            exists=os.path.lexists(Path(session.home)/name)
            if not exists:
                if stage == 'disable-default': raise ValueError
                continue
            if recorder._read(name) != {**base,'stage':stage}:
                raise ValueError
            stages.append(stage)
        value=redis_acl_experiment.inspect_after_failure(execute,admin_user=admin_user,
            expected_run_id=expected_run_id,expected_client_id=expected_client_id,
            recorded_intents=frozenset(stages),profile=profile)
        if (not isinstance(value,dict) or set(value)!={'observation','retry_allowed','recovery_automated',
                'safe_to_backup','safe_to_update'}
                or value['observation'] not in ('default_on_uncertain','default_off_clients_present','default_off_only_admin')
                or any(value[k] is not False for k in ('retry_allowed','recovery_automated','safe_to_backup','safe_to_update'))):
            raise ValueError
        if (recorder._read_scope(session.site,plan['uid']) != before
                or finalizer._check_journal(session.home,plan,operation,'prepared') != state):
            raise ValueError
        # Re-read exact evidence after live observation; no stale/corrupt or
        # newly appearing marker is allowed to be interpreted as absence.
        for stage in ('disable-default','kill-default'):
            name='redis-acl-intent-'+stage+'.json'
            if os.path.lexists(Path(session.home)/name) != (stage in stages): raise ValueError
            if stage in stages and recorder._read(name) != {**base,'stage':stage}: raise ValueError
        _verify_plan_pod(session,plan)
        session.reverify()
        return value
    except Exception:
        raise InspectionError('REDIS_ACL_OPERATION_INSPECTION_UNVERIFIED') from None
