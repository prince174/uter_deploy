"""Observe a Redis container's termination, without modifying a cluster.

This module is an experimental primitive, not an isolation or durability proof.
The caller must hold the controller lock and trust the pinned kubeconfig and API.
No result from this function authorizes an upgrade, removes a finalizer, or
guarantees that Redis flushed its AOF to durable storage.
"""
import re

from scripts import kubernetes_fence_finalizer as finalizer


class ShutdownObservationError(ValueError):
    """Fixed diagnostic only; never include Kubernetes or workload contents."""
    def __init__(self,stage='UNVERIFIED'):
        super().__init__('KUBE_REDIS_SHUTDOWN_UNVERIFIED')
        self.stage=stage


def observe(directory, plan, operation, api):
    """Observe the finalizer-protected Pod for this exact journal operation.

    The Pod must still exist, retain our sole finalizer, and report an unchanged
    spec and exact container ID with a completed, zero-signal, zero-exit state.
    Missing or uncertain data is refused. This is not proof of graceful shutdown:
    external force-delete history, node, CSI and AOF durability remain unchecked.
    """
    stage='PLAN'
    try:
        finalizer._validate_plan(plan)
        finalizer._check_journal(directory, plan, operation, 'isolating')
        token = finalizer._token(operation)
        if api.context != plan['context'] or api.namespace != plan['namespace']:
            raise ValueError
        stage='POD_FETCH'
        pod = api.get(plan['pod'])
        stage='POD_STATUS'
        meta = pod['metadata']
        state = pod['status']
        statuses = state['containerStatuses']
        stage='POD_IDENTITY'
        if (meta['name'] != plan['pod'] or meta['namespace'] != plan['namespace']
                or meta['uid'] != plan['uid'] or not isinstance(meta.get('deletionTimestamp'), str)
                or not meta['deletionTimestamp'] or meta.get('finalizers') != [token]
                or not isinstance(meta.get('resourceVersion'), str)
                or not re.fullmatch(r'[0-9]{1,32}', meta['resourceVersion'])):
            raise ValueError
        stage='POD_SPEC'
        if finalizer._digest(pod['spec']) != plan['spec_sha256']:
            raise ValueError
        stage='POD_STATUS'
        if state.get('phase') not in ('Running', 'Succeeded') or not isinstance(statuses, list) or len(statuses) != 1:
            raise ValueError
        item = statuses[0]
        stage='CONTAINER'
        if (item['name'] != 'redis' or item['containerID'] != plan['container_id']
                or type(item['restartCount']) is not int or item['restartCount'] != 0
                or item.get('lastState', {}) not in ({}, None)):
            raise ValueError
        stage='TERMINATED_STATE'
        terminated = item['state']['terminated']
        if not isinstance(terminated,dict):raise ValueError
        stage='EXIT_CODE'
        if type(terminated.get('exitCode')) is not int or terminated['exitCode'] != 0:raise ValueError
        stage='SIGNAL'
        if type(terminated.get('signal',0)) is not int or terminated.get('signal',0) != 0:raise ValueError
        stage='REASON'
        if terminated.get('reason') != 'Completed':raise ValueError
    except Exception:
        raise ShutdownObservationError(stage) from None
    return {'result': 'termination_observed', 'redis_isolated': False,
            'unforced_deletion_verified': False, 'aof_durable': False,
            'safe_to_upgrade': False}
