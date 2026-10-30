"""Experimental durable Kubernetes inventory, not an update authority.

This adapter can bind a signed workload inventory to a prepared operation.
It cannot prove ingress, restart or external Redis-writer exclusion. Therefore
the coordinator is deliberately blocked before any maintenance request.
"""
from scripts import (kubernetes_fence_finalizer as finalizer,
                     kubernetes_maintenance_preflight as preflight,
                     maintenance_evidence, maintenance_protocol, maintenance_transport)


class RuntimeError(ValueError):
    pass


def _recorder(session, operation, key):
    plan = finalizer.read_plan(session.home)
    finalizer._check_journal(session.home, plan, operation, 'prepared')
    def locked():
        session._guard()
        return True
    recorder = maintenance_evidence.Recorder(session.home, key, operation=operation,
        backend='kubernetes', plan_sha256=finalizer.plan_hash(plan), lock_guard=locked)
    recorder._read_scope(session.site, plan['uid'])
    return recorder, plan


def _record(session, plan, snapshot):
    if (not isinstance(snapshot, dict) or snapshot.get('safe_to_start') is not False
            or snapshot.get('redis_isolated') is not False or snapshot.get('safe_to_update') is not False
            or snapshot.get('ingress_fenced') is not False or snapshot.get('restart_fenced') is not False
            or set(snapshot.get('writers', {})) != {'agent', 'guardrail'}):
        raise ValueError
    return {'schema':1, 'site':session.site, 'resource_uid':plan['uid'],
            'manifest_sha256':finalizer._digest(session.manifest), 'writers':snapshot['writers']}


def prepare(session, operation, key):
    """Persist a write-once initial inventory before any application request."""
    try:
        recorder, plan = _recorder(session, operation, key)
        snapshot = preflight.observe(session)
        value = _record(session, plan, snapshot)
        recorder._write('maintenance-kubernetes-inventory.json', value)
        if _record(session, plan, preflight.observe(session)) != value:
            raise ValueError
        return {'inventory_recorded':True, 'safe_to_start':False, 'safe_to_backup':False, 'safe_to_update':False}
    except Exception:
        raise RuntimeError('KUBE_MAINTENANCE_INVENTORY_UNVERIFIED') from None


def _inventory(session, recorder, plan):
    finalizer._check_journal(session.home, plan, recorder.operation, 'prepared')
    before = recorder._read_scope(session.site, plan['uid'])
    saved = recorder._read('maintenance-kubernetes-inventory.json')
    current = _record(session, plan, preflight.observe(session, require_ready=False))
    if saved != current or recorder._read_scope(session.site, plan['uid']) != before:
        raise RuntimeError('KUBE_MAINTENANCE_INVENTORY_CHANGED')
    finalizer._check_journal(session.home, plan, recorder.operation, 'prepared')
    return {service:(entry['uid']+'/'+entry['container_id'],) for service, entry in current['writers'].items()}


def _require_fences(session, recorder, plan):
    """No implementation currently proves all necessary independent fences."""
    raise RuntimeError('KUBE_MAINTENANCE_FENCE_UNVERIFIED')


def collect(session, operation, key):
    """Wire the durable inventory to the coordinator, but fail closed first."""
    recorder, plan = _recorder(session, operation, key)
    initial = _inventory(session, recorder, plan)
    _require_fences(session, recorder, plan)
    # Unreachable until the preceding gate has a tested, independently pinned
    # ingress/restart/Redis implementation; never enable it by an operator flag.
    def observe():
        return _inventory(session, recorder, plan)
    def request(service, instance, method, timeout):
        snapshot = preflight.observe(session, require_ready=False)
        if instance != initial[service][0]:
            raise RuntimeError('KUBE_MAINTENANCE_INVENTORY_CHANGED')
        return maintenance_transport.request(service=service, method=method, session=session,
            pod=snapshot['writers'][service]['pod'], identity_guard=lambda:observe() == initial)
    return maintenance_protocol.collect(initial, observe_inventory=observe, request=request,
        record_intent=recorder.intent, record_receipt=recorder.receipt)
