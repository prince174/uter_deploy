"""Prepared Compose protocol wiring, disabled without a real ingress fence.

This experimental module has no CLI and does not stop writers, capture Redis,
or authorize an update. A genuine continuously checked ingress/restart guard
and crash recovery must exist before `_verify_ingress` can be implemented.
"""
from pathlib import Path

from scripts import (backup_snapshot, compose_fence_recovery_plan as plans,
                     compose_fence_start as start, compose_nsfirewall_adapter as fence,
                     maintenance_evidence, maintenance_protocol, maintenance_transport,
                     redis_fence_journal as journal)


class ComposeMaintenanceError(ValueError):
    pass


def _verify_ingress(home, record, writers):
    """No implementation yet: a boolean supplied by an operator is not proof."""
    raise ComposeMaintenanceError('COMPOSE_INGRESS_FENCE_UNAVAILABLE')


def _writers_restart_disabled(writers):
    for service in ('agent', 'guardrail'):
        raw=start.diagnostic._docker('inspect','--format','{{json .HostConfig.RestartPolicy}}',writers[service]['id'])
        value=start.diagnostic._json(raw)
        if value != {'Name':'no','MaximumRetryCount':0}:
            raise ComposeMaintenanceError('COMPOSE_RESTART_POLICY_UNVERIFIED')


def collect_prepared(home, bundle, publisher, key):
    """Bind coordinator to a durable prepared operation, retaining all markers.

    Caller holds the fenced managed lock and uses a signed executor. The
    coordinator does not create a prepared journal, change restart policy,
    remove traffic, or release evidence. It must fail before POST when the
    ingress guard is absent; errors preserve the existing journal and records.
    """
    adapter=None
    try:
        home=Path(home)
        def locked():
            backup_snapshot._require_fenced_operation_lock(home)
            return True
        locked()
        record=journal.read(home)
        if record['backend']!='compose' or record['phase']!='prepared':raise ValueError
        maintenance_protocol.verify_capability(bundle,publisher)
        plan=plans.read(home,key,record['plan_sha256'],operation=record['operation'],
                        site=record['site'],resource=record['resource'])
        adapter=fence.Adapter(home,bundle,publisher,key)
        current,writers,bundle_hash=start._observe(home,bundle,publisher,key,adapter)
        current=dict(current,operation=record['operation'])
        intent=start.read_intent(home,key,record,bundle_hash)
        if (current!=plan or intent['agent']!=writers['agent'] or intent['guardrail']!=writers['guardrail']):
            raise ValueError
        inventory={service:(writers[service]['id'],) for service in ('agent','guardrail')}

        def observe():
            locked()
            if journal.read(home)!=record:raise ValueError
            observed,instances,observed_hash=start._observe(home,bundle,publisher,key,adapter)
            observed=dict(observed,operation=record['operation'])
            if observed!=plan or instances!=writers or observed_hash!=bundle_hash:raise ValueError
            if start.read_intent(home,key,record,bundle_hash)!=intent:raise ValueError
            _writers_restart_disabled(writers)
            if _verify_ingress(home,record,writers) is not True:raise ValueError
            return {service:(instances[service]['id'],) for service in ('agent','guardrail')}

        # This must precede any POST or durable maintenance intent. Until a
        # genuine fence is integrated, it always raises.
        if observe()!=inventory:raise ValueError
        recorder=maintenance_evidence.Recorder(home,key,operation=record['operation'],backend='compose',
                                               plan_sha256=record['plan_sha256'],lock_guard=locked)
        def request(service,instance,method,timeout):
            if timeout!=5:raise ValueError
            return maintenance_transport.request(service=service,method=method,container_id=instance,
                                                 identity_guard=lambda: observe()==inventory)
        result=maintenance_protocol.collect(inventory,observe_inventory=observe,request=request,
                                            record_intent=recorder.intent,record_receipt=recorder.receipt)
        if observe()!=inventory:raise ValueError
        for service in ('agent','guardrail'):
            instance=writers[service]['id']
            receipt=result[instance]
            if recorder.read_receipt(service,instance,receipt['boot_id'],site=record['site'],
                                     resource=record['resource'])!=receipt:raise ValueError
        return result
    except Exception:
        raise ComposeMaintenanceError('COMPOSE_MAINTENANCE_PREPARED_UNVERIFIED') from None
    finally:
        if adapter is not None:adapter.close()
