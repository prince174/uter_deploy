"""Read-only maintenance capability check for a narrow signed Compose profile.

This check never sends POST, establishes ingress/Redis fencing, or authorizes an
update. Root, kernel, Docker daemon and the signed executor remain trusted.
"""
from pathlib import Path

from scripts import (backup_snapshot, compose_fence_start as start,
                     compose_nsfirewall_adapter as fence, maintenance_protocol,
                     maintenance_transport, redis_fence_journal as journal)


class CheckError(ValueError):
    pass


def check(home, bundle, publisher, key):
    """Observe the exact two signed processes without changing their state."""
    adapter = None
    try:
        backup_snapshot._require_fenced_operation_lock(home)
        if journal.blocks_mutation(home):
            raise ValueError
        manifest = maintenance_protocol.verify_capability(bundle, publisher)
        home = Path(home)
        adapter = fence.Adapter(home, bundle, publisher, key)
        plan, writers, bundle_hash = start._observe(home, bundle, publisher, key, adapter)
        boots = set()
        def identity_guard():
            backup_snapshot._require_fenced_operation_lock(home)
            if journal.blocks_mutation(home):
                return False
            observed_plan, observed_writers, observed_hash = start._observe(home, bundle, publisher, key, adapter)
            observed_plan = dict(observed_plan, operation=plan['operation'])
            return observed_plan == plan and observed_writers == writers and observed_hash == bundle_hash
        for service in ('agent', 'guardrail'):
            status, raw = maintenance_transport.request(service=service, method='GET',
                container_id=writers[service]['id'], identity_guard=identity_guard)
            value = maintenance_protocol._parse(raw)
            if (status != 200 or value['state'] != 'running' or value['safe_to_stop'] is not False
                    or value['error'] is not None or value['evidence'] is not None
                    or value['boot_id'] in boots):
                raise ValueError
            boots.add(value['boot_id'])
        if not identity_guard():
            raise ValueError
        return {'backend': 'compose', 'version': manifest['version'], 'protocol': 1,
                'processes_observed': 2, 'redis_isolated': False, 'safe_to_update': False}
    except Exception:
        raise CheckError('COMPOSE_MAINTENANCE_CHECK_UNVERIFIED') from None
    finally:
        if adapter is not None:
            adapter.close()
