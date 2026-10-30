"""Experimental Compose fence orchestration contract, without a Docker adapter.

NOT connected to uterctl, not a production fence, not permission to migrate.
A future adapter must be implemented and independently reviewed before use.
The caller owns the same exclusive operation lock for the entire transaction.
Journal state records intent, never establishes that the fence is still held.
"""
from scripts import redis_fence_journal as journal


class ComposeFenceProtocolError(ValueError):
    pass


def _record(home, operation, phase):
    current = journal.read(home)
    if (current['backend'] != 'compose' or current['operation'] != operation
            or current['phase'] != phase):
        raise ComposeFenceProtocolError('COMPOSE_FENCE_STATE_INVALID')
    return current


def isolate(home, operation, adapter):
    """Experimental ordered operations. Exceptions leave the journal for inspection.

    Adapter must verify exact plan/resource identity, signed installation,
    stopped Uter writers, local trusted daemon and a single private bridge.
    The hypothetical adapter must also reject published ports, host networking,
    extra networks, unix Redis sockets, replicas and untrusted volume owners.
    """
    record = _record(home, operation, 'prepared')
    try:
        if adapter.verify_preconditions(record) is not True:
            raise ValueError('precondition not verified')
    except Exception:
        raise ComposeFenceProtocolError('COMPOSE_FENCE_PRECONDITION_FAILED') from None
    journal.advance(home, operation=operation, expected='prepared', next_phase='isolating')
    try:
        adapter.disable_restart(record)
        adapter.disconnect_network(record)
        adapter.close_external_clients(record)
        if adapter.verify_isolated(record) is not True:
            raise ValueError('isolation not verified')
    except Exception:
        # A failed/timed-out operation may actually have taken effect. Never
        # assume rollback is safe and never remove the intent record.
        raise ComposeFenceProtocolError('COMPOSE_FENCE_ISOLATION_INCOMPLETE') from None
    journal.advance(home, operation=operation, expected='isolating', next_phase='isolated')


def capture(home, operation, adapter, capture_while_isolated):
    """Capture only after re-checking real runtime state; never trust journal alone."""
    record = _record(home, operation, 'isolated')
    try:
        if adapter.verify_isolated(record) is not True:
            raise ValueError('isolation not verified')
    except Exception:
        raise ComposeFenceProtocolError('COMPOSE_FENCE_LOST') from None
    journal.advance(home, operation=operation, expected='isolated', next_phase='capturing')
    try:
        capture_while_isolated()
        if adapter.verify_isolated(record) is not True:
            raise ValueError('isolation not verified')
    except Exception:
        raise ComposeFenceProtocolError('COMPOSE_FENCE_CAPTURE_INCOMPLETE') from None
    journal.advance(home, operation=operation, expected='capturing', next_phase='captured')


def abort_to_old(home, operation, adapter):
    """Experiment: restore old configuration only if adapter proves it is safe.

    This API is deliberately not a generic rollback of a partially migrated
    deployment. A future adapter must verify exact plan and data state, both
    before and after restoration, including AOF and graceful-stop requirements.
    """
    record = journal.read(home)
    if (record['backend'] != 'compose' or record['operation'] != operation
            or record['phase'] not in ('prepared', 'isolating', 'isolated', 'capturing', 'captured')):
        raise ComposeFenceProtocolError('COMPOSE_FENCE_STATE_INVALID')
    try:
        if adapter.verify_old_restoration_safe(record) is not True:
            raise ValueError('old restoration not verified')
    except Exception:
        raise ComposeFenceProtocolError('COMPOSE_FENCE_RESTORE_UNSAFE') from None
    journal.advance(home, operation=operation, expected=record['phase'], next_phase='aborting')
    try:
        adapter.restore_old_configuration(record)
        if adapter.verify_old_restored(record) is not True:
            raise ValueError('restoration not verified')
    except Exception:
        raise ComposeFenceProtocolError('COMPOSE_FENCE_RESTORE_INCOMPLETE') from None
    journal.advance(home, operation=operation, expected='aborting', next_phase='restored')
