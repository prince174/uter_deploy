"""Experimental journaled netns fence protocol; not an update implementation."""
from scripts import compose_fence_origin as origin, redis_fence_journal as journal


class NamespaceProtocolError(ValueError): pass


def _record(home,operation,phase):
    state=journal.read(home)
    if state.get('backend')!='compose' or state.get('operation')!=operation or state.get('phase')!=phase:
        raise NamespaceProtocolError('NS_PROTOCOL_STATE_INVALID')
    return state


def isolate(home,operation,adapter):
    record=_record(home,operation,'prepared')
    try:
        if adapter.prepare(record) is not True:raise ValueError
    except Exception:raise NamespaceProtocolError('NS_PROTOCOL_PRECONDITION_FAILED') from None
    journal.advance(home,operation=operation,expected='prepared',next_phase='isolating')
    try:
        adapter.disable_restart(record)
        adapter.install_rule(record)
        adapter.close_clients(record)
        if adapter.verify_fenced(record) is not True:raise ValueError
    except Exception:
        raise NamespaceProtocolError('NS_PROTOCOL_ISOLATION_INCOMPLETE') from None
    journal.advance(home,operation=operation,expected='isolating',next_phase='isolated')


def release_without_capture(home,operation,adapter):
    """One-process clean release only; not valid after capture, restart or crash."""
    record=_record(home,operation,'isolated')
    try:
        if adapter.authorize_release_before_capture(record) is not True:raise ValueError
        origin.ensure(home,adapter.backup_key,journal.read(home),'pre_capture')
        adapter.release_before_capture(record)
    except Exception:
        raise NamespaceProtocolError('NS_PROTOCOL_RELEASE_INCOMPLETE') from None
    # Only Redis has been released. Guardrail/Agent remain stopped and their
    # restoration has not been attempted or verified by this protocol.
    journal.advance(home,operation=operation,expected='pre_capture_aborting',next_phase='redis_released')


def recover_before_capture(home,operation,adapter):
    """Resume an interrupted no-capture fence; caller holds operation lock.

    Never handles `capturing`, `captured` or generic `aborting`: the latter can
    mean an update already changed data. Redis recovery does not start writers.
    """
    record=journal.read(home)
    allowed=('prepared','isolating','isolated','pre_capture_aborting')
    if record.get('backend')!='compose' or record.get('operation')!=operation or record.get('phase') not in allowed:
        raise NamespaceProtocolError('NS_RECOVERY_STATE_UNSUPPORTED')
    try:
        if adapter.attach_before_capture_recovery(record) is not True:raise ValueError
        if record['phase']!='pre_capture_aborting':
            journal.advance(home,operation=operation,expected=record['phase'],next_phase='pre_capture_aborting')
        origin.ensure(home,adapter.backup_key,journal.read(home),'pre_capture')
        if adapter.recover_before_capture(record) is not True:raise ValueError
        journal.advance(home,operation=operation,expected='pre_capture_aborting',next_phase='redis_released')
    except Exception:
        raise NamespaceProtocolError('NS_RECOVERY_INCOMPLETE') from None
