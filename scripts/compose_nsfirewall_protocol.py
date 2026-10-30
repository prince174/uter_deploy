"""Experimental journaled netns fence protocol; not an update implementation."""
from scripts import redis_fence_journal as journal


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
        adapter.release_before_capture(record)
    except Exception:
        raise NamespaceProtocolError('NS_PROTOCOL_RELEASE_INCOMPLETE') from None
    journal.advance(home,operation=operation,expected='aborting',next_phase='restored')
