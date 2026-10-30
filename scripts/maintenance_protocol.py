"""Bounded protocol-v1 coordinator; no runtime adapter or update authorization.

The caller must hold the operation lock, durably record each intent, fence
ingress/restarts, and authenticate the full replica inventory. A receipt never
establishes Redis isolation or permission to migrate data.
"""
import json
import re
import time

from scripts import maintenance_receipt

_BOOT = re.compile(r'[0-9a-f]{32}\Z')
_FIELDS = {'protocol', 'boot_id', 'state', 'safe_to_stop', 'active_requests', 'error', 'evidence'}


class ProtocolError(ValueError):
    pass


def _parse(raw, expected_boot=None):
    if not isinstance(raw, bytes) or len(raw) > 16384:
        raise ProtocolError('MAINTENANCE_RESPONSE_UNVERIFIED')
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=pairs)
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or type(value['protocol']) is not int or value['protocol'] != 1
                or not isinstance(value['boot_id'], str) or not _BOOT.fullmatch(value['boot_id'])
                or (expected_boot is not None and value['boot_id'] != expected_boot)
                or value['state'] not in ('running', 'draining', 'quiesced', 'failed')
                or type(value['active_requests']) is not int or value['active_requests'] < 0
                or type(value['safe_to_stop']) is not bool):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeDecodeError):
        raise ProtocolError('MAINTENANCE_RESPONSE_UNVERIFIED') from None


def collect(inventory, *, observe_inventory, request, record_intent, record_receipt, clock=time.monotonic, sleep=time.sleep):
    """Coordinate exact Agent then Guardrail instances through a supplied adapter.

    This is an experimental library, not an executable adapter. `record_intent`
    must persist and fsync a write-once record before the sole POST. `request`
    returns (HTTP status, JSON bytes); errors leave the operation incomplete.
    `record_receipt` must durably bind the receipt to that exact instance before
    any subsequent writer is contacted. Neither callback is implemented here.
    POST transport failure is re-observed via GET, never retried. No call is
    made until all initial running states and complete identities are verified.
    """
    try:
        if (not isinstance(inventory, dict) or set(inventory) != {'agent', 'guardrail'}
                or any(not isinstance(inventory[s], tuple) or not inventory[s] for s in inventory)
                or any(not isinstance(x, str) or not x or len(x) > 256 for s in inventory for x in inventory[s])
                or len({x for s in inventory for x in inventory[s]}) != sum(map(len, inventory.values()))):
            raise ValueError
        initial = {s: tuple(inventory[s]) for s in ('agent', 'guardrail')}
        def checked():
            if observe_inventory() != initial:
                raise ProtocolError('MAINTENANCE_INVENTORY_CHANGED')
        boots = {}
        checked()
        for service in ('agent', 'guardrail'):
            for instance in initial[service]:
                checked(); status, raw = request(service, instance, 'GET', 5)
                value = _parse(raw)
                if (status != 200 or value['state'] != 'running' or value['safe_to_stop'] is not False
                        or value['error'] is not None or value['evidence'] is not None):
                    raise ProtocolError('MAINTENANCE_INITIAL_STATE_UNVERIFIED')
                boots[instance] = value['boot_id']
                checked()
        if len(set(boots.values())) != len(boots):
            raise ProtocolError('MAINTENANCE_BOOT_ID_DUPLICATE')
        receipts = {}
        for service in ('agent', 'guardrail'):
            deadline = clock() + 70
            for instance in initial[service]:
                if clock() >= deadline:
                    raise ProtocolError('MAINTENANCE_DEADLINE_EXCEEDED')
                checked()
                if record_intent(service, instance, boots[instance]) is not True:
                    raise ProtocolError('MAINTENANCE_INTENT_UNVERIFIED')
                checked()
                if clock() >= deadline:
                    raise ProtocolError('MAINTENANCE_DEADLINE_EXCEEDED')
                try:
                    status, raw = request(service, instance, 'POST', 5)
                except TimeoutError:
                    status, raw = None, None
                if status is not None:
                    value = _parse(raw, boots[instance])
                    if status != 202 or value['state'] not in ('draining', 'quiesced'):
                        raise ProtocolError('MAINTENANCE_POST_UNVERIFIED')
                while True:
                    if clock() >= deadline:
                        raise ProtocolError('MAINTENANCE_DEADLINE_EXCEEDED')
                    checked(); status, raw = request(service, instance, 'GET', 5)
                    value = _parse(raw, boots[instance]); checked()
                    if clock() >= deadline:
                        raise ProtocolError('MAINTENANCE_DEADLINE_EXCEEDED')
                    if status == 200 and value['state'] == 'quiesced':
                        receipt = maintenance_receipt.validate(raw, service=service, expected_boot=boots[instance])
                        checked()
                        if record_receipt(service, instance, boots[instance], receipt) is not True:
                            raise ProtocolError('MAINTENANCE_RECEIPT_PERSISTENCE_UNVERIFIED')
                        checked()
                        if clock() >= deadline:
                            raise ProtocolError('MAINTENANCE_DEADLINE_EXCEEDED')
                        receipts[instance] = receipt
                        break
                    if status != 202 or value['state'] != 'draining' or value['safe_to_stop'] is not False or value['error'] is not None:
                        raise ProtocolError('MAINTENANCE_STATE_UNVERIFIED')
                    sleep(min(0.5, max(0, deadline-clock())))
            checked()
        return receipts
    except ProtocolError:
        raise
    except Exception:
        raise ProtocolError('MAINTENANCE_OPERATION_UNCERTAIN') from None
