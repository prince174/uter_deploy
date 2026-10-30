"""Validate Uter protocol v1 receipts without authorizing workload mutations.

Receipt validation does not establish process identity, writer exclusion or a
Redis fence. Callers must prove those independently before any backup/update.
"""
import json
import re

_BOOT = re.compile(r'[0-9a-f]{32}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


class ReceiptError(ValueError):
    pass


def validate(raw, *, service, expected_boot):
    """Accept only a complete quiesced receipt for the expected process boot."""
    try:
        if service not in ('agent', 'guardrail') or not isinstance(expected_boot, str) or not _BOOT.fullmatch(expected_boot):
            raise ValueError
        if not isinstance(raw, bytes) or len(raw) > 16384:
            raise ValueError
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=pairs)
        if (not isinstance(value, dict) or set(value) != {'protocol', 'boot_id', 'state', 'safe_to_stop', 'active_requests', 'error', 'evidence'}
                or type(value['protocol']) is not int or value['protocol'] != 1
                or value['boot_id'] != expected_boot or value['state'] != 'quiesced'
                or value['safe_to_stop'] is not True or type(value['active_requests']) is not int
                or value['active_requests'] != 0 or value['error'] is not None):
            raise ValueError
        evidence = value['evidence']
        if service == 'agent':
            if (not isinstance(evidence, dict) or set(evidence) != {'requests_drained', 'redis', 'audit'}
                    or evidence['requests_drained'] is not True or evidence['redis'] != 'not_used'
                    or evidence['audit'] != 'guardrail_owned'):
                raise ValueError
        else:
            if not isinstance(evidence, dict) or set(evidence) != {'audit', 'redis_closed'} or evidence['redis_closed'] is not True:
                raise ValueError
            audit = evidence['audit']
            if (not isinstance(audit, dict) or set(audit) != {'last_seq', 'last_hash', 'fsynced', 'verified'}
                    or type(audit['last_seq']) is not int or audit['last_seq'] < 1
                    or not isinstance(audit['last_hash'], str) or not _HASH.fullmatch(audit['last_hash'])
                    or audit['fsynced'] is not True or audit['verified'] is not True):
                raise ValueError
        return value
    except (ValueError, TypeError, KeyError, UnicodeDecodeError):
        raise ReceiptError('MAINTENANCE_RECEIPT_UNVERIFIED') from None
