"""Strict identity of an uncommitted source snapshot; no source content is stored."""
import re


def validate_secret_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'SOURCE_SNAPSHOT_[A-F0-9]{32}', value):
        raise ValueError('Invalid temporary snapshot secret name')
    return value


def validate(value, baseline=None):
    if not isinstance(value, dict) or set(value) != {'kind', 'baseline_commit', 'patch_sha256'}:
        raise ValueError('Invalid source snapshot provenance')
    if value['kind'] != 'uncommitted_patch' or not isinstance(value['baseline_commit'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['baseline_commit']):
        raise ValueError('Invalid snapshot baseline')
    if not isinstance(value['patch_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['patch_sha256']):
        raise ValueError('Invalid snapshot patch fingerprint')
    if baseline is not None and value['baseline_commit'] != baseline:
        raise ValueError('Snapshot baseline mismatch')
    return value
