"""Validate an experimental Helm maintenance profile; never authorize an update.

Inputs must be obtained by a trusted caller; this check is not live Pod identity,
continuous Redis isolation, recovery authorization or an installer entry point.
"""
import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from scripts import backup_installation, backup_snapshot, maintenance_protocol, workload_preflight

_DIGEST = re.compile(r'^[a-zA-Z0-9./:_-]+@sha256:([0-9a-f]{64})$')
_RESERVED = {'UTER_MAINTENANCE_ENABLED', 'UTER_MAINTENANCE_KEY_FILE', 'WEB_CONCURRENCY'}
# The validator and chart are both signed. These hashes bind the candidate to
# the reviewed chart, including defaults, not to an arbitrary capable release.
_CHART = {
    'Chart.yaml': '2fee8cce6ec5e5ba70f306e44284968711a8063398bb8fbb77414147fcd78134',
    'templates/_network.tpl': 'd40c7574d7006effeab95f891ea405abda56c7f5de8d48ffa017dce5d9072b44',
    'templates/network.yaml': 'd85447a5c2b17d8f046138866098e3241523f9278eee255506468f9fda1ece9b',
    'templates/storage.yaml': '79354a066aa3ddf9db48bc7e2051a1553a71b5fda2409a6a78b6e40ba9b94922',
    'templates/workloads.yaml': '5b1043826e9cf607e02ed1ed3733e54fdd30ad83000cf210f3a763bff76a39da',
    'values.yaml': '49be0ee4d87e17503cd44ee90dcecd41c76bc3dcfc6c4f23545fea1e6ae38ce5',
}


def _verify_chart(bundle, inventory):
    chart = Path(bundle) / 'charts/uter'
    found = set()
    for item in chart.rglob('*'):
        if item.is_symlink(): raise ValueError
        if item.is_dir(): continue
        if not item.is_file(): raise ValueError
        found.add(item.relative_to(chart).as_posix())
    if found != set(_CHART): raise ValueError
    for relative, digest in _CHART.items():
        data = workload_preflight.read_trusted_file(chart / relative, 1024 * 1024, secret=False,
                                                    error='KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED')
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest or inventory.get('charts/uter/' + relative) != actual:
            raise ValueError


def _verify_signed_chart(bundle, publisher_key, manifest):
    read = lambda p, limit: workload_preflight.read_trusted_file(p, limit, secret=False,
                                  error='KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED')
    root = Path(bundle)
    raw_inventory = read(root / 'checksums.json', 1024 * 1024)
    public = load_pem_public_key(read(publisher_key, 32768))
    if not isinstance(public, Ed25519PublicKey): raise ValueError
    public.verify(base64.b64decode(read(root / 'checksums.sig', 1024), validate=True), raw_inventory)
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result: raise ValueError
            result[name] = value
        return result
    inventory = json.loads(raw_inventory, object_pairs_hook=unique)
    raw_manifest = read(root / 'manifest.json', 1024 * 1024)
    if (not isinstance(inventory, dict) or inventory.get('manifest.json') != hashlib.sha256(raw_manifest).hexdigest()
            or json.loads(raw_manifest, object_pairs_hook=unique) != manifest): raise ValueError
    _verify_chart(bundle, inventory)


def validate(bundle, publisher_key, home, site, values, maintenance_secret, service_secrets):
    """Authenticate release and validate a prospective, explicitly enabled profile.

    Kubernetes objects and values are trusted-caller snapshots, not independently
    authenticated live evidence. Key bytes are never returned or logged.
    """
    try:
        manifest = maintenance_protocol.verify_capability(bundle, publisher_key)
        _verify_signed_chart(bundle, publisher_key, manifest)
        if backup_snapshot.maintenance_enabled(home, values, site, manifest) is not True:
            raise ValueError
        name = site['name'] + '-maintenance'
        backup_snapshot.validate_maintenance_secret(maintenance_secret, name, site['namespace'], home=home)
        for service in ('guardrail', 'agent', 'redis'):
            expected = _DIGEST.fullmatch(manifest['images'][service])
            actual = _DIGEST.fullmatch(values['images'][service])
            if not expected or not actual or expected.group(1) != actual.group(1):
                raise ValueError
        for field in ('guardrailEnv', 'agentEnv'):
            env = values.get(field, {})
            if not isinstance(env, dict) or _RESERVED.intersection(env):
                raise ValueError
        service_names = {values[field] for field in ('guardrailSecret', 'agentSecret', 'redisSecret')}
        pulls = values.get('imagePullSecrets', [])
        if (not isinstance(pulls, list) or any(not isinstance(x, dict) or not isinstance(x.get('name'), str) for x in pulls)
                or len(service_names) != 3 or name in service_names
                or any(x['name'] == name for x in pulls)):
            raise ValueError
        key = backup_installation.safe_file(Path(home) / 'runtime/maintenance-key', private=True, limit=4096).strip()
        # Exact Secret identities/fields are checked; service inputs are still only
        # snapshots and do not establish live deployment configuration.
        for field, required in (('guardrailSecret', ('JWT_SECRET', 'AUDIT_LOG_HMAC_KEY')),
                                ('agentSecret', ('AGENT_INTERNAL_SHARED_SECRET',)),
                                ('redisSecret', ('password',))):
            item = service_secrets[field]
            if (item.get('kind') != 'Secret' or item.get('type') != 'Opaque' or 'stringData' in item
                    or item.get('metadata', {}).get('name') != values[field]
                    or item.get('metadata', {}).get('namespace') != site['namespace']
                    or not isinstance(item.get('data'), dict) or not 1<=len(item['data'])<=256):
                raise ValueError
            if not set(required).issubset(item['data']): raise ValueError
            for field_name, credential in item['data'].items():
                if not isinstance(credential, str) or len(credential)>16384: raise ValueError
                other = base64.b64decode(credential, validate=True).strip()
                if (field_name in required and not other) or (other and hmac.compare_digest(key, other)):
                    raise ValueError
        return {'candidate_profile_valid': True, 'process_count_verified': False,
                'safe_to_backup': False, 'safe_to_update': False, 'safe_to_restore': False}
    except Exception:
        raise ValueError('KUBERNETES_MAINTENANCE_PROFILE_UNVERIFIED') from None
