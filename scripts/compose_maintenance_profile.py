"""Experimental verification of a signed Compose maintenance overlay.

This observes signed files and a prepared key only. It does not inspect a live
container, prove the number of running workers, isolate traffic or Redis, or
authorize maintenance, backup, restore or update. Callers must establish the
trust and isolation of the running signed executor themselves.
"""
import base64
import hashlib
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import compose_maintenance_secret, maintenance_protocol, workload_preflight

OVERLAY = 'maintenance.yaml'
OVERLAY_SHA256 = '90fa7edac1da390c01f2cb3378841284d5a03ad8dc0e6b24c16a5663affb02d2'
_DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
_IMAGE = re.compile(r'^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$')


def _read(path, limit=65536):
    return workload_preflight.read_trusted_file(path, limit, secret=False,
                                                error='COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED')


def verify(bundle, publisher_key, home, cfg):
    """Verify the immutable profile, exact image digests and prepared key.

    Repository names can differ for a private mirror. This function never
    renders or runs Compose, and does not treat configuration as runtime proof.
    """
    try:
        if not isinstance(cfg, dict) or cfg.get('backend') != 'compose' or not compose_maintenance_secret.enabled(cfg):
            raise ValueError
        signed = maintenance_protocol.verify_capability(bundle, publisher_key)
        bundle = Path(bundle); home = Path(home)
        raw_inventory = _read(bundle/'checksums.json', 1024*1024)
        public = load_pem_public_key(_read(publisher_key, 32768))
        if not isinstance(public,Ed25519PublicKey):raise ValueError
        public.verify(base64.b64decode(_read(bundle/'checksums.sig', 1024),validate=True),raw_inventory)
        inventory = json.loads(raw_inventory)
        raw_manifest = _read(bundle/'manifest.json', 1024*1024)
        if (not isinstance(inventory,dict) or inventory.get('manifest.json') != hashlib.sha256(raw_manifest).hexdigest()
                or json.loads(raw_manifest) != signed):raise ValueError
        expected = signed['images']; images = cfg['images']
        if not isinstance(images, dict) or set(images) != {'agent', 'guardrail', 'redis'} or set(expected) != set(images):
            raise ValueError
        for name in images:
            ref = images[name]; trusted = expected[name]
            if not isinstance(ref, str) or not isinstance(trusted, str):
                raise ValueError
            parts = ref.split('@'); signed_parts = trusted.split('@')
            if (not _IMAGE.fullmatch(ref) or len(parts) != 2 or len(signed_parts) != 2 or not signed_parts[0]
                    or not _DIGEST.fullmatch(parts[1]) or parts[1] != signed_parts[1]):
                raise ValueError
        for filename in ('compose.yaml', OVERLAY):
            signed_file = _read(bundle/'compose'/filename)
            if (inventory.get('compose/'+filename) != hashlib.sha256(signed_file).hexdigest()
                    or _read(home/'compose'/filename) != signed_file):
                raise ValueError
            if filename == OVERLAY and hashlib.sha256(signed_file).hexdigest() != OVERLAY_SHA256:
                raise ValueError
        compose_maintenance_secret.read_key(home/'runtime')
        # The profile asks for one worker; container identity, actual process
        # and ability to reach loopback must be checked independently.
        return {'web_concurrency_env_requested': True, 'installation_state_verified': False, 'runtime_verified': False,
                'redis_isolated': False, 'safe_to_backup': False, 'safe_to_update': False}
    except Exception:
        raise ValueError('COMPOSE_MAINTENANCE_PROFILE_UNVERIFIED') from None
