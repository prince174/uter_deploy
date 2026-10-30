"""Synthetic stdin-only redis-check-rdb probe; disposable hosted CI only."""
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid

from scripts import experimental_rdb_probe as shared

# Same image referenced by the 0.1.6 and gated 0.1.7 published manifests.
IMAGE = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'
LABEL = 'io.uter-deploy.synthetic-rdb-stdin'


def verify_stream(container, snapshot, execute=subprocess.run):
    """Never print checker output: diagnostics may include Redis key names."""
    if not re.fullmatch(r'[0-9a-f]{64}', container) or not snapshot.startswith(b'REDIS') or len(snapshot) < 32:
        raise RuntimeError('invalid synthetic fixture')
    corrupt = snapshot[:-1] + bytes([snapshot[-1] ^ 1])
    tests = ((snapshot, True), (corrupt, False), (snapshot[:-8], False))
    for payload, valid in tests:
        result = execute(['docker', '--context', 'default', 'exec', '-i', container,
                          'redis-check-rdb', '/dev/stdin'], input=payload,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         check=False, timeout=shared.TIMEOUT_SECONDS)
        if (result.returncode == 0) != valid:
            raise RuntimeError('stdin RDB validation returned an unexpected status')


def main():
    shared.runner_guard(os.environ)
    if shared.run(['docker', 'context', 'show']).strip() != b'default':
        raise RuntimeError('nondefault context')
    details = json.loads(shared.run(['docker', '--context', 'default', 'context', 'inspect', 'default']))
    if (not isinstance(details, list) or len(details) != 1 or
            details[0].get('Endpoints', {}).get('docker', {}).get('Host') != 'unix:///var/run/docker.sock'):
        raise RuntimeError('default context must use local Linux socket')
    container = None
    uncertain = False
    owner = uuid.uuid4().hex
    try:
        uncertain = True
        container = shared.run(['docker', '--context', 'default', 'run', '-d', '--label', f'{LABEL}={owner}',
                                '--network', 'none', '--tmpfs', '/data:rw,mode=1777',
                                '--log-driver', 'none', IMAGE, 'redis-server', '--save', '',
                                '--appendonly', 'no']).decode().strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container):
            container = None
            raise RuntimeError('unexpected container identifier')
        uncertain = False
        def redis(*args, data=None):
            return shared.run(['docker', '--context', 'default', 'exec', '-i', container,
                               'redis-cli', *args], data=data).strip()
        import time
        for _ in range(50):
            try:
                if redis('PING') == b'PONG':
                    break
            except RuntimeError:
                pass
            time.sleep(.1)
        else:
            raise RuntimeError('synthetic Redis not ready')
        # Only fixed synthetic data, including binary payload larger than a pipe buffer.
        fixture = b''.join(hashlib.sha256(i.to_bytes(4, 'big')).digest() for i in range(8192))
        if redis('-x', 'SET', 'sess:synthetic', data=fixture) != b'OK':
            raise RuntimeError('synthetic data initialization failed')
        if redis('SAVE') != b'OK':
            raise RuntimeError('synthetic save failed')
        snapshot = shared.run(['docker', '--context', 'default', 'exec', container, 'cat', '/data/dump.rdb'])
        verify_stream(container, snapshot)
    finally:
        cleanup_failed = uncertain
        if container:
            try:
                template = '{{.Id}} {{index .Config.Labels "' + LABEL + '"}}'
                identity = shared.run(['docker', '--context', 'default', 'inspect', '--format', template, container]).decode().strip()
                if identity != f'{container} {owner}':
                    raise RuntimeError('synthetic container ownership mismatch')
                removed = shared.run(['docker', '--context', 'default', 'rm', '-f', container]).decode().strip()
                if removed != container:
                    raise RuntimeError('synthetic container removal mismatch')
            except (RuntimeError, OSError, subprocess.TimeoutExpired, UnicodeError):
                cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError('synthetic Docker cleanup unconfirmed')
    print('Synthetic RDB stdin checks passed; cleanup confirmed.')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as exc:
        raise SystemExit('Synthetic stdin test failed: ' + str(exc))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise SystemExit('Synthetic stdin test failed: ' + type(exc).__name__)
