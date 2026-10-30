"""Apply an authenticated private working-tree patch in an isolated CI checkout."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import source_provenance


_MAINTENANCE_NEW_FILES = frozenset(('agent/maintenance.py', 'guardrail/maintenance.py',
    'tests/unit/test_maintenance.py', 'tests/unit/test_maintenance_process.py'))


def apply(root, baseline, digest, secret, *, allow_maintenance_files=False):
    if not re.fullmatch(r'[0-9a-f]{40}', baseline or '') or not re.fullmatch(r'[0-9a-f]{64}', digest or ''):
        raise ValueError('Invalid snapshot identity')
    if not isinstance(secret, str) or len(secret) > 49152:
        raise ValueError('Invalid snapshot secret')
    try:
        patch = base64.b64decode(secret, validate=True)
    except (ValueError, TypeError):
        raise ValueError('Invalid snapshot secret') from None
    if not patch or hashlib.sha256(patch).hexdigest() != digest:
        raise ValueError('Snapshot fingerprint mismatch')
    root = Path(root)
    def git(*args, data=None):
        result = subprocess.run(['git', '-C', str(root), *args], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            raise ValueError('Snapshot git verification failed')
        return result.stdout
    if git('rev-parse', '--verify', 'HEAD^{commit}').strip().decode('ascii') != baseline:
        raise ValueError('Snapshot baseline mismatch')
    if git('status', '--porcelain=v1', '--untracked-files=all'):
        raise ValueError('Snapshot checkout not clean')
    git('apply', '--check', '-', data=patch)
    git('apply', '-', data=patch)
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    added = []
    for item in status.split(b'\0'):
        if not item or not item.startswith(b'?? '):
            continue
        name = item[3:].decode('utf-8')
        if not allow_maintenance_files or name not in _MAINTENANCE_NEW_FILES:
            raise ValueError('Snapshot contains an unsupported new file')
        info = (root / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Snapshot contains an unsafe new file')
        added.append(name)
    if added:
        # These are intent-to-add entries in the disposable CI index only.
        # Compare the entire resulting diff to the authenticated input so no
        # omitted or substituted file can inherit the snapshot provenance.
        git('add', '-N', '--', *sorted(added))
        if git('diff', '--binary', '--no-ext-diff', '--no-renames', 'HEAD', '--') != patch:
            raise ValueError('Snapshot diff differs from authenticated input')
    if not git('diff', '--name-only', '--no-ext-diff'):
        raise ValueError('Snapshot patch contains no tracked changes')
    state = {'kind': 'uncommitted_patch', 'baseline_commit': baseline, 'patch_sha256': digest}
    return source_provenance.validate(state, baseline)


if __name__ == '__main__':
    # Pop the value before any subprocess runs: child git does not inherit it.
    secret = os.environ.pop('SOURCE_SNAPSHOT_PATCH_B64', '')
    try:
        mode = os.environ.get('SNAPSHOT_MAINTENANCE_FILES', 'false')
        if mode not in ('true', 'false'):
            raise ValueError('Invalid snapshot mode')
        state = apply(os.environ['SNAPSHOT_ROOT'], os.environ['SNAPSHOT_BASE_SHA'],
                      os.environ['SNAPSHOT_PATCH_SHA256'], secret, allow_maintenance_files=mode == 'true')
        print(json.dumps(state, sort_keys=True))
    except Exception:
        print('Snapshot identity or application failed', file=sys.stderr)
        raise SystemExit(1)
