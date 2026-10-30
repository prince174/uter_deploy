"""Run disposable CI using a tracked working-tree patch, then remove its secret.

This tool never commits or prints the patch. A forced termination can prevent
cleanup: verify the dedicated secret is absent after an interrupted run.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.source_provenance import validate_secret_name

SECRET_PREFIX = 'SOURCE_SNAPSHOT_'
REPO = 'prince174/uter_deploy'
WORKFLOW = 'snapshot-protected-images.yml'
GH = shutil.which('gh') or shutil.which('gh.exe') or 'gh'


def command(args, data=None, env=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    if result.returncode:
        raise RuntimeError('Private snapshot command failed')
    return result.stdout


def source_snapshot(root, expected, normalize_crlf=False):
    env = os.environ.copy()
    env['GIT_OPTIONAL_LOCKS'] = '0'
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    env['GIT_CONFIG_GLOBAL'] = os.devnull
    prefix = ['git', '-C', str(root), '-c', 'core.fsmonitor=false']
    if normalize_crlf:
        # Explicitly opt in only when matching the original Windows Git config.
        prefix += ['-c', 'core.autocrlf=true']
    baseline = command(prefix+['rev-parse', '--verify', 'HEAD^{commit}'], env=env).strip().decode('ascii')
    if not re.fullmatch(r'[0-9a-f]{40}', baseline) or baseline != expected:
        raise ValueError('Source baseline does not match requested commit')
    patch = command(prefix+['diff', '--binary', '--no-ext-diff', '--no-renames', 'HEAD', '--'], env=env)
    if not patch or len(base64.b64encode(patch)) > 48*1024:
        raise ValueError('Tracked patch is empty or exceeds Actions secret limit')
    return baseline, patch, hashlib.sha256(patch).hexdigest()


def run(root, baseline, normalize_crlf=False, maintenance_files=False):
    # A random name separates concurrent runs. Never overwrite even on a
    # practically impossible collision with a pre-existing secret.
    secret = SECRET_PREFIX + secrets.token_hex(16).upper()
    validate_secret_name(secret)
    existing = command([GH, 'secret', 'list', '--repo', REPO]).decode('utf-8')
    if any(line.split('\t', 1)[0] == secret for line in existing.splitlines()):
        raise ValueError('Dedicated temporary snapshot secret already exists')
    _, patch, digest = source_snapshot(root, baseline, normalize_crlf)
    created = False
    try:
        # Mark before issuing the request: on an ambiguous network failure,
        # cleanup still attempts to remove a secret that might have been set.
        created = True
        print('Temporary snapshot secret: '+secret, flush=True)
        command([GH, 'secret', 'set', secret, '--repo', REPO], data=base64.b64encode(patch))
        del patch
        out = command([GH, 'workflow', 'run', WORKFLOW, '--repo', REPO, '--ref', 'main',
                       '-f', 'baseline_sha='+baseline, '-f', 'patch_sha256='+digest,
                       '-f', 'secret_name='+secret, '-f', 'maintenance_files='+str(maintenance_files).lower()]).decode('utf-8')
        match = re.search(r'https://github\.com/prince174/uter_deploy/actions/runs/([0-9]+)', out)
        if not match:
            raise RuntimeError('Workflow dispatched but its run ID was not returned')
        run_id = match.group(1)
        print('Snapshot build: '+match.group(0), flush=True)
        while True:
            result = json.loads(command([GH, 'run', 'view', run_id, '--repo', REPO,
                                         '--json', 'status,conclusion']))
            if result['status'] == 'completed':
                if result['conclusion'] != 'success': raise RuntimeError('Snapshot build did not pass')
                return run_id
            time.sleep(15)
    finally:
        if created:
            try:
                command([GH, 'secret', 'delete', secret, '--repo', REPO])
                print('Temporary snapshot secret deleted.', flush=True)
            except Exception:
                print('Temporary snapshot secret cleanup failed; verify it in GitHub Actions settings.', file=sys.stderr)
                raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--baseline', required=True)
    p.add_argument('--normalize-crlf', action='store_true', help='Use Git core.autocrlf=true when matching a Windows checkout')
    p.add_argument('--maintenance-files', action='store_true', help='Allow the reviewed maintenance protocol files in isolated CI')
    args = p.parse_args()
    run(args.source_root, args.baseline, args.normalize_crlf, args.maintenance_files)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print('Snapshot build failed or interrupted; no patch content is printed.', file=sys.stderr)
        raise SystemExit(1)
