#!/usr/bin/env python3
"""Verify a pair of public releases before a disposable GitHub-hosted upgrade."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import extract_release_inputs, extract_signed_bundle
from scripts.verify_release_pair import verify_pair

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = '65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2'
TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?\Z')


def check_inputs(old_tag, new_tag, old_version, new_version):
    if (not TAG.fullmatch(old_tag) or not TAG.fullmatch(new_tag) or old_tag == new_tag
            or not VERSION.fullmatch(old_version) or not VERSION.fullmatch(new_version)
            or old_version == new_version):
        raise ValueError('Invalid distinct release tags or versions')


def tag_commit(root, tag):
    if not TAG.fullmatch(tag):
        raise ValueError('Invalid tag')
    try:
        output = subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--verify',
                                          'refs/tags/' + tag + '^{commit}'],
                                         stderr=subprocess.DEVNULL, timeout=15, text=True).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError('Release tag cannot be resolved') from None
    if not re.fullmatch(r'[0-9a-f]{40}', output):
        raise ValueError('Invalid tag commit')
    return output


def verify_assets(root, old_tag, new_tag, old_version, new_version, *, resolve_tag=tag_commit):
    check_inputs(old_tag, new_tag, old_version, new_version)
    root = Path(root)
    work = root / 'work'
    old, new = work / 'pair' / 'old', work / 'pair' / 'new'
    for side in (old, new):
        key = side / 'publisher-public.pem'
        if key.is_symlink() or not key.is_file() or key.stat().st_size > 4096:
            raise ValueError('Invalid public key asset')
        if hashlib.sha256(key.read_bytes()).hexdigest() != FINGERPRINT:
            raise ValueError('Publisher fingerprint mismatch')
    if (old / 'publisher-public.pem').read_bytes() != (new / 'publisher-public.pem').read_bytes():
        raise ValueError('Publisher keys differ')
    # The extraction code validates the signed inventory before exposing files.
    for side in (old, new):
        extract_signed_bundle.extract(side / 'signed-bundle.tar.gz', side / 'publisher-public.pem', side / 'bundle')
    previous, current = verify_pair(old / 'bundle', new / 'bundle', old / 'publisher-public.pem',
                                    FINGERPRINT, old_version, new_version)
    if not previous.get('installation_archive_sha256') or not current.get('installation_archive_sha256'):
        raise ValueError('Both releases must authenticate installation inputs')
    # Compare the signed commit to the exact tag, not to the workflow branch.
    if current.get('deployment_commit') != resolve_tag(root, new_tag):
        raise ValueError('New signed deployment commit does not match the selected tag')
    if previous.get('deployment_commit') != resolve_tag(root, old_tag):
        raise ValueError('Old signed deployment commit does not match the selected tag')
    inputs = work / 'input'
    inputs.mkdir(mode=0o700, parents=True, exist_ok=False)
    for side, name in ((old, 'published-old'), (new, 'published-new')):
        extract_release_inputs.extract(side / 'installation-inputs.tar.gz',
                                       side / 'installation-inputs.tar.gz.sha256', inputs / name,
                                       bundle=side / 'bundle', key=side / 'publisher-public.pem')
    old_digest = {name: ref.rsplit('@', 1)[-1] for name, ref in previous['images'].items()}
    new_digest = {name: ref.rsplit('@', 1)[-1] for name, ref in current['images'].items()}
    return {'old_tag': old_tag, 'new_tag': new_tag, 'old_version': old_version, 'new_version': new_version,
            'signatures': 'verified', 'input_archive_hashes': 'verified', 'tag_commits': 'verified',
            'transition_and_data_epoch': 'verified',
            'product_image_digests_unchanged': old_digest == new_digest,
            'arbitrary_data_migration': 'not_verified'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('old-tag', 'new-tag', 'old-version', 'new-version'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    if (os.name != 'posix' or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux'
            or Path(os.environ.get('GITHUB_WORKSPACE', '/nonexistent')).resolve() != ROOT.resolve()):
        raise SystemExit('Disposable GitHub-hosted Linux runner required')
    report = verify_assets(ROOT, args.old_tag, args.new_tag, args.old_version, args.new_version)
    evidence = ROOT / 'work' / 'release-upgrade-preflight.json'
    with evidence.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Release upgrade preflight failed; inspect inputs and signatures.', file=sys.stderr)
        sys.exit(1)
