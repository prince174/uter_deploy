"""Validate two published signed bundles and their compatibility before CI work."""
import argparse
import hashlib
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uterctl


def verify_pair(old, new, key, fingerprint, old_version, new_version):
    if hashlib.sha256(Path(key).read_bytes()).hexdigest() != fingerprint:
        raise ValueError('Publisher fingerprint mismatch')
    previous = uterctl.verify(old, key)
    current = uterctl.verify(new, key)
    if previous['version'] != old_version or current['version'] != new_version:
        raise ValueError('Unexpected release version')
    if previous['version'] == current['version']:
        raise ValueError('Two different releases are required')
    uterctl.transition(previous, current)
    if not current.get('installation_archive_sha256'):
        raise ValueError('New release must authenticate installation archive')
    return previous, current


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('old', 'new', 'key'):
        parser.add_argument('--'+arg, type=Path, required=True)
    for arg in ('fingerprint', 'old-version', 'new-version'):
        parser.add_argument('--'+arg, required=True)
    args = parser.parse_args()
    verify_pair(args.old, args.new, args.key, args.fingerprint, args.old_version, args.new_version)
    print('Published release signatures and permitted upgrade verified')
