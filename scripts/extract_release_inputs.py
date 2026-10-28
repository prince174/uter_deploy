"""Verify and safely extract a release installation archive into a new directory."""
import argparse
import hashlib
import io
import sys

sys.dont_write_bytecode = True
from pathlib import Path
import tarfile

REQUIRED = {'images.json', 'policy.toml', 'model_profiles.toml', 'publication.json'}
OPTIONAL = {f'{name}-security-summary.json' for name in ('guardrail', 'agent', 'redis')}


def extract(archive, checksum, destination, *, bundle=None, key=None, legacy_unverified=False):
    parts = checksum.read_text(encoding='utf-8').split()
    if len(parts) != 2 or parts[1] != archive.name or len(parts[0]) != 64:
        raise ValueError('Invalid checksum file')
    # Hash and extract the same bounded byte snapshot, preventing replacement between checks.
    with archive.open('rb') as stream:
        payload = stream.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError('Installation archive too large')
    actual = hashlib.sha256(payload).hexdigest()
    if (bundle is None) != (key is None):
        raise ValueError('Both signed bundle and publisher key are required')
    if bundle is None and not legacy_unverified:
        raise ValueError('A signed bundle and publisher key are required; legacy extraction must be explicit')
    if bundle is not None and legacy_unverified:
        raise ValueError('Signed and legacy modes cannot be combined')
    if bundle is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import uterctl
        manifest=uterctl.verify(bundle,key)
        if manifest.get('installation_archive_sha256') != actual:
            raise ValueError('Installation archive does not match signed manifest')
    if actual != parts[0]:
        raise ValueError('Installation archive checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or not REQUIRED <= set(names) or set(names) - REQUIRED - OPTIONAL:
            raise ValueError('Unexpected installation archive contents')
        if any(not member.isfile() or member.size > 1024 * 1024 for member in members):
            raise ValueError('Unexpected installation archive member')
        destination.mkdir(parents=True, exist_ok=False)
        for member in members:
            with tar.extractfile(member) as source, (destination / member.name).open('xb') as target:
                target.write(source.read())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('checksum', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--legacy-unverified', action='store_true', help='Explicitly permit old releases without a signed installation archive')
    args = parser.parse_args()
    extract(args.archive, args.checksum, args.destination, bundle=args.bundle, key=args.key, legacy_unverified=args.legacy_unverified)
