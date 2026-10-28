"""Verify and safely extract a release installation archive into a new directory."""
import argparse
import hashlib
from pathlib import Path
import tarfile

REQUIRED = {'images.json', 'policy.toml', 'model_profiles.toml', 'publication.json'}
OPTIONAL = {f'{name}-security-summary.json' for name in ('guardrail', 'agent', 'redis')}


def extract(archive, checksum, destination):
    parts = checksum.read_text(encoding='utf-8').split()
    if len(parts) != 2 or parts[1] != archive.name or len(parts[0]) != 64:
        raise ValueError('Invalid checksum file')
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != parts[0]:
        raise ValueError('Installation archive checksum mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
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
    args = parser.parse_args()
    extract(args.archive, args.checksum, args.destination)
