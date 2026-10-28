"""Populate a new empty recovery volume with a verified Redis or audit snapshot.

This primitive does not attach volumes, stop workloads, or perform a cutover.
It refuses nonempty targets, including existing Redis AOF data.
"""
import argparse
import os
from pathlib import Path
import shutil
import sys
import tarfile

# Kubernetes ConfigMap files are symlinks into a projected version directory.
# Keep the lexical mount path so the sibling archive_safety module remains importable.
sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
from scripts.archive_safety import check_tar


def empty_directory(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('Recovery volume must be an existing directory, not a symlink')
    if any(path.iterdir()):
        raise ValueError('Recovery volume is not empty; refusing to overwrite data')
    return path


def populate_redis(snapshot, destination):
    snapshot = Path(snapshot)
    if snapshot.is_symlink() or not snapshot.is_file():
        raise ValueError('Redis snapshot must be a regular file')
    with snapshot.open('rb') as src:
        if src.read(5) != b'REDIS': raise ValueError('Invalid Redis snapshot header')
        src.seek(0)
        dest = empty_directory(destination) / 'dump.rdb'
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            shutil.copyfileobj(src, out, 1024 * 1024)
            out.flush(); os.fsync(out.fileno())


def populate_audit(snapshot, destination):
    snapshot = Path(snapshot)
    if snapshot.is_symlink() or not snapshot.is_file(): raise ValueError('Invalid audit archive')
    check_tar(snapshot)
    target = empty_directory(destination)
    with tarfile.open(snapshot, 'r:*') as archive:
        members = archive.getmembers()
        def clean(name):
            while name.startswith('./'): name = name[2:]
            return '' if name == '.' else name
        for member in members:
            if '..' in Path(member.name).parts:
                raise ValueError('Parent path segments are forbidden in audit archives')
        # Compose captures ./audit.jsonl; Kubernetes captures audit/audit.jsonl.
        names = [clean(m.name) for m in members if m.isfile()]
        prefix = 'audit/' if names and all(n.startswith('audit/') for n in names) else ''
        if prefix:
            for m in members:
                name = clean(m.name)
                if name not in ('audit', 'audit/') and not name.startswith(prefix):
                    raise ValueError('Unexpected entry outside audit root')
                m.name = name[len(prefix):] if name.startswith(prefix) else '.'
        if 'audit.jsonl' not in [clean(m.name) for m in members if m.isfile()]:
            raise ValueError('Audit log is missing')
        for member in members:
            name = clean(member.name)
            if not name: continue
            path = target.joinpath(*name.split('/'))
            if member.isdir(): path.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as out, archive.extractfile(member) as src:
                    shutil.copyfileobj(src, out, 1024 * 1024)
                    out.flush(); os.fsync(out.fileno())
            else: raise ValueError('Unsupported audit entry')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=['redis', 'audit'])
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--destination', type=Path, required=True)
    args = p.parse_args()
    if not os.path.ismount(args.destination):
        raise ValueError('Destination must be an explicitly mounted recovery volume')
    (populate_redis if args.kind == 'redis' else populate_audit)(args.snapshot, args.destination)
    print('Snapshot copied into previously empty recovery volume; workload not started.')


if __name__ == '__main__':
    main()
