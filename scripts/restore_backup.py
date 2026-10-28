#!/usr/bin/env python3
"""Verify and export an encrypted backup to a new private directory, without touching workloads."""
import argparse
import json
import os
from pathlib import Path
import posixpath
import sys
import tarfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import backup_crypto, backup_store


def check_tar_members(archive):
    seen=set(); entries=0
    for member in archive:
        normalized=posixpath.normpath(member.name)
        if member.name.startswith('/') or '\\' in member.name or normalized=='..' or normalized.startswith('../'):
            raise ValueError('Unsafe path in backup archive')
        if not (member.isfile() or member.isdir()):
            raise ValueError('Links and special files are forbidden in backup archives')
        if normalized in seen: raise ValueError('Duplicate archive entry')
        seen.add(normalized);entries+=1
        if member.isfile():
            source=archive.extractfile(member)
            while source.read(1024*1024): pass
    if not entries: raise ValueError('Backup archive is empty')


def check_tar(path):
    with tarfile.open(path,'r:*') as archive: check_tar_members(archive)


def export(backup, key_path, destination):
    backup=Path(backup).resolve(strict=True);key=backup_crypto.read_key(key_path);destination=Path(destination).absolute()
    if destination.exists() or destination.is_symlink(): raise ValueError('Export destination already exists')
    manifest=backup_store.verify_set(backup,key)
    destination.mkdir(mode=0o700,parents=False)
    marker=destination/'INCOMPLETE'
    marker.write_text('Sensitive recovery data. Export not completed.\n')
    if os.name=='posix': marker.chmod(0o600)
    for label,metadata in manifest['files'].items():
        name={'runtime':'runtime.tar','redis':'redis.rdb','audit':'audit.tar','kubernetes':'kubernetes.json'}[label]
        target=destination/name
        backup_crypto.decrypt_to_new_file(backup/(label+'.enc'),target,key,backup_store.aad(manifest['id'],label),metadata)
        if label in ('runtime','audit'): check_tar(target)
        if label=='redis':
            with target.open('rb') as stream:
                if stream.read(5)!=b'REDIS': raise ValueError('Invalid Redis snapshot header')
        if label=='kubernetes':
            if not isinstance(json.loads(target.read_text()),dict): raise ValueError('Invalid Kubernetes resources')
    marker.unlink()
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup',type=Path,required=True);p.add_argument('--backup-key',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();m=export(args.backup,args.backup_key,args.output)
    print('Verified backup '+m['id']+' exported to a new private directory. Contents include secrets.')


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(f'restore export: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
