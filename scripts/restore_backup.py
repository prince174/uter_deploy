#!/usr/bin/env python3
"""Verify and export an encrypted backup to a new private directory, without touching workloads."""
import argparse
import json
import os
from pathlib import Path
import posixpath
import sys
import tarfile

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import backup_crypto, backup_store
from scripts.archive_safety import check_tar, check_tar_members


def stage_archive(path, destination):
    """Extract a validated archive into a new private directory; never overwrite live data."""
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('Staging destination already exists')
    # Validate the entire archive before creating any destination content.
    check_tar(path)
    destination.mkdir(mode=0o700, parents=False)
    with tarfile.open(path,'r:*') as archive:
        for member in archive:
            normalized=posixpath.normpath(member.name)
            if (member.name.startswith('/') or '\\' in member.name or normalized == '..'
                    or normalized.startswith('../') or not (member.isfile() or member.isdir())):
                raise ValueError('Unsafe entry in staging archive')
            target=destination.joinpath(*normalized.split('/'))
            if member.isdir():
                target.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as out, archive.extractfile(member) as source:
                    while True:
                        block=source.read(1024*1024)
                        if not block:break
                        out.write(block)
    return destination


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


def prepare_staging(backup, key_path, destination):
    """Decrypt and unpack into a new directory only; no running workload is modified."""
    manifest=export(backup,key_path,destination)
    destination=Path(destination)
    marker=destination/'INCOMPLETE'
    marker.write_text('Sensitive recovery data. Staging not completed.\n')
    if os.name=='posix': marker.chmod(0o600)
    stage_archive(destination/'runtime.tar',destination/'runtime-staged')
    stage_archive(destination/'audit.tar',destination/'audit-staged')
    marker.unlink()
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup',type=Path,required=True);p.add_argument('--backup-key',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--stage',action='store_true',help='Also unpack archives into new private staging directories')
    args=p.parse_args();m=(prepare_staging if args.stage else export)(args.backup,args.backup_key,args.output)
    print('Verified backup '+m['id']+' exported to a new private directory. Contents include secrets; workloads are unchanged.')


if __name__=='__main__':
    try: main()
    except Exception as exc:
        print(f'restore export: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
