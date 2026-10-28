"""Adopt if needed and update an installation with a verified encrypted backup."""
import argparse
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import secrets
import sys

sys.dont_write_bytecode = True  # Signed bundles must remain byte-for-byte immutable.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import adopt_managed, backup_crypto


def update(home,bundle,publisher_key,backup_root,backup_key,*,current_bundle=None,create_backup_key=False):
    if os.name!='posix':raise ValueError('Managed update requires a Linux host')
    home=Path(home).resolve(strict=True);bundle=Path(bundle).resolve(strict=True)
    backup_root_path=Path(backup_root).absolute();backup_key_path=Path(backup_key).absolute()
    if backup_root_path.is_symlink() or backup_key_path.is_symlink():
        raise ValueError('Backup paths must not be symlinks')
    backup_root=backup_root_path.resolve();backup_key=backup_key_path.resolve()
    if backup_root==home or backup_root.is_relative_to(home):raise ValueError('Backup directory must be outside installation home')
    if backup_key==home or backup_key.is_relative_to(home) or backup_key.is_relative_to(backup_root):
        raise ValueError('Backup key must be stored separately from installation and backups')
    if not backup_root.is_dir() or backup_root.is_symlink():raise ValueError('Backup root must be an existing directory')
    if backup_root.stat().st_uid!=os.geteuid() or backup_root.stat().st_mode & 0o022:
        raise ValueError('Backup root must be owned by the current user and not writable by group or others')
    key_parent=backup_key.parent
    if not key_parent.is_dir() or key_parent.stat().st_uid!=os.geteuid() or key_parent.stat().st_mode & 0o077:
        raise ValueError('Backup key directory must be owner-only and owned by the current user')
    recovery=home/'recovery-operation.json'
    if recovery.exists() and uterctl.read(recovery).get('phase')!='complete':
        raise ValueError('Recovery is incomplete; inspect its journal before update')
    new=uterctl.verify(bundle,publisher_key)
    state_path=home/'state.json'
    if state_path.exists():
        state=uterctl.read(state_path)
        if not state.get('adopted_installer') or state.get('pending'):
            raise ValueError('Only a fully adopted installation without a pending update is supported')
        old=state['current'];uterctl.transition(old,new)
    else:
        if current_bundle is None:raise ValueError('Current signed bundle required for first adoption')
        current_bundle=Path(current_bundle).resolve(strict=True)
        old=uterctl.verify(current_bundle,publisher_key);uterctl.transition(old,new)
        cfg=uterctl.read(home/'install.json')
        if cfg.get('images')!=old['images']:raise ValueError('Current bundle does not match installed images')
    if old['version']==new['version']:raise ValueError('New release must have a different version')
    if backup_key.exists():
        if create_backup_key:raise ValueError('Backup key already exists; refusing replacement')
        backup_crypto.read_key(backup_key)
    else:
        if not create_backup_key:raise ValueError('Backup key not found; explicitly request key creation')
        backup_crypto.create_key(backup_key)
    if not state_path.exists():
        adopt_managed.adopt(home,current_bundle,publisher_key)
    label=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(8)
    destination=backup_root/('uter-'+label)
    with contextlib.redirect_stdout(io.StringIO()):
        uterctl.main(['apply','--home',str(home),'--bundle',str(bundle),'--key',str(publisher_key),
                      '--backup-dir',str(destination),'--backup-key',str(backup_key)])
    state=uterctl.read(state_path)
    return {'version':state['current']['version'],'backup':str(destination),
            'backup_id':state['last_backup']['id'],'backup_key':str(backup_key)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('home','bundle','publisher-key','backup-root','backup-key'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--current-bundle',type=Path)
    p.add_argument('--create-backup-key',action='store_true')
    a=p.parse_args()
    result=update(a.home,a.bundle,a.publisher_key,a.backup_root,a.backup_key,
                  current_bundle=a.current_bundle,create_backup_key=a.create_backup_key)
    print(json.dumps(result,indent=2))
    print('Store the backup key securely and separately; without it the backup cannot be restored.')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'update: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
