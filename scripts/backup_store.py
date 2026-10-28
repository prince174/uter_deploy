"""Encrypted, authenticated backup-set storage; source capture is supplied separately."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from scripts import backup_crypto

REQUIRED = {'compose': {'runtime', 'redis', 'audit'},
            'helm': {'runtime', 'redis', 'audit', 'kubernetes'}}


def installation_fingerprint(home, site):
    data = json.dumps({'home':str(Path(home).resolve()),'backend':site['backend'],
                       'name':site['name'],'namespace':site['namespace'],
                       'context':site.get('context')},sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(data).hexdigest()


def aad(backup_id, label):
    return ('uter-backup-v1:'+backup_id+':'+label).encode()


class BackupWriter:
    def __init__(self, destination, key, home, site, version):
        self.path=Path(destination).resolve()
        home=Path(home).resolve()
        if self.path == home or self.path.is_relative_to(home):
            raise ValueError('Backup must be stored outside installation home')
        if site.get('backend') not in REQUIRED: raise ValueError('Unsupported backup backend')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?',version): raise ValueError('Invalid version')
        if self.path.exists(): raise ValueError('Backup destination already exists')
        self.path.mkdir(mode=0o700,parents=False)
        self.key=key
        self.manifest={'schema':1,'id':secrets.token_hex(16),'created_at':datetime.now(timezone.utc).isoformat(),
                       'installation':installation_fingerprint(home,site),'backend':site['backend'],
                       'version':version,'files':{}}

    def put(self, label, source):
        return self.write_component(label, lambda stream: backup_crypto.encrypt_stream(source, stream, self.key, aad(self.manifest['id'], label)))

    def put_generated(self, label, generate):
        def write(stream):
            writer=backup_crypto.EncryptedStreamWriter(stream,self.key,aad(self.manifest['id'],label))
            generate(writer)
            return writer.finish()
        return self.write_component(label, write)

    def write_component(self, label, write):
        if label not in REQUIRED[self.manifest['backend']] or label in self.manifest['files']:
            raise ValueError('Unexpected or duplicate backup component')
        path=self.path/(label+'.enc')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                meta=write(stream)
                stream.flush();os.fsync(stream.fileno())
            if not meta['plaintext_bytes']: raise ValueError('Empty backup component')
            backup_crypto.decrypt_verify(path,self.key,aad(self.manifest['id'],label),meta)
            self.manifest['files'][label]=meta
        except BaseException:
            path.unlink(missing_ok=True);raise

    def finish(self):
        if set(self.manifest['files']) != REQUIRED[self.manifest['backend']]:
            raise ValueError('Incomplete backup; no receipt issued')
        data={'manifest':self.manifest,'mac':backup_crypto.sign_manifest(self.manifest,self.key)}
        path=self.path/'manifest.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(data,stream,sort_keys=True,indent=2);stream.flush();os.fsync(stream.fileno())
        verify_set(self.path,self.key)
        return self.manifest


def verify_set(path, key, *, home=None, site=None, version=None):
    path=Path(path)
    if not path.is_dir() or path.is_symlink() or (path/'manifest.json').is_symlink(): raise ValueError('Invalid backup directory')
    data=json.loads((path/'manifest.json').read_text(encoding='utf-8'))
    manifest=data['manifest'];backup_crypto.verify_manifest(manifest,data['mac'],key)
    backend=manifest.get('backend');files=manifest.get('files')
    if manifest.get('schema')!=1 or backend not in REQUIRED or not isinstance(files,dict) or set(files)!=REQUIRED[backend]:
        raise ValueError('Invalid or incomplete backup manifest')
    if not re.fullmatch(r'[0-9a-f]{32}',manifest.get('id','')): raise ValueError('Invalid backup ID')
    if version is not None and manifest['version']!=version: raise ValueError('Backup version mismatch')
    if home is not None and (site is None or manifest['installation']!=installation_fingerprint(home,site)):
        raise ValueError('Backup belongs to a different installation')
    for label,meta in files.items():
        item=path/(label+'.enc')
        if not item.is_file() or item.is_symlink(): raise ValueError('Missing backup component')
        backup_crypto.decrypt_verify(item,key,aad(manifest['id'],label),meta)
    return manifest
