"""One-shot offline ACL layout staging, not an installer or recovery path.

Only a new private staging directory containing one verified capsule is
accepted. No workload, Docker, Kubernetes, installer or update gate is touched.
An incomplete attempt that remains on disk cannot be automatically retried.
It contains plaintext credentials, even on failure. A receipt can be left behind
after an error; its presence alone is never proof of successful staging. The
HMAC receipt binds this draft, but is not an anti-replay or a fence proof.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat

from scripts import backup_crypto, compose_mount_inode_probe, redis_acl_credential_capsule as capsule, redis_acl_staged

STAGE='redis-acl-stage'


class StageError(ValueError):pass


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _write(directory,name,data,uid,gid,mode):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        os.fchown(fd,uid,gid);os.fchmod(fd,mode)
        with os.fdopen(os.dup(fd),'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        info=os.fstat(fd);named=os.stat(name,dir_fd=directory,follow_symlinks=False)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,stat.S_IMODE(x.st_mode),x.st_nlink,x.st_size)
        if (not stat.S_ISREG(info.st_mode) or identity(info)!=identity(named)
                or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_nlink,info.st_size)
                !=(uid,gid,mode,1,len(data))):raise ValueError
    finally:os.close(fd)


def _read(directory,name,uid,gid,mode):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_nlink)
                !=(uid,gid,mode,1) or before.st_size>8192):raise ValueError
        data=os.read(fd,8193);after=os.fstat(fd);named=os.stat(name,dir_fd=directory,follow_symlinks=False)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if identity(before)!=identity(after) or identity(after)!=identity(named) or len(data)!=before.st_size:raise ValueError
        return data
    finally:os.close(fd)


def prepare(bundle,publisher,directory,backup_key,site):
    """Prepare one offline ACL draft; any failure after mkdir is uncertain."""
    parent=None;stage=None;acl_dir=None
    try:
        payload,capsule_sha=capsule._load(bundle,publisher,directory,backup_key,site,'compose')
        manifest=redis_acl_staged.verify_profile(bundle,publisher)
        manifest_sha=hashlib.sha256(_json(manifest)).hexdigest()
        parent=compose_mount_inode_probe._runtime_dir(directory);parent_info=os.fstat(parent)
        if (parent_info.st_uid!=0 or stat.S_IMODE(parent_info.st_mode)!=0o700
                or set(os.listdir(parent))!={capsule.NAME}):raise ValueError
        capsule._same_directory(directory,parent,parent_info)
        if capsule._load(bundle,publisher,directory,backup_key,site,'compose')!=(payload,capsule_sha):raise ValueError
        stage_id=secrets.token_hex(16)
        binding={'schema':1,'stage_id':stage_id,'site':site,'backend':'compose',
                 'manifest_sha256':manifest_sha,'capsule_sha256':capsule_sha}
        key=backup_crypto.derive_key(backup_key,b'redis-acl-offline-stage')
        intent={'binding':binding,'phase':'intent'}
        intent_data=_json({'record':intent,'hmac':backup_crypto.sign_manifest(intent,key)})
        os.mkdir(STAGE,0o700,dir_fd=parent)
        stage=os.open(STAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        os.fchown(stage,0,0);os.fchmod(stage,0o700);stage_info=os.fstat(stage)
        if (stage_info.st_uid,stage_info.st_gid,stat.S_IMODE(stage_info.st_mode))!=(0,0,0o700):raise ValueError
        os.fsync(parent)
        _write(stage,'intent.json',intent_data,0,0,0o600);os.fsync(stage)
        _write(stage,'writer-password',payload['writer'].encode('ascii'),0,0,0o600)
        _write(stage,'admin-password',payload['admin'].encode('ascii'),0,0,0o600)
        os.mkdir('acl',0o700,dir_fd=stage)
        acl_dir=os.open('acl',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=stage)
        os.fchown(acl_dir,0,1000);os.fchmod(acl_dir,0o710);acl_info=os.fstat(acl_dir)
        if (acl_info.st_uid,acl_info.st_gid,stat.S_IMODE(acl_info.st_mode))!=(0,1000,0o710):raise ValueError
        _write(acl_dir,'users.acl',payload['acl'].encode('ascii'),999,1000,0o400)
        os.fsync(acl_dir);os.fsync(stage)
        # Read exactly what was written, without putting secrets in the receipt.
        for name,value in (('writer-password',payload['writer']),('admin-password',payload['admin'])):
            if not hmac.compare_digest(_read(stage,name,0,0,0o600),value.encode('ascii')):raise ValueError
        if not hmac.compare_digest(_read(acl_dir,'users.acl',999,1000,0o400),payload['acl'].encode('ascii')):raise ValueError
        receipt={'binding':binding,'phase':'staged','acl_sha256':hashlib.sha256(payload['acl'].encode('ascii')).hexdigest()}
        receipt_data=_json({'record':receipt,'hmac':backup_crypto.sign_manifest(receipt,key)})
        _write(stage,'receipt.json',receipt_data,0,0,0o600);os.fsync(stage);os.fsync(parent)
        capsule._same_directory(directory,parent,parent_info)
        stage_named=os.stat(STAGE,dir_fd=parent,follow_symlinks=False)
        acl_named=os.stat('acl',dir_fd=stage,follow_symlinks=False)
        if ((stage_info.st_dev,stage_info.st_ino,stage_info.st_uid,stage_info.st_gid,stat.S_IMODE(stage_info.st_mode))
                !=(stage_named.st_dev,stage_named.st_ino,stage_named.st_uid,stage_named.st_gid,stat.S_IMODE(stage_named.st_mode))
                or (acl_info.st_dev,acl_info.st_ino,acl_info.st_uid,acl_info.st_gid,stat.S_IMODE(acl_info.st_mode))
                !=(acl_named.st_dev,acl_named.st_ino,acl_named.st_uid,acl_named.st_gid,stat.S_IMODE(acl_named.st_mode))
                or set(os.listdir(stage))!={'intent.json','writer-password','admin-password','acl','receipt.json'}
                or set(os.listdir(acl_dir))!={'users.acl'}
                or _read(stage,'intent.json',0,0,0o600)!=intent_data
                or _read(stage,'receipt.json',0,0,0o600)!=receipt_data
                or not hmac.compare_digest(_read(stage,'writer-password',0,0,0o600),payload['writer'].encode('ascii'))
                or not hmac.compare_digest(_read(stage,'admin-password',0,0,0o600),payload['admin'].encode('ascii'))
                or not hmac.compare_digest(_read(acl_dir,'users.acl',999,1000,0o400),payload['acl'].encode('ascii'))
                or redis_acl_staged.verify_profile(bundle,publisher)!=manifest
                or capsule._load(bundle,publisher,directory,backup_key,site,'compose')!=(payload,capsule_sha)):
            raise ValueError
        return {'staged':True,'workloads_configured':False,'safe_to_install':False,
                'safe_to_backup':False,'safe_to_update':False}
    except Exception:raise StageError('REDIS_ACL_STAGE_UNCERTAIN') from None
    finally:
        for fd in (acl_dir,stage,parent):
            if fd is not None:os.close(fd)
