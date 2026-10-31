"""Offline encrypted Redis ACL credentials; this does not provision workloads.

The signed Compose ACL profile is an experimental scope, not authorization to
deploy either backend. A caller must retain the 32-byte key separately. No CLI,
installer, backup/restore flow, or maintenance/update gate consumes this module.
An interrupted publication is uncertain; never retry over an existing capsule.
There is no generation pointer or anti-replay: an older authentic capsule for
the same scope can be substituted. Never use this for production recovery.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import backup_crypto, compose_mount_inode_probe, redis_acl_durable, redis_acl_staged

MAGIC=b'UTERAC1\0'
NAME='redis-acl-credentials.v1.enc'
SITE=re.compile(r'[A-Za-z0-9._-]{1,128}\Z')
SECRET=re.compile(r'[0-9a-f]{64}\Z')
ADMIN=re.compile(r'uter-maint-[0-9a-f]{16}\Z')
LIMIT=8192


class CapsuleError(ValueError):pass


def _arguments(bundle,publisher,directory,backup_key,site,backend):
    if (os.name!='posix' or os.geteuid()!=0 or not isinstance(backup_key,bytes) or len(backup_key)!=32
            or not isinstance(site,str) or not SITE.fullmatch(site) or backend!='compose'):
        raise ValueError
    manifest=redis_acl_staged.verify_profile(bundle,publisher)
    manifest_hash=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    aad=json.dumps({'schema':1,'site':site,'backend':backend,'manifest_sha256':manifest_hash},
                   sort_keys=True,separators=(',',':')).encode()
    fd=compose_mount_inode_probe._runtime_dir(directory)
    info=os.fstat(fd)
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
        os.close(fd);raise ValueError
    return manifest,aad,fd,info


def _same_directory(path,fd,original):
    other=compose_mount_inode_probe._runtime_dir(path)
    try:
        now=os.fstat(fd);named=os.fstat(other)
        ident=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,stat.S_IMODE(x.st_mode))
        if ident(original)!=ident(now) or ident(now)!=ident(named):raise ValueError
    finally:os.close(other)


def create(bundle,publisher,directory,backup_key,site,backend):
    """Create one authenticated encrypted draft with exclusive publication.

    No plaintext file is written. Errors after any write have uncertain outcome;
    inspect and authenticate any existing capsule before taking further action.
    """
    fd=None;temporary=None
    try:
        manifest,aad,fd,info=_arguments(bundle,publisher,directory,backup_key,site,backend)
        writer=secrets.token_hex(32);admin=secrets.token_hex(32)
        if hmac.compare_digest(writer,admin):raise ValueError
        admin_user='uter-maint-'+secrets.token_hex(8)
        acl=redis_acl_durable.render(admin_user=admin_user,writer_hash=hashlib.sha256(writer.encode()).hexdigest(),
                                     admin_hash=hashlib.sha256(admin.encode()).hexdigest(),writer_on=True).decode('ascii')
        payload=json.dumps({'schema':1,'writer':writer,'admin':admin,'admin_user':admin_user,'acl':acl},
                           sort_keys=True,separators=(',',':')).encode()
        nonce=secrets.token_bytes(12)
        encrypted=MAGIC+nonce+AESGCM(backup_crypto.derive_key(backup_key,b'redis-acl-credential-capsule')).encrypt(nonce,payload,aad)
        if len(encrypted)>LIMIT:raise ValueError
        temporary='.redis-acl-capsule-'+secrets.token_hex(16)
        out=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'wb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(encrypted);stream.flush();os.fsync(stream.fileno())
            file_info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid!=0 or file_info.st_nlink!=1
                    or stat.S_IMODE(file_info.st_mode)!=0o600 or file_info.st_size!=len(encrypted)):raise ValueError
        _same_directory(directory,fd,info)
        if redis_acl_staged.verify_profile(bundle,publisher)!=manifest:raise ValueError
        os.link(temporary,NAME,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
        os.fsync(fd)
        os.unlink(temporary,dir_fd=fd);temporary=None
        os.fsync(fd)
        _same_directory(directory,fd,info)
        named=os.stat(NAME,dir_fd=fd,follow_symlinks=False)
        if ((named.st_dev,named.st_ino,named.st_uid,named.st_gid,named.st_size,named.st_nlink,stat.S_IMODE(named.st_mode))
                !=(file_info.st_dev,file_info.st_ino,file_info.st_uid,file_info.st_gid,len(encrypted),1,0o600)):raise ValueError
        return {'capsule_created':True,'workloads_configured':False,'safe_to_update':False}
    except Exception:raise CapsuleError('REDIS_ACL_CAPSULE_CREATE_UNCERTAIN') from None
    finally:
        if fd is not None:
            if temporary is not None:
                try:os.unlink(temporary,dir_fd=fd)
                except OSError:pass
            os.close(fd)


def read(bundle,publisher,directory,backup_key,site,backend):
    """Authenticate a draft in memory; never publish files or start Redis."""
    directory_fd=None;file_fd=None
    try:
        manifest,aad,directory_fd,info=_arguments(bundle,publisher,directory,backup_key,site,backend)
        file_fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
        before=os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=0
                or stat.S_IMODE(before.st_mode)!=0o600 or not len(MAGIC)+12+16<=before.st_size<=LIMIT):raise ValueError
        raw=os.read(file_fd,LIMIT+1)
        after=os.fstat(file_fd);named=os.stat(NAME,dir_fd=directory_fd,follow_symlinks=False)
        fields=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if fields(before)!=fields(after) or fields(after)!=fields(named) or len(raw)!=before.st_size or not raw.startswith(MAGIC):raise ValueError
        data=AESGCM(backup_crypto.derive_key(backup_key,b'redis-acl-credential-capsule')).decrypt(
            raw[len(MAGIC):len(MAGIC)+12],raw[len(MAGIC)+12:],aad)
        payload=json.loads(data)
        if (not isinstance(payload,dict) or set(payload)!={'schema','writer','admin','admin_user','acl'}
                or type(payload['schema']) is not int or payload['schema']!=1 or not isinstance(payload['writer'],str) or not SECRET.fullmatch(payload['writer'])
                or not isinstance(payload['admin'],str) or not SECRET.fullmatch(payload['admin'])
                or hmac.compare_digest(payload['writer'],payload['admin']) or not isinstance(payload['admin_user'],str)
                or not ADMIN.fullmatch(payload['admin_user'])):raise ValueError
        expected=redis_acl_durable.render(admin_user=payload['admin_user'],writer_hash=hashlib.sha256(payload['writer'].encode()).hexdigest(),
                    admin_hash=hashlib.sha256(payload['admin'].encode()).hexdigest(),writer_on=True).decode('ascii')
        if payload['acl']!=expected:raise ValueError
        _same_directory(directory,directory_fd,info)
        if redis_acl_staged.verify_profile(bundle,publisher)!=manifest:raise ValueError
        return payload
    except Exception:raise CapsuleError('REDIS_ACL_CAPSULE_UNVERIFIED') from None
    finally:
        if file_fd is not None:os.close(file_fd)
        if directory_fd is not None:os.close(directory_fd)
