"""Experimental, durable OFF ACL file preparation; no production fence.

The caller must hold a trusted lock, bind the Redis process and admin session,
prove the signed profile and record durable intent/receipt. This module never
touches Redis, starts workloads, authorizes update, or automatically recovers an
uncertain outcome. Directory ACL state must be mounted read-only as a directory.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat

from scripts import compose_mount_inode_probe, redis_acl_experiment, redis_acl_staged

NAME='users.acl'
_ADMIN=re.compile(r'uter-maint-[a-z0-9]{1,24}\Z')
_HASH=re.compile(r'[0-9a-f]{64}\Z')


class DurableError(ValueError):pass


def render(*,admin_user,writer_hash,admin_hash,writer_on):
    if (not isinstance(admin_user,str) or not _ADMIN.fullmatch(admin_user)
            or not isinstance(writer_hash,str) or not _HASH.fullmatch(writer_hash)
            or not isinstance(admin_hash,str) or not _HASH.fullmatch(admin_hash)
            or hmac.compare_digest(writer_hash,admin_hash) or type(writer_on) is not bool):
        raise DurableError('REDIS_DURABLE_PROFILE_INVALID')
    commands=' '.join(sorted(redis_acl_experiment._UTER_TEST))
    return ('user default off -@all\n'
            'user uter-writer '+('on' if writer_on else 'off')+' #'+writer_hash+' ~* &* -@all '+commands+'\n'
            'user '+admin_user+' on #'+admin_hash+' ~* &* +@all\n').encode('ascii')


def _directory(path):
    fd=compose_mount_inode_probe._runtime_dir(path)
    info=os.fstat(fd)
    if (info.st_uid!=0 or info.st_gid!=1000 or stat.S_IMODE(info.st_mode)!=0o710):
        os.close(fd);raise ValueError
    return fd,info


def _read(directory):
    fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=999 or info.st_gid!=1000
                or stat.S_IMODE(info.st_mode)!=0o400 or info.st_nlink!=1):raise ValueError
        data=os.read(fd,65537)
        if len(data)>65536:raise ValueError
        after=os.fstat(fd);named=os.stat(NAME,dir_fd=directory,follow_symlinks=False)
        fields=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if fields(info)!=fields(after) or fields(after)!=fields(named):raise ValueError
        return data,info
    finally:os.close(fd)


class DurablePrepare:
    """Single attempt, no replay. Callback assertions alone are not fence proof."""
    def __init__(self,*,bundle,publisher,directory,admin_user,writer_hash,admin_hash,
                 lock_guard,record_intent,record_receipt):
        if (os.name!='posix' or not hasattr(os,'geteuid') or os.geteuid()!=0
                or not callable(lock_guard) or not callable(record_intent) or not callable(record_receipt)):
            raise DurableError('REDIS_DURABLE_ARGUMENT_INVALID')
        self.bundle=Path(bundle);self.publisher=Path(publisher);self.directory=Path(directory)
        self.manifest=redis_acl_staged.verify_profile(bundle,publisher)
        self.before=render(admin_user=admin_user,writer_hash=writer_hash,admin_hash=admin_hash,writer_on=True)
        self.after=render(admin_user=admin_user,writer_hash=writer_hash,admin_hash=admin_hash,writer_on=False)
        self.admin_user=admin_user;self.writer_hash=writer_hash;self.admin_hash=admin_hash
        self.guard=lock_guard;self.intent=record_intent;self.receipt=record_receipt;self.used=False
        self.prepared=None

    def _guard(self):
        if self.guard() is not True or redis_acl_staged.verify_profile(self.bundle,self.publisher)!=self.manifest:
            raise ValueError

    def prepare_off(self):
        """Durably publish OFF file, but do not modify volatile Redis ACLs."""
        directory=None;tempfd=None;name=None;temp_inode=None
        try:
            if self.used:raise ValueError
            self.used=True;self._guard()
            directory,initial_dir=_directory(self.directory)
            before,old=_read(directory)
            if before!=self.before:raise ValueError
            if self.intent('persist-writer-off') is not True:raise ValueError
            self._guard()
            same,again=_read(directory)
            if same!=before or (again.st_dev,again.st_ino)!=(old.st_dev,old.st_ino):raise ValueError
            name='.users.acl.'+secrets.token_hex(16)+'.tmp'
            tempfd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            created=os.fstat(tempfd);temp_inode=(created.st_dev,created.st_ino)
            os.fchown(tempfd,999,1000);os.fchmod(tempfd,0o400)
            with os.fdopen(tempfd,'wb') as out:
                tempfd=None;out.write(self.after);out.flush();os.fsync(out.fileno())
            named=os.stat(name,dir_fd=directory,follow_symlinks=False)
            if (named.st_dev,named.st_ino)!=temp_inode:raise ValueError
            self._guard();same,again=_read(directory)
            if same!=before or (again.st_dev,again.st_ino)!=(old.st_dev,old.st_ino):raise ValueError
            os.replace(name,NAME,src_dir_fd=directory,dst_dir_fd=directory);name=None
            os.fsync(directory)
            published,info=_read(directory)
            if published!=self.after or (info.st_dev,info.st_ino)!=temp_inode:raise ValueError
            rechecked,now=_directory(self.directory)
            try:
                if (now.st_dev,now.st_ino)!=(initial_dir.st_dev,initial_dir.st_ino):raise ValueError
            finally:os.close(rechecked)
            self._guard()
            digest=hashlib.sha256(published).hexdigest()
            if self.receipt('writer-off-file-durable',digest) is not True:raise ValueError
            self._guard();published_again,info_again=_read(directory)
            if published_again!=published or (info_again.st_dev,info_again.st_ino)!=temp_inode:raise ValueError
            named,now=_directory(self.directory)
            try:
                if (now.st_dev,now.st_ino)!=(initial_dir.st_dev,initial_dir.st_ino):raise ValueError
            finally:os.close(named)
            self.prepared=(digest,initial_dir.st_dev,initial_dir.st_ino,temp_inode)
            return {'disk_off_prepared':True,'version_sha256':digest,'redis_state_verified':False,
                    'continuous_fence_verified':False,'safe_to_backup':False,'safe_to_update':False}
        except Exception:
            raise DurableError('REDIS_DURABLE_PREPARE_UNCERTAIN') from None
        finally:
            if tempfd is not None:
                try:os.close(tempfd)
                except OSError:pass
            if name is not None and directory is not None and temp_inode is not None:
                try:
                    candidate=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    if (candidate.st_dev,candidate.st_ino)==temp_inode:os.unlink(name,dir_fd=directory)
                except OSError:pass
            if directory is not None:
                try:os.close(directory)
                except OSError:pass

    def verify_off(self):
        """Reobserve the previously prepared host file; not Redis mount proof."""
        directory=None
        try:
            if self.prepared is None:raise ValueError
            self._guard();directory,info=_directory(self.directory)
            digest,dev,ino,file_id=self.prepared
            data,item=_read(directory)
            if ((info.st_dev,info.st_ino)!=(dev,ino) or (item.st_dev,item.st_ino)!=file_id
                    or data!=self.after or hashlib.sha256(data).hexdigest()!=digest):raise ValueError
            self._guard()
            current,now=_directory(self.directory)
            try:
                if (now.st_dev,now.st_ino)!=(dev,ino):raise ValueError
            finally:os.close(current)
            return True
        except Exception:raise DurableError('REDIS_DURABLE_FILE_UNVERIFIED') from None
        finally:
            if directory is not None:os.close(directory)
