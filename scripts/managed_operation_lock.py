"""Experimental unified authenticated operation-lock capability.

Not yet wired to uterctl. Trust the local filesystem, installation owner,
host PID/proc namespace and every controller using this protocol. Old O_EXCL
controllers must not run concurrently. Reclaim proves only lock-owner death;
it never proves completion of any previously submitted Docker/API request.
Legacy PID-only sentinels and uncertain metadata are never reclaimed.
"""
from contextlib import contextmanager
import fcntl
import hmac
import os
from pathlib import Path
import secrets
import stat

from scripts import backup_installation, experimental_operation_lock as primitive

KEY_NAME='.operation-lock-key'
_HELD={}


class ManagedLockError(ValueError): pass


def _key(home,*,create):
    try:
        home=backup_installation.private_directory(home)
        directory=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            try:
                fd=os.open(KEY_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            except FileNotFoundError:
                if not create or os.path.lexists(home/primitive.SENTINEL) or os.path.lexists(home/primitive.OWNER):
                    raise ManagedLockError('MANAGED_LOCK_KEY_MISSING') from None
                try:
                    fd=os.open(KEY_NAME,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
                    try:
                        os.fchmod(fd,0o600);primitive._write_all(fd,secrets.token_bytes(32));os.fsync(fd)
                    finally:os.close(fd)
                    os.fsync(directory)
                except FileExistsError:
                    # A concurrent initializer may have created an incomplete
                    # key. The bounded private read below decides; never retry
                    # by replacing it.
                    pass
                fd=os.open(KEY_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            try:
                info=os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                        or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size!=32):
                    raise ManagedLockError('MANAGED_LOCK_KEY_UNSAFE')
                value=os.read(fd,33)
                if len(value)!=32:raise ManagedLockError('MANAGED_LOCK_KEY_UNSAFE')
                # Re-establish durability if an earlier initializer was
                # interrupted after writing but before directory fsync.
                os.fsync(fd);os.fsync(directory)
                return home,value
            finally:os.close(fd)
        finally:os.close(directory)
    except ManagedLockError:raise
    except Exception:raise ManagedLockError('MANAGED_LOCK_KEY_UNVERIFIED') from None


def assert_held(home):
    """Require this process's authenticated Lease and continuously held gate."""
    try:
        home=backup_installation.private_directory(home)
        lease=_HELD.get(str(home))
        if lease is None or lease.record is None or lease.gate is None or lease.directory is None:raise ValueError
        _,key=_key(home,create=False)
        if not hmac.compare_digest(key,lease.key):raise ValueError
        record=lease.record
        if (record['pid']!=os.getpid() or record['start']!=primitive._identity(os.getpid())
                or record['boot']!=primitive._boot() or primitive._read_owner(lease.directory,lease.key)!=record):raise ValueError
        primitive._assert_owner(lease.directory,record)
        gate=os.fstat(lease.gate);named=os.stat(primitive.GATE,dir_fd=lease.directory,follow_symlinks=False)
        directory=os.fstat(lease.directory);actual=home.stat()
        if (not stat.S_ISREG(gate.st_mode) or gate.st_uid!=os.geteuid() or gate.st_mode&0o077
                or (gate.st_dev,gate.st_ino)!=(named.st_dev,named.st_ino) or gate.st_nlink!=1
                or (directory.st_dev,directory.st_ino)!=(actual.st_dev,actual.st_ino)):raise ValueError
        probe=os.open(primitive.GATE,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=lease.directory)
        try:
            try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:pass
            else:
                fcntl.flock(probe,fcntl.LOCK_UN)
                raise ValueError
            # The registered description must itself still own the lock.
            fcntl.flock(lease.gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(probe)
    except Exception:raise ManagedLockError('MANAGED_LOCK_NOT_HELD') from None


@contextmanager
def locked(home,*,reclaim=False):
    """Acquire a fresh lease or explicitly reclaim its authenticated dead owner.

    Reclaim is a lock-only operation. Caller must independently constrain and
    recheck safe journal phases; never use it to retry an unknown workload call.
    """
    home,key=_key(home,create=not reclaim)
    if str(home) in _HELD:raise ManagedLockError('MANAGED_LOCK_ALREADY_HELD')
    lease=None;owned=False
    try:
        try:lease=primitive.Lease(home,key,secrets.token_hex(16))
        except primitive.LockError:raise
        except Exception:raise ManagedLockError('MANAGED_LOCK_ENVIRONMENT_UNVERIFIED') from None
        if reclaim:
            try:owner=primitive._read_owner(lease.directory,key)
            except Exception:raise ManagedLockError('MANAGED_LOCK_OWNER_UNVERIFIED') from None
            lease.operation=owner['operation']
            lease.reclaim()
        else:lease.acquire()
        _HELD[str(home)]=lease
        assert_held(home)
        owned=True
        yield
    finally:
        if lease is not None:
            try:
                if owned and lease.record is not None:
                    assert_held(home)
                    lease.release()
            finally:
                _HELD.pop(str(home),None)
                lease.close()
