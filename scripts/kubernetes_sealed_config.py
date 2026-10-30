"""Keep a pinned kubeconfig in a sealed Linux memfd for exact child requests.

This is not an isolation proof. The administrator must provision the pin
independently; cluster identity, writer exclusion, CNI, CSI and signed workload
must still be verified. Only trusted kubectl child processes receive this fd.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import os
import stat

from scripts import kubernetes_fence_pin as pin

SEALS=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE


class SealedConfigError(ValueError): pass


def _read_fd(fd):
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 1<=info.st_size<=pin.MAX_CONFIG:raise ValueError
    result=bytearray();offset=0
    while offset<info.st_size:
        block=os.pread(fd,min(65536,info.st_size-offset),offset)
        if not block:raise ValueError
        result.extend(block);offset+=len(block)
    if len(result)!=info.st_size:raise ValueError
    return bytes(result)


def verify_sealed(fd,expected_sha256=None):
    """Recheck seals and content without exposing kubeconfig data."""
    try:
        if (type(fd) is not int or fd<0 or fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS!=SEALS
                or not fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC):
            raise ValueError
        raw=_read_fd(fd);digest=hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(digest,expected_sha256):raise ValueError
        return digest
    except (OSError,ValueError,TypeError):raise SealedConfigError('KUBE_CONFIG_SEAL_UNVERIFIED') from None


@contextmanager
def sealed(raw,profile):
    """Validate first, then create an immutable in-memory credential file."""
    pin.verify_config(raw,profile)
    fd=None
    try:
        if not hasattr(os,'memfd_create') or not hasattr(os,'MFD_ALLOW_SEALING'):
            raise ValueError
        fd=os.memfd_create('uter-kubeconfig',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        view=memoryview(raw)
        while view:
            count=os.write(fd,view)
            if count<=0:raise ValueError
            view=view[count:]
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
        expected=hashlib.sha256(raw).hexdigest()
        verify_sealed(fd,expected)
        if not fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC:raise ValueError
    except BaseException as error:
        if fd is not None:os.close(fd)
        if isinstance(error,(pin.PinError,SealedConfigError)):raise
        if isinstance(error,(OSError,ValueError,TypeError)):
            raise SealedConfigError('KUBE_CONFIG_SEAL_UNVERIFIED') from None
        raise
    try:
        yield fd,expected
    finally:os.close(fd)
