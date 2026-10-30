"""One pinned root-owned kubectl FD and an allowlisted process environment."""
import hashlib
import fcntl
import os
from pathlib import Path
import re
import stat

ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C'}


def verify(fd,expected):
    if type(fd) is not int or fd<0 or not re.fullmatch(r'[0-9a-f]{64}',expected):raise ValueError
    if not fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC:raise ValueError
    info=os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022
            or info.st_nlink!=1 or not info.st_mode&0o111 or not 0<info.st_size<=128*1024*1024):raise ValueError
    digest=hashlib.sha256();offset=0
    while offset<info.st_size:
        chunk=os.pread(fd,min(1024*1024,info.st_size-offset),offset)
        if not chunk:raise ValueError
        offset+=len(chunk);digest.update(chunk)
    after=os.fstat(fd)
    fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_mode','st_nlink')
    if digest.hexdigest()!=expected or any(getattr(info,x)!=getattr(after,x) for x in fields):raise ValueError


def open_binary(path,expected):
    value=Path(path)
    if not value.is_absolute() or '..' in value.parts:raise ValueError
    for item in (value,*value.parents):
        info=item.lstat()
        if info.st_uid!=0 or info.st_mode&0o022 or stat.S_ISLNK(info.st_mode):raise ValueError
        if item!=value and not stat.S_ISDIR(info.st_mode):raise ValueError
    fd=os.open(value,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        verify(fd,expected)
        return fd
    except BaseException:
        os.close(fd);raise
