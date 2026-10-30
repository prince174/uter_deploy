"""Private Compose maintenance-key handling; does not authorize maintenance.

The opt-in is intentionally not provisioned by the installer yet. Backups are
encrypted by their caller; the validation here is not an ingress/Redis fence.
"""
import os
from pathlib import Path
import re
import stat

KEY_NAME = 'maintenance-key'
_KEY = re.compile(rb'[!-~]{32,4096}\Z')


def enabled(cfg):
    value = cfg.get('maintenance_enabled', False)
    if type(value) is not bool:
        raise ValueError('MAINTENANCE_CONFIG_INVALID')
    return value


def _open_key(runtime):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        directory = os.open(Path(runtime), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        dstat = os.fstat(directory)
        named_dir = os.stat(Path(runtime), follow_symlinks=False)
        if (not stat.S_ISDIR(dstat.st_mode) or (dstat.st_dev, dstat.st_ino) != (named_dir.st_dev, named_dir.st_ino)
                or dstat.st_uid != os.geteuid() or stat.S_IMODE(dstat.st_mode) != 0o700):
            raise ValueError
        fd = os.open(KEY_NAME, flags, dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError
        return fd, info, directory, dstat
    except Exception:
        if 'fd' in locals():
            os.close(fd)
        if 'directory' in locals():
            os.close(directory)
        raise ValueError('MAINTENANCE_KEY_UNVERIFIED') from None


def read_key(runtime, *, staged=False):
    """Read bounded content and confirm the path still names the opened file."""
    fd, info, directory, dstat = _open_key(runtime)
    try:
        owner = os.geteuid() if staged else 10001
        mode = 0o600 if staged else 0o400
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError
        if not staged and info.st_gid != 10001:
            raise ValueError
        with os.fdopen(os.dup(fd), 'rb') as source:
            data = source.read(4097)
        after = os.fstat(fd)
        named = os.stat(KEY_NAME, dir_fd=directory, follow_symlinks=False)
        named_dir = os.stat(Path(runtime), follow_symlinks=False)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_uid, x.st_gid, x.st_mode, x.st_nlink)
        if (identity(info) != identity(after) or identity(after) != identity(named)
                or (dstat.st_dev, dstat.st_ino) != (named_dir.st_dev, named_dir.st_ino)
                or not _KEY.fullmatch(data)):
            raise ValueError
        return data
    except Exception:
        raise ValueError('MAINTENANCE_KEY_UNVERIFIED') from None
    finally:
        os.close(fd)
        os.close(directory)


def prepare_restored_key(runtime, expected):
    """Restore container access without following links or changing key bytes."""
    if read_key(runtime, staged=True) != expected:
        raise ValueError('MAINTENANCE_KEY_UNVERIFIED')
    fd, info, directory, dstat = _open_key(runtime)
    try:
        named = os.stat(KEY_NAME, dir_fd=directory, follow_symlinks=False)
        named_dir = os.stat(Path(runtime), follow_symlinks=False)
        if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                or (dstat.st_dev, dstat.st_ino) != (named_dir.st_dev, named_dir.st_ino)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or os.read(fd, 4097) != expected):
            raise ValueError
        os.fchown(fd, 10001, 10001)
        os.fchmod(fd, 0o400)
    except Exception:
        raise ValueError('MAINTENANCE_KEY_UNVERIFIED') from None
    finally:
        os.close(fd)
        os.close(directory)
    if read_key(runtime) != expected:
        raise ValueError('MAINTENANCE_KEY_UNVERIFIED')
