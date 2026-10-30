"""Experimental momentary bind-mount inode comparison for Docker init PID.

Linux root, host kernel and Docker administrator are trusted. This observation
does not inspect a Python worker, prove ingress/Redis isolation, prevent a
restart or permit backup/update. It is not connected to uterctl.
"""
import os
from pathlib import Path
import select
import stat

from scripts import compose_maintenance_secret


class ProbeError(ValueError):
    pass


def _pid_start(proc):
    fd=os.open('stat',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=proc)
    try:
        raw=os.read(fd,4097)
    finally:os.close(fd)
    if len(raw)>4096 or not raw or b') ' not in raw:raise ValueError
    # comm may itself contain parentheses and spaces. Fields after the final
    # close parenthesis start at Linux procfs field 3 (state).
    fields=raw.rsplit(b') ',1)[1].split()
    if len(fields)<20 or not fields[19].isdigit():raise ValueError
    start=int(fields[19])
    if start<=0:raise ValueError
    return start


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_nlink)


def _runtime_dir(runtime):
    path=Path(runtime)
    if not path.is_absolute() or '..' in path.parts:raise ValueError
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    directory=os.open('/',flags)
    try:
        info=os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError
        for part in path.parts[1:]:
            next_directory=os.open(part,flags,dir_fd=directory)
            os.close(directory);directory=next_directory
            info=os.fstat(directory)
            sticky_root=info.st_uid==0 and bool(info.st_mode&stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and not sticky_root)):
                raise ValueError
        return directory
    except Exception:
        os.close(directory)
        raise


def observe(pid, runtime):
    """Compare a pinned host key with the init PID's view at this instant.

    Open only /proc/<pid>/root as the intentional procfs magic link; all
    components beneath that root are opened by dirfd with O_NOFOLLOW. No key
    content or process metadata is emitted. The caller must separately bind
    this PID to a double-checked Docker container identity.
    """
    fds=[]
    try:
        if (os.name!='posix' or not hasattr(os,'pidfd_open') or not hasattr(os,'O_PATH')
                or not hasattr(os,'O_NOFOLLOW') or not hasattr(os,'geteuid') or os.geteuid()!=0
                or type(pid) is not int or pid<=1 or pid>4194304):raise ValueError
        own_ns=os.stat('/proc/self/ns/pid');init_ns=os.stat('/proc/1/ns/pid')
        if (own_ns.st_dev,own_ns.st_ino)!=(init_ns.st_dev,init_ns.st_ino):raise ValueError
        pidfd=os.pidfd_open(pid,0);fds.append(pidfd)
        if select.select([pidfd],[],[],0)[0]:raise ValueError
        proc=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(proc)
        proc_id=os.fstat(proc);start=_pid_start(proc)
        anchored=_runtime_dir(runtime);fds.append(anchored)
        anchored_info=os.fstat(anchored)
        host,host_before,host_dir,host_dir_before=compose_maintenance_secret._open_key(Path(runtime))
        fds.extend([host,host_dir])
        if (anchored_info.st_dev,anchored_info.st_ino)!=(host_dir_before.st_dev,host_dir_before.st_ino):raise ValueError
        if (not stat.S_ISREG(host_before.st_mode) or host_before.st_uid!=10001 or host_before.st_gid!=10001
                or stat.S_IMODE(host_before.st_mode)!=0o400 or host_before.st_nlink!=1):raise ValueError
        # `/proc/<pid>/root` is the only intentionally followed magic link.
        root=os.open('root',os.O_PATH|os.O_DIRECTORY,dir_fd=proc);fds.append(root)
        directory=root
        for part in ('run','uter-maintenance'):
            directory=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);fds.append(directory)
        mounted=os.open('key',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory);fds.append(mounted)
        mounted_before=os.fstat(mounted)
        if not stat.S_ISREG(mounted_before.st_mode) or _identity(mounted_before)!=_identity(host_before):raise ValueError
        if (_identity(os.fstat(mounted))!=_identity(mounted_before)
                or _identity(os.stat('key',dir_fd=directory,follow_symlinks=False))!=_identity(mounted_before)
                or _identity(os.fstat(host))!=_identity(host_before)
                or _identity(os.stat(compose_maintenance_secret.KEY_NAME,dir_fd=host_dir,follow_symlinks=False))!=_identity(host_before)
                or (os.fstat(host_dir).st_dev,os.fstat(host_dir).st_ino)!=(host_dir_before.st_dev,host_dir_before.st_ino)
                or _pid_start(proc)!=start or select.select([pidfd],[],[],0)[0]):raise ValueError
        named_runtime=os.stat(runtime,follow_symlinks=False)
        if (named_runtime.st_dev,named_runtime.st_ino)!=(host_dir_before.st_dev,host_dir_before.st_ino):raise ValueError
        reanchored=_runtime_dir(runtime);fds.append(reanchored)
        now=os.fstat(reanchored)
        if (now.st_dev,now.st_ino)!=(host_dir_before.st_dev,host_dir_before.st_ino):raise ValueError
        current=os.stat('/proc/'+str(pid),follow_symlinks=False)
        if (current.st_dev,current.st_ino)!=(proc_id.st_dev,proc_id.st_ino):raise ValueError
        return {'init_key_inode_match':True,'host_pid_namespace_verified':False,'worker_identity_verified':False,
                'continuous_fence_verified':False,'safe_to_update':False}
    except Exception:
        raise ProbeError('COMPOSE_INIT_KEY_INODE_UNVERIFIED') from None
    finally:
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError:pass
