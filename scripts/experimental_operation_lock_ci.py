"""Opt-in GitHub-hosted Linux SIGKILL test for experimental operation lock.

Runs in a private disposable temporary directory and never contacts Docker or
Kubernetes. The namespace observations and one hosted runner are not proof of
complete process visibility on arbitrary customer machines, nor of completion
of commands previously submitted to an external daemon.
"""
import os
from pathlib import Path
import secrets
import select
import signal
import stat
import tempfile
import time

from scripts import experimental_operation_lock as lock


class ProbeError(ValueError): pass


def require_hosted_environment():
    if (os.name!='posix' or os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.environ.get('RUNNER_OS')!='Linux'
            or os.environ.get('UTER_CI_STRICT_RUNNER')!='true'):
        raise ProbeError('CI_GUARD')
    try:
        if not lock._host_pid_namespace() or Path('/proc/1/comm').read_text().strip()!='systemd':
            raise ValueError
        lines=Path('/proc/self/status').read_text().splitlines()
        namespace=[line.split(':',1)[1].split() for line in lines if line.startswith('NSpid:')]
        if len(namespace)!=1 or namespace[0]!=[str(os.getpid())]:raise ValueError
    except (OSError,ValueError,UnicodeError):raise ProbeError('PID_NAMESPACE_UNVERIFIED') from None


def read_byte(fd,timeout=30):
    if not select.select([fd],[],[],timeout)[0]:raise ProbeError('CHILD_TIMEOUT')
    value=os.read(fd,1)
    if not value:raise ProbeError('CHILD_FAILED')
    return value


def wait_child(pid,timeout=30):
    deadline=time.monotonic()+timeout
    while True:
        value,status=os.waitpid(pid,os.WNOHANG)
        if value:return status
        if time.monotonic()>=deadline:raise ProbeError('CHILD_TIMEOUT')
        time.sleep(.02)


def legacy_attempt(home):
    """Try the exact old-style create. Never unlink anything on a test failure."""
    try:
        fd=os.open(home/lock.SENTINEL,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    except FileExistsError:return False
    except OSError:raise ProbeError('LEGACY_IO') from None
    os.close(fd)
    return True


def run():
    require_hosted_environment()
    children=set();descriptors=set()
    def pipe():
        pair=os.pipe();descriptors.update(pair);return pair
    def close_owned(fd):
        os.close(fd);descriptors.remove(fd)
    with tempfile.TemporaryDirectory(prefix='uter-lock-ci-') as temp:
        home=Path(temp)
        info=home.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077):
            raise ProbeError('TEMP_UNSAFE')
        key=secrets.token_bytes(32);operation=secrets.token_hex(16)
        owner_ready_r,owner_ready_w=pipe()
        owner=os.fork()
        if owner==0:
            os.close(owner_ready_r)
            try:
                if not lock._host_pid_namespace():raise ValueError
                lease=lock.Lease(home,key,operation);lease.acquire()
                os.write(owner_ready_w,b'R')
                while True:signal.pause()
            except BaseException:os._exit(11)
        close_owned(owner_ready_w);children.add(owner)
        try:
            if read_byte(owner_ready_r)!=b'R':raise ProbeError('OWNER_START')
            if legacy_attempt(home):raise ProbeError('LEGACY_GAP')
            os.kill(owner,signal.SIGKILL)
            status=wait_child(owner);children.remove(owner)
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:raise ProbeError('OWNER_KILL')
            if legacy_attempt(home):raise ProbeError('LEGACY_GAP')

            stop_r,stop_w=pipe();watch_r,watch_w=pipe()
            watcher=os.fork()
            if watcher==0:
                os.close(stop_w);os.close(watch_r)
                try:
                    os.write(watch_w,b'R')
                    while not select.select([stop_r],[],[],0)[0]:
                        if legacy_attempt(home):os.write(watch_w,b'V');os._exit(12)
                    if os.read(stop_r,1)!=b'S':os._exit(13)
                    os.write(watch_w,b'S');os._exit(0)
                except BaseException:os._exit(14)
            close_owned(stop_r);close_owned(watch_w);children.add(watcher)
            if read_byte(watch_r)!=b'R':raise ProbeError('WATCHER_START')

            control_r,control_w=pipe();reclaim_r,reclaim_w=pipe()
            reclaimer=os.fork()
            if reclaimer==0:
                os.close(control_w);os.close(reclaim_r)
                try:
                    if not lock._host_pid_namespace():raise ValueError
                    lease=lock.Lease(home,key,operation);lease.reclaim()
                    if (home/lock.SENTINEL).read_text()!=str(os.getpid()) or legacy_attempt(home):raise ValueError
                    os.write(reclaim_w,b'R')
                    if read_byte(control_r)!=b'G':raise ValueError
                    lease.release();lease.close();os.write(reclaim_w,b'D');os._exit(0)
                except BaseException:os._exit(15)
            close_owned(control_r);close_owned(reclaim_w);children.add(reclaimer)
            if read_byte(reclaim_r)!=b'R':raise ProbeError('RECLAIM_FAILED')
            if legacy_attempt(home):raise ProbeError('LEGACY_GAP')
            os.write(stop_w,b'S')
            if read_byte(watch_r)!=b'S':raise ProbeError('LEGACY_GAP')
            status=wait_child(watcher);children.remove(watcher)
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status):raise ProbeError('LEGACY_GAP')
            os.write(control_w,b'G')
            if read_byte(reclaim_r)!=b'D':raise ProbeError('RELEASE_FAILED')
            status=wait_child(reclaimer);children.remove(reclaimer)
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status):raise ProbeError('RELEASE_FAILED')
            if not legacy_attempt(home):raise ProbeError('LEGACY_RELEASE')
            # This sentinel was created by this process in its private fixture.
            (home/lock.SENTINEL).unlink()
        finally:
            for child in children:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass
            for child in children:
                try:os.waitpid(child,0)
                except ChildProcessError:pass
            for descriptor in descriptors:
                try:os.close(descriptor)
                except OSError:pass


if __name__=='__main__':
    try:run()
    except ProbeError as error:
        allowed={'CI_GUARD','PID_NAMESPACE_UNVERIFIED','CHILD_TIMEOUT','CHILD_FAILED','TEMP_UNSAFE',
                 'LEGACY_IO','LEGACY_GAP','OWNER_START','OWNER_KILL','WATCHER_START',
                 'RECLAIM_FAILED','RELEASE_FAILED','LEGACY_RELEASE'}
        print('LOCK_CI_'+(str(error) if str(error) in allowed else 'UNVERIFIED'));raise SystemExit(1)
    except BaseException:
        print('LOCK_CI_UNVERIFIED');raise SystemExit(1)
    print('LOCK_CI_SIGKILL_RECLAIM_PASS')
