"""Disposable hosted-Linux managed-lock SIGKILL test; no Docker or Kubernetes."""
import os
from pathlib import Path
import signal
import tempfile

from scripts import experimental_operation_lock as primitive, experimental_operation_lock_ci as fixture
from scripts import managed_operation_lock as lock


def run():
    fixture.require_hosted_environment()
    with tempfile.TemporaryDirectory(prefix='uter-managed-lock-') as temporary:
        home=Path(temporary);home.chmod(0o700)
        read_fd,write_fd=os.pipe();owner=os.fork()
        if owner==0:
            os.close(read_fd)
            try:
                with lock.locked(home):
                    lock.assert_held(home);os.write(write_fd,b'R')
                    while True:signal.pause()
            except BaseException:os._exit(11)
        os.close(write_fd)
        try:
            if fixture.read_byte(read_fd)!=b'R' or fixture.legacy_attempt(home):raise fixture.ProbeError('MANAGED_OWNER')
            os.kill(owner,signal.SIGKILL)
            status=fixture.wait_child(owner);owner=None
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status)!=signal.SIGKILL:raise fixture.ProbeError('MANAGED_KILL')
            if fixture.legacy_attempt(home):raise fixture.ProbeError('MANAGED_STALE')
            with lock.locked(home,reclaim=True):
                lock.assert_held(home)
                if fixture.legacy_attempt(home):raise fixture.ProbeError('MANAGED_RECLAIM_GAP')
            if os.path.lexists(home/primitive.SENTINEL):raise fixture.ProbeError('MANAGED_RELEASE')
            # A legacy lock has no authenticated owner; never reclaim it.
            (home/primitive.SENTINEL).write_text('123');(home/primitive.SENTINEL).chmod(0o600)
            try:
                with lock.locked(home,reclaim=True):raise fixture.ProbeError('MANAGED_LEGACY_ACCEPTED')
            except lock.ManagedLockError as error:
                if str(error)!='MANAGED_LOCK_OWNER_UNVERIFIED':raise
            if (home/primitive.SENTINEL).read_text()!='123':raise fixture.ProbeError('MANAGED_LEGACY_CHANGED')
        finally:
            os.close(read_fd)
            if owner is not None:
                try:os.kill(owner,signal.SIGKILL)
                except ProcessLookupError:pass
                try:fixture.wait_child(owner)
                except ChildProcessError:pass
    print('MANAGED_LOCK_SIGKILL_CI_PASS')


if __name__=='__main__':
    try:run()
    except Exception:
        import sys
        print('MANAGED_LOCK_SIGKILL_CI_FAILED',file=sys.stderr);sys.exit(1)
