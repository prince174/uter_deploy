import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import experimental_operation_lock as lock


@unittest.skipUnless(sys.platform.startswith('linux'), 'requires local Linux flock and procfs')
class ExperimentalOperationLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.key = b'k' * 32
        self.operation = 'a' * 32
        self.leases = []
        # WSL may restrict unprivileged access to /proc/1/ns; tests model the
        # trusted full host namespace, rather than running as local root.
        patcher = mock.patch.object(lock, '_host_pid_namespace', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for lease in self.leases:
            lease.close()
        self.tmp.cleanup()

    def lease(self):
        obj = lock.Lease(self.home, self.key, self.operation)
        self.leases.append(obj)
        return obj

    def dead_owner(self):
        # Child owns the gate/sentinel and exits abruptly without cleanup.
        code = ("import os,sys; from unittest.mock import patch; "
                "from scripts import experimental_operation_lock as m; "
                "patch.object(m,'_host_pid_namespace',return_value=True).start(); "
                "x=m.Lease(sys.argv[1],b'k'*32,'a'*32);x.acquire();os._exit(0)")
        child = subprocess.run([sys.executable, '-c', code, str(self.home)], timeout=10)
        self.assertEqual(child.returncode, 0)

    def test_compatibility_and_reclaim_have_no_gap_in_sentinel(self):
        self.dead_owner()
        lease = self.lease()
        replace = os.replace
        seen = []
        def checked_replace(src, dst, **kwargs):
            if dst == lock.SENTINEL:
                for when in ('before', 'after'):
                    if when == 'after': replace(src, dst, **kwargs)
                    with self.assertRaises(FileExistsError):
                        os.open(self.home / lock.SENTINEL, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    seen.append(when)
                return
            return replace(src, dst, **kwargs)
        with mock.patch.object(lock.os, 'replace', side_effect=checked_replace):
            lease.reclaim()
        self.assertEqual(seen, ['before', 'after'])
        self.assertEqual((self.home / lock.SENTINEL).read_text(), str(os.getpid()))
        lease.release()
        fd = os.open(self.home / lock.SENTINEL, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)

    def test_unknown_legacy_sentinel_never_reclaimed(self):
        sentinel = self.home / lock.SENTINEL
        sentinel.write_text('12345')
        sentinel.chmod(0o600)
        before = sentinel.stat().st_ino
        with self.assertRaises(lock.LockError):
            self.lease().reclaim()
        self.assertEqual(sentinel.read_text(), '12345')
        self.assertEqual(sentinel.stat().st_ino, before)

    def test_real_sigkill_releases_gate_and_allows_atomic_takeover(self):
        code = ("import time,sys; from unittest.mock import patch; "
                "from scripts import experimental_operation_lock as m; "
                "patch.object(m,'_host_pid_namespace',return_value=True).start(); "
                "x=m.Lease(sys.argv[1],b'k'*32,'a'*32);x.acquire(); "
                "print('READY',flush=True);time.sleep(30)")
        child = subprocess.Popen([sys.executable, '-c', code, str(self.home)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'READY')
            child.send_signal(signal.SIGKILL)
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
            lease = self.lease()
            lease.reclaim()
            self.assertEqual((self.home / lock.SENTINEL).read_text(), str(os.getpid()))
            lease.release()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()

    def test_live_owner_and_reused_pid_are_both_refused(self):
        lease = self.lease()
        lease.acquire()
        lease.close()  # simulate lost gate while process is still alive
        before = (self.home / lock.SENTINEL).stat().st_ino
        with self.assertRaisesRegex(lock.LockError, 'LOCK_OWNER_LIVE_OR_UNKNOWN'):
            self.lease().reclaim()
        self.assertEqual((self.home / lock.SENTINEL).stat().st_ino, before)

    def test_flock_prevents_concurrent_reclaimers(self):
        self.dead_owner()
        first = self.lease()
        with self.assertRaisesRegex(lock.LockError, 'LOCK_GATE_BUSY'):
            self.lease()
        first.reclaim()
        first.release()

    def test_tampered_metadata_or_key_fails_closed(self):
        self.dead_owner()
        path = self.home / lock.OWNER
        value = json.loads(path.read_text())
        value['record']['pid'] += 1
        path.write_text(json.dumps(value))
        with self.assertRaises(lock.LockError):
            self.lease().reclaim()
        self.assertTrue((self.home / lock.SENTINEL).exists())

    def test_crash_between_sentinel_and_metadata_replace_fails_closed(self):
        self.dead_owner()
        lease = self.lease()
        replace = os.replace
        def uncertain(src, dst, **kwargs):
            if dst == lock.OWNER:
                raise OSError(errno.EIO, 'synthetic crash')
            return replace(src, dst, **kwargs)
        with mock.patch.object(lock.os, 'replace', side_effect=uncertain):
            with self.assertRaisesRegex(lock.LockError, 'LOCK_RECLAIM_UNCERTAIN'):
                lease.reclaim()
        lease.close()
        before = (self.home / lock.SENTINEL).stat().st_ino
        with self.assertRaises(lock.LockError):
            self.lease().reclaim()
        self.assertEqual((self.home / lock.SENTINEL).stat().st_ino, before)

    def test_partial_acquire_never_blindly_removes_sentinel(self):
        lease = self.lease()
        real_link = os.link
        def fail_metadata(src, dst, **kwargs):
            if dst == lock.OWNER:
                raise OSError(errno.EIO, 'synthetic crash')
            return real_link(src, dst, **kwargs)
        with mock.patch.object(lock.os, 'link', side_effect=fail_metadata):
            with self.assertRaisesRegex(lock.LockError, 'LOCK_ACQUIRE_UNCERTAIN'):
                lease.acquire()
        lease.close()
        self.assertTrue((self.home / lock.SENTINEL).exists())
        with self.assertRaises(lock.LockError):
            self.lease().reclaim()
        self.assertTrue((self.home / lock.SENTINEL).exists())

    def test_fsync_failure_at_every_reclaim_boundary_keeps_sentinel(self):
        # Each case uses a freshly killed owner. The five fsync calls cover
        # new temp sentinel, anchor directory, new metadata, exchanged sentinel,
        # and exchanged metadata. No failure can create an O_EXCL opening.
        for failure in range(1, 6):
            with self.subTest(fsync=failure), tempfile.TemporaryDirectory() as directory:
                self.home = Path(directory)
                self.dead_owner()
                lease = self.lease()
                actual = os.fsync
                counter = [0]
                def fail(fd):
                    counter[0] += 1
                    if counter[0] == failure:
                        raise OSError(errno.EIO, 'injected failure')
                    return actual(fd)
                with mock.patch.object(lock.os, 'fsync', side_effect=fail):
                    with self.assertRaises(lock.LockError):
                        lease.reclaim()
                self.assertEqual(counter[0], failure)
                with self.assertRaises(FileExistsError):
                    os.open(self.home / lock.SENTINEL, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                lease.close()

    def test_child_cannot_release_parent_lease(self):
        lease = self.lease()
        lease.acquire()
        with mock.patch.object(lock.os, 'getpid', return_value=os.getpid() + 1):
            with self.assertRaisesRegex(lock.LockError, 'LOCK_OWNER_UNVERIFIED'):
                lease.release()
        self.assertIsNone(lease.record)
        self.assertTrue((self.home / lock.SENTINEL).exists())

    def test_release_uncertainty_invalidates_lease_and_never_removes_new_owner(self):
        lease = self.lease()
        lease.acquire()
        with mock.patch.object(lock.os, 'fsync', side_effect=OSError(errno.EIO, 'injected')):
            with self.assertRaises(OSError):
                lease.release()
        self.assertIsNone(lease.record)
        sentinel = self.home / lock.SENTINEL
        fd = os.open(sentinel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, b'12345')
        os.close(fd)
        with self.assertRaisesRegex(lock.LockError, 'LOCK_NOT_OWNED'):
            lease.release()
        self.assertEqual(sentinel.read_bytes(), b'12345')

    def test_owner_mac_is_domain_separated_from_raw_backup_key(self):
        lease = self.lease()
        lease.acquire()
        outer = json.loads((self.home / lock.OWNER).read_text())
        raw_mac = hmac.new(self.key, lock._canonical(outer['record']), hashlib.sha256).hexdigest()
        self.assertNotEqual(outer['mac'], raw_mac)
        self.assertEqual(outer['mac'], hmac.new(lock._key(self.key),
                         lock._canonical(outer['record']), hashlib.sha256).hexdigest())
        lease.release()


if __name__ == '__main__':
    unittest.main()
