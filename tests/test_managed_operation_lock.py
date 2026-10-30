import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.name=='posix':
    import fcntl
    from scripts import experimental_operation_lock as primitive, managed_operation_lock as subject


@unittest.skipUnless(os.name=='posix','POSIX flock and proc required')
class ManagedLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.home.chmod(0o700)
        # WSL restricts /proc/1/ns to this user; this models the required
        # trusted host namespace without weakening production validation.
        namespace=patch.object(primitive,'_host_pid_namespace',return_value=True)
        namespace.start();self.addCleanup(namespace.stop)

    def test_fresh_lease_is_capability_and_releases_once(self):
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_NOT_HELD'):subject.assert_held(self.home)
        with subject.locked(self.home):
            subject.assert_held(self.home)
            self.assertEqual((self.home/primitive.SENTINEL).stat().st_nlink,2)
            self.assertEqual((self.home/subject.KEY_NAME).stat().st_mode&0o777,0o600)
            with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_ALREADY_HELD'):
                with subject.locked(self.home):pass
        self.assertFalse(os.path.lexists(self.home/primitive.SENTINEL))
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_NOT_HELD'):subject.assert_held(self.home)

    def test_legacy_pid_sentinel_is_never_reclaimed_or_replaced(self):
        sentinel=self.home/primitive.SENTINEL;sentinel.write_text('123');sentinel.chmod(0o600)
        for reclaim in (False,True):
            with self.subTest(reclaim=reclaim),self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_KEY_MISSING'):
                with subject.locked(self.home,reclaim=reclaim):pass
            self.assertEqual(sentinel.read_text(),'123')
        self.assertFalse(os.path.lexists(self.home/subject.KEY_NAME))

    def test_legacy_sentinel_is_not_reclaimed_even_if_managed_key_exists(self):
        with subject.locked(self.home):pass
        sentinel=self.home/primitive.SENTINEL;sentinel.write_text('123');sentinel.chmod(0o600)
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_OWNER_UNVERIFIED'):
            with subject.locked(self.home,reclaim=True):pass
        self.assertEqual(sentinel.read_text(),'123')

    def test_own_pid_file_alone_is_not_a_capability(self):
        sentinel=self.home/primitive.SENTINEL;sentinel.write_text(str(os.getpid()));sentinel.chmod(0o600)
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_NOT_HELD'):subject.assert_held(self.home)
        self.assertTrue(sentinel.exists())

    def test_unsafe_key_is_not_followed_or_replaced(self):
        key=self.home/subject.KEY_NAME;key.symlink_to(self.home/'missing')
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_KEY_UNVERIFIED'):
            with subject.locked(self.home):pass
        self.assertTrue(key.is_symlink())

    def test_lost_flock_is_detected_and_sentinel_is_preserved(self):
        with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_NOT_HELD'):
            with subject.locked(self.home):
                lease=subject._HELD[str(self.home)]
                fcntl.flock(lease.gate,fcntl.LOCK_UN)
                subject.assert_held(self.home)
        self.assertTrue(os.path.lexists(self.home/primitive.SENTINEL))
        self.assertTrue(os.path.lexists(self.home/primitive.OWNER))

    def test_changed_key_or_gate_permissions_preserve_uncertain_sentinel(self):
        for mode in ('key','gate'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
                home=Path(temp);home.chmod(0o700)
                with self.assertRaisesRegex(subject.ManagedLockError,'MANAGED_LOCK_NOT_HELD'):
                    with subject.locked(home):
                        if mode=='key':(home/subject.KEY_NAME).write_bytes(b'z'*32)
                        else:(home/primitive.GATE).chmod(0o644)
                        subject.assert_held(home)
                self.assertTrue(os.path.lexists(home/primitive.SENTINEL))
                self.assertTrue(os.path.lexists(home/primitive.OWNER))

    def test_real_sigkill_requires_explicit_reclaim_and_keeps_exclusion(self):
        code=('import os,sys,time;from scripts import managed_operation_lock as m;'
              'm.primitive._host_pid_namespace=lambda:True;'
              'h=sys.argv[1];ctx=m.locked(h);ctx.__enter__();print("READY",flush=True);time.sleep(300)')
        child=subprocess.Popen([sys.executable,'-c',code,str(self.home)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        self.addCleanup(lambda:child.poll() is None and child.kill())
        self.assertEqual(child.stdout.readline().strip(),'READY')
        sentinel=self.home/primitive.SENTINEL;before=sentinel.read_text()
        with self.assertRaises(primitive.LockError):
            with subject.locked(self.home,reclaim=True):pass
        os.kill(child.pid,signal.SIGKILL);child.wait(timeout=10)
        self.assertTrue(os.path.lexists(sentinel));self.assertEqual(sentinel.read_text(),before)
        with self.assertRaises(primitive.LockError):
            with subject.locked(self.home):pass
        with subject.locked(self.home,reclaim=True):
            subject.assert_held(self.home)
            self.assertEqual(sentinel.read_text(),str(os.getpid()))
        self.assertFalse(os.path.lexists(sentinel));child.stdout.close()

    def test_another_process_cannot_acquire_held_gate(self):
        code=('import sys;from scripts import managed_operation_lock as m;'
              'm.primitive._host_pid_namespace=lambda:True;'
              'ctx=m.locked(sys.argv[1]);ctx.__enter__()')
        with subject.locked(self.home):
            child=subprocess.run([sys.executable,'-c',code,str(self.home)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            self.assertNotEqual(child.returncode,0);subject.assert_held(self.home)

    def test_hosted_probe_uses_isolated_fixture_and_real_sigkill(self):
        import contextlib,io
        from scripts import managed_operation_lock_ci
        out=io.StringIO()
        with patch.object(managed_operation_lock_ci.fixture,'require_hosted_environment'),contextlib.redirect_stdout(out):
            managed_operation_lock_ci.run()
        self.assertEqual(out.getvalue().strip(),'MANAGED_LOCK_SIGKILL_CI_PASS')


if __name__=='__main__':unittest.main()
