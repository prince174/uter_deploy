"""Backups stream through a checker without creating plaintext files."""
import io
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from scripts import backup_snapshot, backup_store


class StreamingSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.site = {'backend': 'compose', 'name': 'unit', 'namespace': 'unit', 'context': 'default'}
        self.writer = backup_store.BackupWriter(self.root / 'backup', b'k' * 32,
                                               self.home, self.site, '1.0.0')
        self.payload = b'REDIS-synthetic-not-a-real-rdb\x00' + bytes(range(256)) * 2000
        self.writer.put('redis', io.BytesIO(self.payload))

    def command(self, body):
        return [sys.executable, '-c', body]

    def test_real_encrypted_stream_is_consumed_and_checker_output_is_discarded(self):
        checker = self.command("import sys,hashlib; data=sys.stdin.buffer.read(); "
                               "print('SENSITIVE OUTPUT'); print('SENSITIVE ERROR', file=sys.stderr); "
                               "sys.exit(hashlib.sha256(data).hexdigest() != " +
                               repr(__import__('hashlib').sha256(self.payload).hexdigest()) + ")")
        real_popen = subprocess.Popen
        with patch.object(backup_snapshot.subprocess, 'Popen', wraps=real_popen) as popen:
            backup_snapshot.verify_redis_snapshot(self.writer, checker)
        self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual({p.name for p in (self.root/'backup').iterdir()}, {'redis.enc'})
        self.assertNotIn(self.payload[:32], (self.root/'backup/redis.enc').read_bytes())

    def test_checker_rejection_fails_with_no_output(self):
        checker = self.command("import sys; sys.stdin.buffer.read(); "
                               "print('SENSITIVE'); print('SENSITIVE', file=sys.stderr); sys.exit(1)")
        with self.assertRaisesRegex(ValueError, 'failed structural validation'):
            backup_snapshot.verify_redis_snapshot(self.writer, checker)

    def test_ciphertext_tampering_is_rejected(self):
        path = self.root/'backup/redis.enc'
        raw = path.read_bytes()
        path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        checker = self.command('import sys; sys.stdin.buffer.read()')
        with self.assertRaises(InvalidTag):
            backup_snapshot.verify_redis_snapshot(self.writer, checker)

    def test_checker_early_close_is_bounded_and_fails(self):
        checker = self.command('import sys; sys.exit(1)')
        with self.assertRaisesRegex(ValueError, 'validation failed or timed out'):
            backup_snapshot.verify_redis_snapshot(self.writer, checker)

    def test_checker_stalling_exit_is_killed(self):
        checker = self.command('import sys,time; sys.stdin.buffer.read(); time.sleep(30)')
        started = time.monotonic()
        with patch.object(backup_snapshot, 'RDB_EXIT_TIMEOUT', 0.1):
            with self.assertRaisesRegex(ValueError, 'validation failed or timed out'):
                backup_snapshot.verify_redis_snapshot(self.writer, checker)
        self.assertLess(time.monotonic() - started, 5)

    def test_checker_not_reading_is_killed_while_streaming(self):
        checker = self.command('import time; time.sleep(30)')
        started = time.monotonic()
        with patch.object(backup_snapshot, 'RDB_STREAM_TIMEOUT', 0.2):
            with self.assertRaisesRegex(ValueError, 'validation failed or timed out'):
                backup_snapshot.verify_redis_snapshot(self.writer, checker)
        self.assertLess(time.monotonic() - started, 5)

    def test_limit_refuses_before_starting_checker(self):
        self.writer.manifest['files']['redis']['plaintext_bytes'] = backup_snapshot.RDB_MAX_BYTES + 1
        with patch.object(backup_snapshot.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(ValueError, '100 MiB'):
                backup_snapshot.verify_redis_snapshot(self.writer, self.command('pass'))
            popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
