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

    def test_timer_is_joined_before_child_can_be_reaped_on_success_or_failure(self):
        for fail_decryption in (False, True):
            events = []

            class Timer:
                def __init__(self, delay, callback):
                    self.joined = False
                def start(self): events.append('timer-start')
                def cancel(self): events.append('timer-cancel')
                def join(self):
                    self.joined = True
                    events.append('timer-join')

            class Process:
                def __init__(self):
                    self.stdin = io.BytesIO()
                    self.returncode = None
                def poll(self):
                    self.assert_timer_joined()
                    events.append('poll')
                    return self.returncode
                def kill(self):
                    self.assert_timer_joined()
                    events.append('kill')
                    self.returncode = -9
                def wait(self, timeout=None):
                    self.assert_timer_joined()
                    events.append('wait')
                    if self.returncode is None:
                        self.returncode = 0
                    return self.returncode
                def assert_timer_joined(self):
                    self_test.assertTrue(timer.joined, 'process reaped or signalled before timer callback joined')

            self_test = self
            timer = Timer(0, None)
            process = Process()
            def decrypt(*args):
                if fail_decryption:
                    raise ValueError('synthetic decryption failure')
                args[-1].write(b'fixture')
            with self.subTest(fail_decryption=fail_decryption), \
                    patch.object(backup_snapshot.threading, 'Timer', return_value=timer), \
                    patch.object(backup_snapshot.subprocess, 'Popen', return_value=process), \
                    patch.object(backup_snapshot.backup_crypto, 'decrypt_verify', side_effect=decrypt):
                if fail_decryption:
                    with self.assertRaisesRegex(ValueError, 'synthetic decryption failure'):
                        backup_snapshot.verify_redis_snapshot(self.writer, ['checker'])
                else:
                    backup_snapshot.verify_redis_snapshot(self.writer, ['checker'])
            self.assertLess(events.index('timer-join'), events.index('wait'))
            self.assertLess(events.index('timer-join'), events.index('poll'))
            self.assertTrue(process.stdin.closed)

    def test_limit_refuses_before_starting_checker(self):
        self.writer.manifest['files']['redis']['plaintext_bytes'] = backup_snapshot.RDB_MAX_BYTES + 1
        with patch.object(backup_snapshot.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(ValueError, '100 MiB'):
                backup_snapshot.verify_redis_snapshot(self.writer, self.command('pass'))
            popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
