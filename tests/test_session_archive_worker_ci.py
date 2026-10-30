import struct
import subprocess
import unittest

from scripts import session_archive_worker_ci


class SyntheticWorkerHarnessTests(unittest.TestCase):
    def test_binary_fields_and_rejected_inputs(self):
        snapshot = b'REDIS0012' + bytes(range(40))
        key = b'sess:synthetic'
        expected = (b'UTSA1\0K' + struct.pack('>QQQ', 2, 42, len(key)) + key +
                    b'V' + struct.pack('>Q', 5) + b'alpha' +
                    b'V' + struct.pack('>Q', 6) + b'beta\0x' + b'EZ' + struct.pack('>Q', 1))
        seen = []

        def fake(command, *, input, stdout, stderr, check, timeout):
            self.assertEqual(command, ['worker'])
            self.assertEqual(timeout, 50)
            seen.append(input)
            return subprocess.CompletedProcess(command, 0 if len(seen) == 1 else 1,
                                               expected if len(seen) == 1 else b'', b'')

        session_archive_worker_ci.verify_worker('worker', snapshot, 42, execute=fake)
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[3][-8:], bytes(8))
        self.assertEqual(seen[4], snapshot + b'extra')

    def test_rejects_success_from_damaged_input(self):
        snapshot = b'REDIS0012' + bytes(range(40))
        calls = 0

        def fake(command, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                key = b'sess:synthetic'
                result = (b'UTSA1\0K' + struct.pack('>QQQ', 2, 42, len(key)) + key +
                          b'V' + struct.pack('>Q', 5) + b'alpha' +
                          b'V' + struct.pack('>Q', 6) + b'beta\0x' + b'EZ' + struct.pack('>Q', 1))
                return subprocess.CompletedProcess(command, 0, result, b'')
            return subprocess.CompletedProcess(command, 0, b'', b'')

        with self.assertRaises(RuntimeError):
            session_archive_worker_ci.verify_worker('worker', snapshot, 42, execute=fake)


if __name__ == '__main__':
    unittest.main()
