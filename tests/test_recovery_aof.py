import unittest
from unittest.mock import patch

from scripts.recovery_aof import enable_checked


class RecoveryAOFTests(unittest.TestCase):
    def test_requires_completed_successful_nonempty_baseline(self):
        info=(b'aof_enabled:1\r\naof_rewrite_in_progress:0\r\naof_rewrite_scheduled:0\r\n'
              b'aof_last_bgrewrite_status:ok\r\naof_last_write_status:ok\r\naof_base_size:42\r\n')
        calls=[]
        def cli(args):
            calls.append(args)
            return b'OK' if args[0]=='CONFIG' else info
        enable_checked(cli,timeout=2)
        self.assertEqual(calls,[['CONFIG','SET','appendonly','yes'],['INFO','persistence']])

    def test_rewrite_error_fails_closed(self):
        def cli(args):return b'OK' if args[0]=='CONFIG' else b'aof_last_bgrewrite_status:err\r\n'
        with self.assertRaisesRegex(ValueError,'AOF creation'):
            enable_checked(cli,timeout=2)

    def test_incomplete_aof_cannot_be_accepted(self):
        with patch('scripts.recovery_aof.time.monotonic',side_effect=[0,0,2]),patch('scripts.recovery_aof.time.sleep'):
            def cli(args):return b'OK' if args[0]=='CONFIG' else b'aof_enabled:1\r\naof_base_size:0\r\n'
            with self.assertRaisesRegex(TimeoutError,'did not complete'):
                enable_checked(cli,timeout=1)
