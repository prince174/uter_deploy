import os
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from scripts import recover_compose


class ComposeRecoveryGuardTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','root check uses POSIX geteuid')
    def test_nonroot_refused_before_docker(self):
        with patch('os.geteuid',return_value=1000),patch.object(recover_compose,'run') as run:
            with self.assertRaisesRegex(ValueError,'requires root'):
                recover_compose.restore('/old','/backup','/key','/pub','/new','uter-restored',18001)
            run.assert_not_called()

    @unittest.skipUnless(os.name=='posix','root check uses POSIX geteuid')
    def test_invalid_project_refused_before_docker(self):
        with patch('os.geteuid',return_value=0),patch.object(recover_compose,'run') as run:
            with self.assertRaisesRegex(ValueError,'Invalid new Compose project'):
                recover_compose.restore('/old','/backup','/key','/pub','/new','../other',18001)
            run.assert_not_called()

    @unittest.skipUnless(os.name=='posix','POSIX permission semantics required')
    def test_staged_helpers_are_readable_to_unprivileged_container(self):
        with tempfile.TemporaryDirectory() as temp:
            staged = recover_compose.stage_recovery_helpers(temp)
            self.assertEqual({p.name for p in staged.iterdir()}, {'recovery_volume.py','archive_safety.py'})
            self.assertEqual(staged.stat().st_mode & 0o777, 0o555)
            for path in staged.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                self.assertEqual(path.read_bytes(), (recover_compose.ROOT/'scripts'/path.name).read_bytes())
