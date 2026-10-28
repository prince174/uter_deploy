import os
import unittest
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
