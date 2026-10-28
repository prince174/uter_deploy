import unittest
from unittest.mock import patch

from scripts import recovery_compose_ci


class DisposableComposeRecoveryGuardTests(unittest.TestCase):
    def test_refuses_outside_ci_without_running_docker(self):
        with patch.dict('os.environ',{},clear=True), patch.object(recovery_compose_ci,'call') as call:
            with self.assertRaisesRegex(ValueError,'GitHub-hosted'):
                recovery_compose_ci.test('/tmp/home','/tmp/backup','/tmp/key','/tmp/pub','/tmp/out',{})
            call.assert_not_called()
