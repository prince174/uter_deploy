import unittest
from unittest.mock import patch
from scripts import recovery_kubernetes_ci


class DisposableKubernetesRecoveryGuardTests(unittest.TestCase):
    def test_refuses_outside_ci_without_running_kubectl(self):
        with patch.dict('os.environ',{},clear=True),patch.object(recovery_kubernetes_ci,'call') as call:
            with self.assertRaisesRegex(ValueError,'GitHub-hosted'):
                recovery_kubernetes_ci.test('/tmp/home','/tmp/backup','/tmp/key','/tmp/pub','/tmp/out',{})
            call.assert_not_called()
