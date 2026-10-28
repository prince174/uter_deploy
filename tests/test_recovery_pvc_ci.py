import unittest
from unittest.mock import patch

from scripts import recovery_pvc_ci


class DisposableRecoveryPVCGuardTests(unittest.TestCase):
    def test_refuses_execution_outside_ci_before_calling_kubernetes(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(recovery_pvc_ci, 'call') as call:
            with self.assertRaisesRegex(ValueError, 'disposable CI'):
                recovery_pvc_ci.test(['kubectl','--context','kind-uter-upgrade-ci'],
                                     'uter-upgrade-ci','image','redis','/tmp')
            call.assert_not_called()

    def test_refuses_other_context_or_namespace(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS':'true'}, clear=True), patch.object(recovery_pvc_ci, 'call') as call:
            with self.assertRaisesRegex(ValueError, 'disposable CI'):
                recovery_pvc_ci.test(['kubectl','--context','kind-other'],
                                     'uter-upgrade-ci','image','redis','/tmp')
            call.assert_not_called()
