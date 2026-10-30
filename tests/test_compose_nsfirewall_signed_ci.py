import os
import unittest
from unittest import mock

from scripts import compose_nsfirewall_signed_ci as ci


class SignedNamespaceCITests(unittest.TestCase):
    def test_local_or_nonhosted_cannot_reach_workloads(self):
        for environ in ({}, {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux',
                             'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose'}):
            with self.subTest(environ=environ),mock.patch.dict(os.environ,environ,clear=True), \
                 mock.patch.object(ci.subprocess,'Popen') as process, mock.patch.object(ci.uterctl,'verify') as signed:
                with self.assertRaises(ci.SignedComposeFenceCheckFailure):
                    ci.verify('/unknown','/unknown','/unknown',{})
                process.assert_not_called();signed.assert_not_called()

    def test_writer_timeout_is_blocked_not_false_closed_socket(self):
        self.assertIn("except TimeoutError:print('BLOCKED',flush=True)",ci.CLIENT)
        self.assertIn('except TimeoutError:raise',ci.CLIENT)

    def test_unexpected_error_cannot_disclose_private_data(self):
        with mock.patch.object(ci,'PHASE','GUARD'),mock.patch.object(ci,'_verify',side_effect=ValueError('secret')):
            with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'COMPOSE_SIGNED_CI_GUARD_FAILED') as error:
                ci.verify('/unknown','/unknown','/unknown',{})
            self.assertNotIn('secret',str(error.exception))

    def test_only_exact_known_exception_category_is_exposed(self):
        name='NS_FENCE_CAPABILITIES_UNSUPPORTED'
        for message,expected in ((name,ci.DIAGNOSTICS[name]),(name+' secret','COMPOSE_SIGNED_CI_GUARD_FAILED')):
            with self.subTest(message=message),mock.patch.object(ci,'PHASE','GUARD'), \
                 mock.patch.object(ci,'_verify',side_effect=ci.fence.NamespaceFenceError(message)):
                with self.assertRaises(ci.SignedComposeFenceCheckFailure) as error:
                    ci.verify('/unknown','/unknown','/unknown',{})
                self.assertEqual(str(error.exception),expected)


if __name__=='__main__':unittest.main()
