import os
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts import compose_fence_signed_ci as ci


class SignedComposeCITest(unittest.TestCase):
    def test_no_docker_or_installation_access_without_all_hosted_runner_guards(self):
        for override in ({}, {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux',
                             'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose'},
                         {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                          'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose','DOCKER_HOST':'unix:///tmp/other'}):
            with self.subTest(override=override), mock.patch.dict(os.environ,override,clear=True), \
                 mock.patch.object(ci.uterctl,'verify') as verify, mock.patch.object(ci.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'COMPOSE_SIGNED_CI_GUARD'):
                    ci.verify('/unknown','/unknown','/unknown',{})
                verify.assert_not_called();launch.assert_not_called()

    def test_paths_must_be_in_the_disposable_workspace(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
             'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose'}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ,env,clear=True), \
             mock.patch.object(ci.uterctl,'verify') as verify:
            with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'COMPOSE_SIGNED_CI_PATH'):
                ci.verify(Path(tmp),Path(tmp),Path(tmp),{})
            verify.assert_not_called()

    def test_external_writer_has_only_synthetic_data(self):
        self.assertIn('uter:ci-fence-check',ci.CLIENT)
        self.assertIn('ci-synthetic-fence-write',ci.CLIENT)
        self.assertIn('sys.stdin.readline()',ci.CLIENT)
        self.assertIn('except TimeoutError: raise',ci.CLIENT)

    def test_unexpected_errors_are_sanitized(self):
        with mock.patch.object(ci,'PHASE','GUARD'), mock.patch.object(ci,'_verify',side_effect=ValueError('secret path or data')):
            with self.assertRaisesRegex(ci.SignedComposeFenceCheckFailure,'COMPOSE_SIGNED_CI_GUARD_FAILED') as error:
                ci.verify('/ignored','/ignored','/ignored',{})
            self.assertNotIn('secret',str(error.exception))


if __name__ == '__main__':unittest.main()
