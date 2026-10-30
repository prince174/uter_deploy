import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import kubernetes_signed_maintenance_product_ci as fixture


class SignedProductFixtureTests(unittest.TestCase):
    def test_nonhosted_runner_rejected_before_any_mutation(self):
        with patch.dict('os.environ',{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted',
                                      'RUNNER_OS':'Linux'},clear=True), \
             patch.object(fixture.subprocess,'run') as process, \
             patch.object(fixture.Path,'mkdir') as mkdir:
            with self.assertRaises(fixture.FixtureError):
                fixture.exercise(root=Path('/tmp'),work=Path('/tmp/work'),home=Path('/tmp/work/home'),
                    kubeconfig=Path('/tmp/kubeconfig'),kube=['kubectl'],site='uter-ci',context='kind-ci',images={})
            process.assert_not_called()
            mkdir.assert_not_called()

    def test_wrong_paths_are_rejected_even_with_hosted_environment(self):
        with patch.dict('os.environ',{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
                                      'RUNNER_OS':'Linux'},clear=True), \
             patch.object(fixture.subprocess,'run') as process, \
             patch.object(fixture.Path,'mkdir') as mkdir:
            with self.assertRaises(fixture.FixtureError):
                fixture.exercise(root=Path('/tmp'),work=Path('/tmp/work'),home=Path('/tmp/work/home'),
                    kubeconfig=Path('/tmp/kubeconfig'),kube=['kubectl'],site='uter-ci',context='kind-ci',images={})
            process.assert_not_called()
            mkdir.assert_not_called()


if __name__ == '__main__': unittest.main()
