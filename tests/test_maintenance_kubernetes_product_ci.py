import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import yaml
from scripts import maintenance_kubernetes_product_ci as probe


class KubernetesProductProbeTests(unittest.TestCase):
    def test_refuses_non_hosted_execution_before_docker(self):
        with mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), \
             mock.patch.object(probe, 'run') as run, self.assertRaises(probe.ProbeError):
            probe.main()
        run.assert_not_called()

    def test_fixture_secret_and_mount_are_local_and_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            chart = home/'charts/uter/templates/workloads.yaml'
            chart.parent.mkdir(parents=True)
            source = Path(__file__).resolve().parents[1]/'charts/uter/templates/workloads.yaml'
            shutil.copyfile(source, chart)
            (home/'values.yaml').write_text('guardrailEnv: {}\nagentEnv: {}\n')
            (home/'resources.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: fixture}\n')
            probe._patch_fixture(home, 'test-key-'+'x'*40)
            self.assertIn('mountPath: /run/uter-maintenance', chart.read_text())
            values = yaml.safe_load((home/'values.yaml').read_text())
            self.assertEqual(values['guardrailEnv']['UTER_MAINTENANCE_ENABLED'], 'true')
            self.assertEqual(values['agentEnv']['UTER_MAINTENANCE_KEY_FILE'], '/run/uter-maintenance/key')
            resources = list(yaml.safe_load_all((home/'resources.yaml').read_text()))
            self.assertEqual(resources[-1]['kind'], 'Secret')
            self.assertEqual(resources[-1]['metadata']['name'], 'uter-maint-ci-maintenance')

    def test_sealed_kubeconfig_detects_changed_digest(self):
        fd, digest = probe._sealed(b'temporary-synthetic-kubeconfig')
        self.addCleanup(os.close, fd)
        self.assertEqual(probe.kubernetes_sealed_config.verify_sealed(fd, digest), digest)
        with self.assertRaises(probe.kubernetes_sealed_config.SealedConfigError):
            probe.kubernetes_sealed_config.verify_sealed(fd, '0'*64)

    def test_workflow_is_manual_with_read_only_permissions(self):
        path = Path(__file__).resolve().parents[1]/'.github/workflows/maintenance-product-kubernetes.yml'
        workflow = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']), {'workflow_dispatch'})
        self.assertEqual(workflow['permissions'], {'contents': 'read', 'actions': 'read'})


if __name__ == '__main__':
    unittest.main()
