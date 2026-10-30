import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from scripts import kubernetes_coordinator_signed_ci as ci


class CoordinatorCITests(unittest.TestCase):
    def test_non_hosted_environment_never_reaches_cluster(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false','UTER_CI_STRICT_RUNNER':'false'},clear=True), \
             patch.object(ci.pin_ci,'_material') as material:
            with self.assertRaises(ci.CoordinatorCITestError):
                ci.verify(Path('/tmp/home'),Path('/tmp/product'),Path('/tmp/key'),{})
            material.assert_not_called()

    def test_signed_child_and_all_runtime_modules_are_in_staged_script_glob(self):
        names={p.name for p in (ci.ROOT/'scripts').glob('*.py')}
        required={'kubernetes_executor_ci_child.py','kubernetes_backup_coordinator.py','kubernetes_runtime_pin.py',
                  'kubernetes_fence_coordinator.py','kubernetes_fence_recovery_session.py','kubernetes_fence_start.py',
                  'kubernetes_audit_reader.py','kubernetes_config_snapshot.py','kubernetes_trusted_kubectl.py',
                  'backup_store.py','backup_snapshot.py','redis_fence_journal.py'}
        self.assertTrue(required.issubset(names))

    def test_child_keeps_package_path_fixed_after_nested_imports(self):
        if os.name!='posix':self.skipTest('Linux isolated child required')
        child=ci.ROOT/'scripts/kubernetes_executor_ci_child.py'
        source=('import importlib.util,sys;'
                's=importlib.util.spec_from_file_location("fixture_child",sys.argv[1]);'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                'assert tuple(sys.modules["scripts"].__path__)==(str(m.ROOT/"scripts"),)')
        result=subprocess.run([sys.executable,'-I','-B','-c',source,str(child)],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0)
