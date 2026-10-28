import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LiveCiSafetyTests(unittest.TestCase):
    def run_script(self, name, env):
        return subprocess.run([sys.executable, str(ROOT / 'scripts' / name)], env=env, capture_output=True, text=True)

    def test_live_scripts_refuse_non_ci(self):
        env = os.environ.copy(); env.pop('GITHUB_ACTIONS', None)
        for name in ('real_llm_upgrade_ci.py', 'ollama_ci_proxy.py'):
            with self.subTest(name=name):
                result = self.run_script(name, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Disposable GitHub-hosted runner required', result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'live CI guard requires Linux')
    def test_unknown_backend_rejected_before_workload_setup(self):
        env = os.environ.copy(); env['GITHUB_ACTIONS'] = 'true'; env['BACKEND'] = 'unexpected'
        result = self.run_script('real_llm_upgrade_ci.py', env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid backend', result.stderr)
