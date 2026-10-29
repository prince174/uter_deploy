import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import uterctl

ROOT = Path(__file__).resolve().parents[1]

class SignedToolImmutabilityTests(unittest.TestCase):
    def test_cli_entrypoints_do_not_create_bytecode_in_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(ROOT / 'uterctl.py', root / 'uterctl.py')
            shutil.copytree(ROOT / 'scripts', root / 'scripts', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            before = uterctl.inventory(root)
            for entry in ('uterctl.py', 'scripts/adopt_managed.py', 'scripts/adopt_installation.py',
                          'scripts/recovery_preflight.py', 'scripts/recover_compose.py',
                          'scripts/recover_kubernetes.py', 'scripts/restore_backup.py',
                          'scripts/extract_signed_bundle.py', 'scripts/update_installation.py',
                          'scripts/preflight.py', 'scripts/fetch_release.py'):
                with self.subTest(entry=entry):
                    subprocess.run([sys.executable, str(root / entry), '--help'], check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    self.assertEqual(before, uterctl.inventory(root))
