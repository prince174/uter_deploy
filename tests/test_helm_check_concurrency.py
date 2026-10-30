import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import uterctl


class HelmCheckConcurrencyTests(unittest.TestCase):
    def test_concurrent_check_does_not_replace_active_apply_values(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home / 'runtime').mkdir()
            (home / 'runtime' / 'values.yaml').write_text('{}', encoding='utf-8')
            bundle = home / 'bundle'
            site = {'backend': 'helm', 'name': 'uter-test', 'namespace': 'uter-test', 'context': 'isolated'}
            apply_manifest = {'version': '1.0.0', 'images': {'redis': 'apply-image'}}
            check_manifest = {'version': '2.0.0', 'images': {'redis': 'check-image'}}
            apply_ready, check_entered, apply_inspected = threading.Event(), threading.Event(), threading.Event()
            errors, temporary_paths, seen_upgrade = [], [], []

            def fake_run(args, **kwargs):
                path = Path(args[-1])
                record = json.loads(path.read_text(encoding='utf-8'))
                if 'lint' in args and record['productVersion'] == '1.0.0':
                    apply_ready.set()
                    if not check_entered.wait(5):
                        raise AssertionError('concurrent check did not enter lint')
                    self.assertEqual(json.loads((home / 'release-values.json').read_text()),
                                     {'images': apply_manifest['images'], 'productVersion': '1.0.0'})
                    apply_inspected.set()
                elif 'lint' in args:
                    self.assertEqual(record, {'images': check_manifest['images'], 'productVersion': '2.0.0'})
                    self.assertNotEqual(path, home / 'release-values.json')
                    self.assertTrue(path.is_file())
                    if os.name == 'posix':
                        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                    temporary_paths.append(path)
                    check_entered.set()
                    if not apply_inspected.wait(5):
                        raise AssertionError('apply did not read its values during check')
                    self.assertTrue(path.is_file())
                elif 'upgrade' in args:
                    seen_upgrade.append(record)
                else:
                    raise AssertionError('unexpected helm invocation')

            def worker(manifest, check):
                try:
                    uterctl.deploy(home, bundle, manifest, site, check=check)
                except BaseException as error:
                    errors.append(error)
                    check_entered.set()
                    apply_inspected.set()

            with patch.object(uterctl, 'run', side_effect=fake_run):
                apply = threading.Thread(target=worker, args=(apply_manifest, False))
                check = threading.Thread(target=worker, args=(check_manifest, True))
                apply.start()
                self.assertTrue(apply_ready.wait(5))
                check.start()
                apply.join(10)
                check.join(10)
            self.assertFalse(apply.is_alive())
            self.assertFalse(check.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(seen_upgrade, [{'images': apply_manifest['images'], 'productVersion': '1.0.0'}])
            self.assertEqual(len(temporary_paths), 1)
            self.assertFalse(temporary_paths[0].exists())

    def test_failed_lint_removes_private_values_and_preserves_apply_values(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home / 'runtime').mkdir()
            (home / 'runtime' / 'values.yaml').write_text('{}', encoding='utf-8')
            shared = home / 'release-values.json'
            shared.write_text('original', encoding='utf-8')
            generated = []
            def fail(args, **kwargs):
                generated.append(Path(args[-1]))
                self.assertTrue(generated[0].is_file())
                raise RuntimeError('helm failed')
            with patch.object(uterctl, 'run', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'helm failed'):
                    uterctl.deploy(home, home / 'bundle', {'version': '2', 'images': {}},
                                   {'backend': 'helm', 'name': 'uter-test', 'namespace': 'uter-test'}, check=True)
            self.assertEqual(shared.read_text(encoding='utf-8'), 'original')
            self.assertFalse(generated[0].exists())

if __name__ == '__main__':
    unittest.main()
