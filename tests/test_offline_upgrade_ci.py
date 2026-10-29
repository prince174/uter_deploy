import tempfile
import unittest
from pathlib import Path

from scripts import offline_upgrade_ci as ci


class OfflineUpgradeCITests(unittest.TestCase):
    def test_signed_target_updater_receives_offline_and_current_bundle(self):
        paths = [Path('/fixture')/name for name in ('old', 'new', 'public', 'home', 'backups', 'key')]
        command = ci.update_command('/python', *paths)
        self.assertEqual(command[1], paths[1]/'scripts/update_installation.py')
        self.assertEqual(command[command.index('--current-bundle')+1], paths[0])
        self.assertEqual(command[command.index('--bundle')+1], paths[1])
        self.assertIn('--offline', command)
        self.assertIn('--create-backup-key', command)

    def test_fingerprint_detects_changes_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'state').write_text('old')
            first = ci.digest_tree(root)
            (root/'state').write_text('new')
            self.assertNotEqual(first, ci.digest_tree(root))
            (root/'link').symlink_to(root/'state')
            with self.assertRaises(ci.ci.StageError):
                ci.digest_tree(root)

    def test_workflow_uses_published_pair_and_enforces_runner_guard(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/offline-upgrade.yml').read_text()
        self.assertIn('--old-version 0.1.4 --new-version 0.1.5', workflow)
        self.assertIn('release_upgrade_preflight_ci.py', workflow)
        self.assertIn('RUNNER_ENVIRONMENT', workflow)
        self.assertIn('scripts/offline_upgrade_ci.py', workflow)
        self.assertIn("--proto '=https' --proto-redir '=https'", workflow)


if __name__ == '__main__':
    unittest.main()
