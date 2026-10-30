import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml
from scripts import session_gate_e2e_ci as ci


class SessionGateCiTests(unittest.TestCase):
    def test_fixture_accepts_only_fixed_actions_and_hides_error_contents(self):
        with self.assertRaisesRegex(ci.CheckFailure, '^FIXTURE_ACTION_INVALID$'):
            ci.fixture([], None, 'secret-canary')
        with mock.patch.object(ci.sessions, 'container_command', side_effect=ValueError('secret-canary')):
            with self.assertRaisesRegex(ci.CheckFailure, '^FIXTURE_PROBE_FAILED$') as raised:
                ci.fixture([], None, 'seed')
            self.assertNotIn('secret-canary', str(raised.exception))
        expected = {'count':2, 'sha256':'a'*64, 'ttl':200, 'matches':True}
        with mock.patch.object(ci.sessions, 'container_command', return_value=expected):
            self.assertEqual(ci.fixture([], None, 'read'), expected)

    def test_historical_controller_requires_epoch_error_not_incidental_failure(self):
        with mock.patch.object(ci, 'run_checked', return_value=(1,b'uterctl: Data migration required')) as command:
            ci.old_controller_refuses(Path('/old'), Path('/new'), Path('/home'), Path('/pub'))
        self.assertIn('apply', command.call_args.args[0])
        with mock.patch.object(ci, 'run_checked', return_value=(1,b'unrelated')):
            with self.assertRaisesRegex(ci.CheckFailure, '^OLD_CONTROLLER_ACCEPTED_EPOCH_CHANGE$'):
                ci.old_controller_refuses(Path('/old'), Path('/new'), Path('/home'), Path('/pub'))
        with mock.patch.object(ci, 'run_checked', return_value=(0,b'Data migration required')):
            with self.assertRaises(ci.CheckFailure):
                ci.old_controller_refuses(Path('/old'), Path('/new'), Path('/home'), Path('/pub'))

    def test_output_is_bounded_and_timeout_is_inconclusive(self):
        code, value = ci.run_checked([os.sys.executable, '-c', 'print("safe")'])
        self.assertEqual((code, value), (0, b'safe\n'))
        with self.assertRaisesRegex(ci.CheckFailure, '^UPDATE_OUTPUT_TOO_LARGE$'):
            ci.run_checked([os.sys.executable, '-c', 'print("x"*10000)'], limit=128)
        with self.assertRaisesRegex(ci.CheckFailure, '^CHILD_INTERRUPTED_CLEANUP_INCONCLUSIVE$'):
            ci.run_checked([os.sys.executable, '-c', 'import time; time.sleep(5)'], timeout=.2)

    def test_block_requires_exact_reason_verified_backup_and_old_live_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); backups=root/'backups'; backups.mkdir(); backup=backups/'ci'; backup.mkdir()
            old={'version':'0.1.6'}; new={'version':'0.1.7'}
            result={'result':'blocked','code':'SESSION_MIGRATION_AMBIGUOUS','old_version':'0.1.6',
                    'new_version':'0.1.7','backup_independently_verified':True,'backup_id':'a'*32,'backup':str(backup)}
            with mock.patch.object(ci, 'run_checked', return_value=(1,json.dumps(result).encode())), \
                 mock.patch.object(ci.uterctl, 'site_config', return_value={'backend':'compose'}), \
                 mock.patch.object(ci.backup_crypto, 'read_key', return_value=b'X'*32), \
                 mock.patch.object(ci.backup_store, 'verify_set', return_value={'id':'a'*32}) as verify, \
                 mock.patch.object(ci, 'verify_live_old') as live:
                self.assertEqual(ci.assert_blocked([], result['code'], root, old, new, root/'pub', backups, root/'key', 'compose'), result)
                verify.assert_called_once(); live.assert_called_once()
            for change in ({'backup_independently_verified':False}, {'backup_id':'b'*31},
                           {'backup':str(root)}, {'code':'UNRELATED_FAILURE'}):
                with self.subTest(change=change), mock.patch.object(ci, 'run_checked', return_value=(1,json.dumps({**result,**change}).encode())):
                    with self.assertRaisesRegex(ci.CheckFailure, '^SIGNED_UPDATE_BLOCK_INVALID$'):
                        ci.assert_blocked([], result['code'], root, old, new, root/'pub', backups, root/'key', 'compose')
            with mock.patch.object(ci, 'run_checked', return_value=(0,json.dumps(result).encode())):
                with self.assertRaises(ci.CheckFailure):
                    ci.assert_blocked([], result['code'], root, old, new, root/'pub', backups, root/'key', 'compose')

    @unittest.skipUnless(os.name=='posix', 'Owned private marker checks require POSIX')
    def test_only_own_matching_marker_can_be_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); marker=home/'session-migration-block.json'
            blocked={'code':'SESSION_MIGRATION_AMBIGUOUS','backup_id':'a'*32,'backup':'/tmp/ci'}
            data={'reason':blocked['code'], 'backup_id':blocked['backup_id'], 'backup_path':blocked['backup']}
            marker.write_text(json.dumps(data)); marker.chmod(0o600)
            with self.assertRaises(ci.CheckFailure): ci.clear_own_marker(home, {**blocked,'backup_id':'b'*32})
            self.assertTrue(marker.exists())
            ci.clear_own_marker(home, blocked)
            self.assertFalse(marker.exists())
            target=home/'other'; target.write_text('secret-canary'); marker.symlink_to(target)
            with self.assertRaises(ci.CheckFailure): ci.clear_own_marker(home, blocked)
            self.assertEqual(target.read_text(), 'secret-canary')

    def test_workflow_uses_disposable_hosted_runners_and_public_artifacts(self):
        path=Path(__file__).resolve().parents[1]/'.github/workflows/session-gate-e2e.yml'
        data=yaml.safe_load(path.read_text())
        job=data['jobs']['upgrade']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(set(job['strategy']['matrix']['backend']), {'compose','kubernetes'})
        scripts='\n'.join(step.get('run','') for step in job['steps'])
        self.assertIn('scripts/session_gate_e2e_ci.py', scripts)
        self.assertIn('github-hosted', scripts)


if __name__=='__main__': unittest.main()
