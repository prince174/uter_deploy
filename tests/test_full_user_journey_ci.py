import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import full_user_journey_ci as journey


class FullUserJourneyTests(unittest.TestCase):
    def test_backup_result_only_accepts_matching_key_and_contained_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backups = root / 'backups'
            backups.mkdir()
            expected = backups / 'one'
            expected.mkdir()
            key = root / 'key'
            output = {'version': '0.1.6', 'backup': str(expected),
                      'backup_id': 'a'*32, 'backup_key': str(key)}
            self.assertEqual(journey.parse_update(json.dumps(output).encode(), backups, key), expected)
            output['backup'] = str(root)
            with self.assertRaises(journey.real.Failure):
                journey.parse_update(json.dumps(output).encode(), backups, key)
            output['backup'] = str(expected)
            output['backup_key'] = str(root/'another')
            with self.assertRaises(journey.real.Failure):
                journey.parse_update(json.dumps(output).encode(), backups, key)

    def test_inference_requires_increase(self):
        with mock.patch.object(journey.real, 'metric', return_value=10):
            self.assertEqual(journey.require_inference(9, 'http://127.0.0.1:1', 'UPDATE'), 10)
            with self.assertRaisesRegex(journey.real.Failure, '^UPDATE_NO_LLM_TOKENS$'):
                journey.require_inference(10, 'http://127.0.0.1:1', 'UPDATE')

    def test_forbidden_selection_never_runs_driver(self):
        for env in ({'RELEASE_TAG': 'wrong', 'RELEASE_VERSION': '0.1.6', 'LLM_MAX_TOKENS_SCENARIO': '64'},
                    {'RELEASE_TAG': 'deploy-2026.10.29-signed-4', 'RELEASE_VERSION': '0.1.6',
                     'LLM_MAX_TOKENS_SCENARIO': 'model_default'}):
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(journey.real, 'main') as run:
                with self.assertRaises(journey.real.Failure):
                    journey.main()
                run.assert_not_called()

    def test_wizard_callback_runs_actual_install_before_upgrade_and_restores_hook(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'work').mkdir()
            events = []
            original = journey.real.run_signed_wizard
            def wizard(argv, timeout=1800):
                events.append('install')
            def run_driver():
                journey.real.run_signed_wizard(['dummy'])
            with mock.patch.object(journey, 'ROOT', root), mock.patch.object(journey.real, 'main', side_effect=run_driver), \
                 mock.patch.object(journey.real, 'run_signed_wizard', side_effect=wizard) as original_mock, \
                 mock.patch.object(journey.real, 'metric', side_effect=[1, 2]), \
                 mock.patch.object(journey, 'old_install_and_recovery', side_effect=lambda argv: events.append('upgrade')), \
                 mock.patch.dict(os.environ, {'BACKEND':'compose','RELEASE_TAG':'deploy-2026.10.29-signed-4',
                    'RELEASE_VERSION':'0.1.6', 'LLM_MAX_TOKENS_SCENARIO':'64'}, clear=True):
                journey.main()
                self.assertIs(journey.real.run_signed_wizard, original_mock)
            self.assertIs(journey.real.run_signed_wizard, original)
            self.assertEqual(events, ['install', 'upgrade'])
            evidence = json.loads((root/'work/full-user-journey-evidence.json').read_text())
            self.assertEqual(evidence['synthetic_redis_and_audit'], 'pass')

    def test_required_option_does_not_return_secret_in_exception(self):
        with self.assertRaisesRegex(journey.real.Failure, '^JOURNEY_ARGUMENT_MISSING$'):
            journey.option(['secret-canary'], '--home')


if __name__ == '__main__':
    unittest.main()
