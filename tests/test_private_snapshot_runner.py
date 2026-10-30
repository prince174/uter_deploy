import json
from pathlib import Path
import unittest
from unittest import mock

from scripts import run_private_snapshot as runner


class PrivateSnapshotRunnerTests(unittest.TestCase):
    def test_cleanup_after_success_and_no_patch_in_arguments(self):
        calls = []
        secret = b'secret-canary'
        def command(args, data=None, env=None):
            calls.append((args, data))
            if args[1:3] == ['secret','list']: return b''
            if args[1:3] == ['workflow','run']:
                return b'https://github.com/prince174/uter_deploy/actions/runs/123\n'
            if args[1:3] == ['run','view']:
                return json.dumps({'status':'completed','conclusion':'success'}).encode()
            return b''
        with mock.patch.object(runner, 'command', side_effect=command), \
             mock.patch.object(runner, 'source_snapshot', return_value=('a'*40, secret, 'b'*64)):
            self.assertEqual(runner.run(Path('/source'), 'a'*40), '123')
        self.assertEqual(calls[-1][0][1:3], ['secret','delete'])
        for args, _ in calls:
            self.assertNotIn('secret-canary', ' '.join(args))

    def test_existing_secret_is_never_overwritten_or_deleted(self):
        with mock.patch.object(runner.secrets, 'token_hex', return_value='a'*32), \
             mock.patch.object(runner, 'command', return_value=(runner.SECRET_PREFIX+'A'*32+'\tupdated\n').encode()) as command:
            with self.assertRaises(ValueError): runner.run(Path('/source'), 'a'*40)
            self.assertEqual(command.call_count, 1)

    def test_failure_still_deletes_temporary_secret(self):
        calls = []
        def command(args, data=None, env=None):
            calls.append(args)
            if args[1:3] == ['workflow','run']: raise RuntimeError('failed')
            return b''
        with mock.patch.object(runner, 'command', side_effect=command), \
             mock.patch.object(runner, 'source_snapshot', return_value=('a'*40,b'x','b'*64)):
            with self.assertRaises(RuntimeError): runner.run(Path('/source'), 'a'*40)
        self.assertEqual(calls[-1][1:3], ['secret','delete'])

    def test_concurrent_runs_use_distinct_secrets_and_delete_only_their_own(self):
        calls = []
        def command(args, data=None, env=None):
            calls.append(args)
            if args[1:3] == ['workflow','run']:
                return b'https://github.com/prince174/uter_deploy/actions/runs/123\n'
            if args[1:3] == ['run','view']:
                return b'{"status":"completed","conclusion":"success"}'
            return b''
        with mock.patch.object(runner.secrets, 'token_hex', side_effect=['a'*32, 'b'*32]), \
             mock.patch.object(runner, 'command', side_effect=command), \
             mock.patch.object(runner, 'source_snapshot', return_value=('a'*40,b'x','b'*64)):
            runner.run(Path('/source'), 'a'*40); runner.run(Path('/source'), 'a'*40)
        sets = [args[3] for args in calls if args[1:3] == ['secret','set']]
        deletes = [args[3] for args in calls if args[1:3] == ['secret','delete']]
        self.assertEqual(sets, [runner.SECRET_PREFIX+'A'*32, runner.SECRET_PREFIX+'B'*32])
        self.assertEqual(deletes, sets)
        dispatches = [args for args in calls if args[1:3] == ['workflow','run']]
        for args, name in zip(dispatches, sets): self.assertIn('secret_name='+name, args)

    def test_invalid_generated_name_rejected_before_secret_lookup(self):
        with mock.patch.object(runner.secrets, 'token_hex', return_value='../../SOURCE_READ_TOKEN'), \
             mock.patch.object(runner, 'command') as command:
            with self.assertRaises(ValueError): runner.run(Path('/source'), 'a'*40)
            command.assert_not_called()


if __name__ == '__main__': unittest.main()
