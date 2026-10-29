import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('install_recovery', Path(__file__).resolve().parents[1] / 'scripts/install_recovery.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FirstInstallDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.cfg = {'backend': 'compose', 'name': 'uter-test', 'context': 'default', 'port': 18000,
                    'images': {k: 'registry.example/' + k + '@sha256:' + 'a' * 64
                               for k in ('guardrail', 'agent', 'redis')}}
        (self.home / 'install.json').write_text(json.dumps(self.cfg))
        (self.home / 'install-state.json').write_text('{"status":"pending"}')
        # Must never be opened or echoed by this diagnostic.
        (self.home / 'credentials.json').write_text('credentials-canary')
        (self.home / 'resources.yaml').write_text('secret-canary')

    def write_config(self):
        (self.home / 'install.json').write_text(json.dumps(self.cfg))

    def test_default_is_read_only_and_always_inconclusive(self):
        before = {p.name: p.read_bytes() for p in self.home.iterdir()}
        with patch.object(m.subprocess, 'Popen') as run:
            result = m.diagnose(self.home, 'compose', 'uter-test', 'default')
        run.assert_not_called()
        self.assertEqual(result['result'], 'inconclusive')
        self.assertEqual(result['ownership'], 'unproven')
        self.assertEqual(result['cluster_or_daemon_identity'], 'unproven')
        self.assertEqual(result['resume'], 'not_available')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.home.iterdir()})
        self.assertNotIn('canary', json.dumps(result))

    def test_identity_mismatch_never_queries_runtime(self):
        for backend, name, context in [('kubernetes', 'uter-test', 'default'),
                                       ('compose', 'other-project', 'default'),
                                       ('compose', 'uter-test', 'other-context')]:
            with self.subTest(backend=backend, name=name, context=context), patch.object(m, 'run_readonly') as run:
                with self.assertRaisesRegex(m.DiagnosticError, '^EXPECTED_IDENTITY_MISMATCH$'):
                    m.diagnose(self.home, backend, name, context, True)
                run.assert_not_called()

    def test_empty_compose_resources_do_not_prove_it_is_safe_to_resume(self):
        context = json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}])
        with patch.dict(os.environ, {}, clear=True), patch.object(m, 'run_readonly', side_effect=[context, '', '', '']) as run:
            result = m.diagnose(self.home, 'compose', 'uter-test', 'default', True)
        self.assertEqual(result['ownership'], 'unproven')
        self.assertEqual(result['resume'], 'not_available')
        self.assertEqual(result['result'], 'inconclusive')
        self.assertEqual(result['observations'], {'container_label_matches': 0, 'volume_label_matches': 0, 'network_label_matches': 0})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 4)
        self.assertTrue(all('rm' not in c and 'up' not in c and 'stop' not in c for c in commands))

    def test_compose_rejects_remote_context_without_listing(self):
        remote = json.dumps([{'Endpoints': {'docker': {'Host': 'tcp://some-host:2376'}}}])
        with patch.dict(os.environ, {}, clear=True), patch.object(m, 'run_readonly', return_value=remote) as run:
            with self.assertRaisesRegex(m.DiagnosticError, '^LOCAL_DEFAULT_UNIX_CONTEXT_REQUIRED$'):
                m.diagnose(self.home, 'compose', 'uter-test', 'default', True)
        self.assertEqual(run.call_count, 1)

    def test_compose_host_override_never_queries_runtime(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://other'}, clear=True), patch.object(m, 'run_readonly') as run:
            with self.assertRaisesRegex(m.DiagnosticError, '^DOCKER_HOST_UNSUPPORTED$'):
                m.diagnose(self.home, 'compose', 'uter-test', 'default', True)
        run.assert_not_called()

    def test_kubernetes_counts_are_partial_and_never_prove_ownership(self):
        self.cfg.update(backend='kubernetes', context='explicit-context')
        self.write_config()
        outputs = ['explicit-context\n', 'namespace/uter-test\n', 'deployment.apps/uter-test-guardrail\n']
        with patch.object(m, 'run_readonly', side_effect=outputs) as run:
            result = m.diagnose(self.home, 'kubernetes', 'uter-test', 'explicit-context', True)
        self.assertEqual(result['result'], 'inconclusive')
        self.assertTrue(result['observations']['namespace_present'])
        self.assertTrue(result['observations']['inventory_is_not_exhaustive'])
        self.assertEqual(result['observations']['partial_label_matches'], 1)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertNotIn('secret', ' '.join(command).lower())
            self.assertFalse(any(x in command for x in ('apply', 'create', 'delete', 'patch', 'replace')))

    def test_missing_namespace_still_does_not_authorize_resume(self):
        self.cfg.update(backend='kubernetes', context='explicit-context')
        self.write_config()
        with patch.object(m, 'run_readonly', side_effect=['explicit-context\n', '']):
            result = m.diagnose(self.home, 'kubernetes', 'uter-test', 'explicit-context', True)
        self.assertFalse(result['observations']['namespace_present'])
        self.assertEqual(result['resume'], 'not_available')

    def test_no_namespace_query_when_kube_context_does_not_exist(self):
        self.cfg.update(backend='kubernetes', context='explicit-context')
        self.write_config()
        with patch.object(m, 'run_readonly', return_value='different-context\n') as run:
            with self.assertRaisesRegex(m.DiagnosticError, '^KUBERNETES_CONTEXT_NOT_FOUND$'):
                m.diagnose(self.home, 'kubernetes', 'uter-test', 'explicit-context', True)
        self.assertEqual(run.call_count, 1)

    def test_non_pending_and_unexpected_state_are_rejected(self):
        for state in ({'status': 'ready'}, {'status': 'pending', 'unexpected': 'value'}, {'status': 'pending-update'}):
            (self.home / 'install-state.json').write_text(json.dumps(state))
            with self.subTest(state=state), self.assertRaisesRegex(m.DiagnosticError, '^NOT_FIRST_INSTALL_PENDING$'):
                m.diagnose(self.home, 'compose', 'uter-test', 'default')

    def test_untrusted_config_and_errors_are_not_echoed(self):
        self.cfg['images']['agent'] = 'secret-canary'
        self.write_config()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(m.subprocess, 'Popen') as run:
            code = m.main(['--home', str(self.home), '--expected-backend', 'compose',
                           '--expected-name', 'uter-test', '--expected-context', 'default', '--inspect-runtime'])
        self.assertEqual(code, 1)
        self.assertNotIn('secret-canary', output.getvalue())
        run.assert_not_called()

    def test_untrusted_subprocess_error_is_not_echoed(self):
        actual_popen = subprocess.Popen
        def fake_popen(command, **kwargs):
            return actual_popen([sys.executable, '-c',
                'import sys; print("stdout-canary"); print("secret-canary", file=sys.stderr); sys.exit(1)'], **kwargs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(os.environ, {}, clear=True), patch.object(m.subprocess, 'Popen', side_effect=fake_popen):
            code = m.main(['--home', str(self.home), '--expected-backend', 'compose',
                           '--expected-name', 'uter-test', '--expected-context', 'default', '--inspect-runtime'])
        self.assertEqual(code, 1)
        self.assertNotIn('canary', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['code'], 'RUNTIME_QUERY_FAILED')

    def test_large_output_is_cut_off_and_process_terminated(self):
        command = [sys.executable, '-c', 'import sys,time; sys.stdout.buffer.write(b"X"*100000); sys.stdout.flush(); time.sleep(30)']
        started = time.monotonic()
        with patch.object(m, 'MAX_OUTPUT', 1024):
            with self.assertRaisesRegex(m.DiagnosticError, '^RUNTIME_RESULT_TOO_LARGE$'):
                m.run_readonly(command, timeout=3)
        self.assertLess(time.monotonic() - started, 5)

    def test_timeout_terminates_process(self):
        command = [sys.executable, '-c', 'import time; time.sleep(30)']
        started = time.monotonic()
        with self.assertRaisesRegex(m.DiagnosticError, '^RUNTIME_QUERY_UNAVAILABLE$'):
            m.run_readonly(command, timeout=0.2)
        self.assertLess(time.monotonic() - started, 5)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process group isolation')
    def test_descendant_holding_pipe_is_terminated_and_reported(self):
        child = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])'
        command = [sys.executable, '-c', child]
        started = time.monotonic()
        with self.assertRaisesRegex(m.DiagnosticError, '^RUNTIME_QUERY_UNAVAILABLE$'):
            m.run_readonly(command, timeout=3)
        self.assertLess(time.monotonic() - started, 5)

    def test_cli_inconclusive_has_distinct_nonzero_exit(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = m.main(['--home', str(self.home), '--expected-backend', 'compose',
                           '--expected-name', 'uter-test', '--expected-context', 'default'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['result'], 'inconclusive')

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'mkfifo'), 'POSIX FIFO')
    def test_fifo_local_state_never_blocks(self):
        target = self.home / 'install-state.json'
        target.unlink()
        os.mkfifo(target)
        cmd = [sys.executable, str(Path(m.__file__)), '--home', str(self.home), '--expected-backend', 'compose',
               '--expected-name', 'uter-test', '--expected-context', 'default']
        result = subprocess.run(cmd, timeout=3, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['code'], 'LOCAL_FILE_INVALID')


if __name__ == '__main__':
    unittest.main()
