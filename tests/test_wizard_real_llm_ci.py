import json
import contextlib
import io
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import sys
import unittest
import urllib.error
from unittest.mock import patch

from scripts import wizard_real_llm_ci as driver


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'a' * 64
OPERATION = 'b' * 32


class IsolatedWizardLlmTests(unittest.TestCase):
    def test_capacity_metrics_never_emit_labels(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, size):
                return (b'vllm:generation_tokens_total{model="secret-canary"} 12\n'
                        b'vllm:num_requests_running{model="secret-canary"} 1\n'
                        b'secret-canary 999\n')
        class Opener:
            def open(self, *args, **kwargs): return Response()
        out = io.StringIO()
        with contextlib.redirect_stderr(out), patch.object(driver.urllib.request, 'build_opener', return_value=Opener()), \
                patch.object(driver.llm, 'read_host_resources', return_value=(set(), 1024**3, 10**10)), \
                patch.object(driver.os, 'getloadavg', return_value=(1, 2, 3)), \
                patch.object(driver.os, 'cpu_count', return_value=4):
            driver.report_capacity_and_vllm_metrics('http://127.0.0.1:1', 'BEFORE_ACCEPTANCE')
        self.assertIn('CPU_4_LOAD1_1.00_MEM_AVAILABLE_MIB_1024', out.getvalue())
        self.assertIn('GENERATION_TOKENS_TOTAL=12.0', out.getvalue())
        self.assertIn('NUM_REQUESTS_RUNNING=1.0', out.getvalue())
        self.assertNotIn('secret-canary', out.getvalue())

    def test_completion_errors_are_sanitized(self):
        error = urllib.error.HTTPError('http://example/secret-canary', 503, 'secret-canary', {}, None)
        self.addCleanup(error.close)
        with patch.object(driver, 'local_json', side_effect=error):
            with self.assertRaisesRegex(driver.Failure, '^COMPLETION_HTTP_503$'):
                driver.completion('http://127.0.0.1:1234', 'test')

    def test_acceptance_diagnostics_reveal_only_safe_status(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home/'install-state.json').write_text(json.dumps({'status':'ready','acceptance':'not-run'}))
            (home/'credentials.json').write_text(json.dumps({'admin':'secret-canary'}))
            output = io.StringIO()
            responses = [{}, {'access_token':'secret-canary'}, {'upstream_available':True,
                         'agent_runtime_available':True, 'toxicity_guard':{'available':True}}, {'blocked':False}]
            with contextlib.redirect_stderr(output), patch.object(driver, 'local_json', side_effect=responses):
                driver.diagnose_compose_acceptance(home, 18000)
            self.assertEqual(output.getvalue(), 'ACCEPTANCE_DIAGNOSTIC=CHAT_PASS\n')
            self.assertNotIn('secret-canary', output.getvalue())

    def test_ready_503_continues_to_check_health_without_body(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            (home/'install-state.json').write_text(json.dumps({'status':'ready','acceptance':'not-run'}))
            (home/'credentials.json').write_text(json.dumps({'admin':'secret-canary'}))
            error = urllib.error.HTTPError('http://127.0.0.1/secret-canary', 503, 'secret-canary', {}, None)
            self.addCleanup(error.close)
            responses = [error, {'access_token':'secret-canary'}, {'upstream_available':False}]
            output = io.StringIO()
            with contextlib.redirect_stderr(output), patch.object(driver, 'local_json', side_effect=responses):
                driver.diagnose_compose_acceptance(home, 18000)
            self.assertIn('ACCEPTANCE_DIAGNOSTIC=READY_HTTP_503', output.getvalue())
            self.assertIn('ACCEPTANCE_DIAGNOSTIC=UPSTREAM_NOT_READY', output.getvalue())
            self.assertNotIn('secret-canary', output.getvalue())

    def test_container_diagnostic_uses_fixed_fields_and_rejects_other_project(self):
        output = io.StringIO()
        name = 'uter-wizard-test'
        results = [(0, (name+'|running|false|0|0|healthy').encode()),
                   (0, b'other|running|false|0|0|secret-canary'), (1,b'')]
        with contextlib.redirect_stderr(output), patch.object(driver, 'command', side_effect=results):
            driver.diagnose_project_containers(name)
        self.assertIn('GUARDRAIL_RUNNING_OOM_FALSE_EXIT_0_RESTARTS_0_HEALTH_HEALTHY', output.getvalue())
        self.assertIn('AGENT_UNAVAILABLE', output.getvalue())
        self.assertIn('REDIS_UNAVAILABLE', output.getvalue())
        self.assertNotIn('secret-canary', output.getvalue())

    def test_wizard_diagnostic_is_bounded_and_only_fixed_codes_are_reported(self):
        output = io.StringIO()
        program = ("import sys\nprint('secret-canary' * 200000)\n"
                   "print('litellm_completion: fail (NETWORK_TIMEOUT)')\n"
                   "print('Мастер установки остановлен: HOST_PREFLIGHT_FAILED. secret-canary')\n"
                   "sys.exit(1)\n")
        with contextlib.redirect_stderr(output), self.assertRaisesRegex(driver.Failure, 'SIGNED_WIZARD_FAILED'):
            driver.run_signed_wizard([sys.executable, '-c', program], timeout=10)
        self.assertIn('WIZARD_CODE=HOST_PREFLIGHT_FAILED', output.getvalue())
        self.assertIn('PREFLIGHT_CODE=NETWORK_TIMEOUT', output.getvalue())
        self.assertNotIn('secret-canary', output.getvalue())

    def test_unrecognized_wizard_code_is_not_reported(self):
        output = io.StringIO()
        program = "import sys; print('Bootstrap stopped: SECRET_CANARY'); sys.exit(1)"
        with contextlib.redirect_stderr(output), self.assertRaisesRegex(driver.Failure, 'SIGNED_WIZARD_FAILED'):
            driver.run_signed_wizard([sys.executable, '-c', program], timeout=10)
        self.assertEqual(output.getvalue(), '')

    def test_signed_acceptance_diagnostic_is_allowlisted(self):
        output = io.StringIO()
        program = ("import sys; print('ACCEPTANCE_DIAGNOSTIC=CHAT_TIMEOUT'); "
                   "print('ACCEPTANCE_DIAGNOSTIC=CHAT_SECRET_CANARY'); sys.exit(1)")
        with contextlib.redirect_stderr(output), self.assertRaisesRegex(driver.Failure, 'SIGNED_WIZARD_FAILED'):
            driver.run_signed_wizard([sys.executable, '-c', program], timeout=10)
        self.assertEqual(output.getvalue(), 'SIGNED_ACCEPTANCE_DIAGNOSTIC=CHAT_TIMEOUT\n')

    def test_remote_default_daemon_rejected_before_any_mutation(self):
        remote = [{'Name': 'default', 'Endpoints': {'docker': {'Host': 'tcp://192.0.2.1:2375'}}}]
        with patch.dict(os.environ, {}, clear=True), patch.object(driver.common, 'runner_guard'), \
                patch.object(driver, 'command', return_value=(0, json.dumps(remote).encode())) as command:
            with self.assertRaisesRegex(driver.Failure, 'LOCAL_DOCKER_REQUIRED'):
                driver.main()
            command.assert_called_once_with(['docker', 'context', 'inspect', 'default'],
                                            'DOCKER_CONTEXT_UNAVAILABLE', timeout=30)

    def test_local_socket_and_active_default_context_required(self):
        local = [{'Name': 'default', 'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]
        with patch.object(driver, 'command', side_effect=[(0, json.dumps(local).encode()), (0, b'default\n')]):
            driver.require_local_docker()
        with patch.object(driver, 'command', side_effect=[(0, json.dumps(local).encode()), (0, b'other\n')]):
            with self.assertRaisesRegex(driver.Failure, 'LOCAL_DOCKER_REQUIRED'):
                driver.require_local_docker()

    def test_failed_network_create_reports_inconclusive_cleanup(self):
        def fake_command(argv, *args, **kwargs):
            if 'create' in argv:
                raise driver.Failure('LLM_NETWORK_CREATE_FAILED')
            if 'inspect' in argv:
                return 0, b'{}'
            return 0, b''
        with patch.dict(os.environ, {'BACKEND': 'compose', 'RELEASE_TAG': 'v0.1.6',
                                     'RELEASE_VERSION': '0.1.6'}, clear=True), \
                patch.object(driver.common, 'runner_guard'), patch.object(driver, 'require_local_docker'), \
                patch.object(driver, 'release_stage', return_value=(Path('/tmp/r'), Path('/tmp/b'), {}, Path('/tmp/c'))), \
                patch.object(driver.llm, 'read_host_resources', return_value=(1, 1)), \
                patch.object(driver.llm, 'preflight_resources'), patch.object(driver, 'require_project_absent'), \
                patch.object(driver.llm, 'docker_gateway', return_value='127.0.0.1'), \
                patch.object(driver, 'command', side_effect=fake_command):
            with self.assertRaisesRegex(driver.Failure, 'ISOLATED_CLEANUP_INCONCLUSIVE'):
                driver.main()

    def test_local_or_self_hosted_runner_is_rejected(self):
        with self.assertRaises(driver.common.CheckFailure):
            driver.common.runner_guard({}, ROOT, uid=0, platform='linux')
        env = {'GITHUB_ACTIONS':'true', 'GITHUB_EVENT_NAME':'workflow_dispatch',
               'RUNNER_ENVIRONMENT':'self-hosted', 'RUNNER_OS':'Linux',
               'GITHUB_REPOSITORY':'prince174/uter_deploy', 'GITHUB_WORKSPACE':str(ROOT),
               'BACKEND':'compose'}
        with self.assertRaises(driver.common.CheckFailure):
            driver.common.runner_guard(env, ROOT, uid=0, platform='linux')

    def test_exact_resource_identity_required_before_removal(self):
        name = 'uter-wizard-llm-test-proxy'
        expected = (IDENTITY + '|/' + name + '|' + OPERATION + '\n').encode()
        with patch.object(driver, 'command', return_value=(0, expected)) as command:
            driver.remove_owned('container', IDENTITY, name, OPERATION)
        self.assertEqual(command.call_args_list[1].args[0][-1], IDENTITY)
        with patch.object(driver, 'command', return_value=(0, expected.replace(OPERATION.encode(), b'c'*32))) as command:
            with self.assertRaisesRegex(driver.Failure, 'RESOURCE_IDENTITY_CHANGED'):
                driver.remove_owned('container', IDENTITY, name, OPERATION)
            self.assertEqual(command.call_count, 1)

    def test_network_with_other_attachment_is_not_removed(self):
        name = 'uter-wizard-llm-test-llm'
        identity = (IDENTITY + '|' + name + '|' + OPERATION + '\n').encode()
        with patch.object(driver, 'command', side_effect=[(0, identity), (0, b'{"other":{}}')]) as command:
            with self.assertRaisesRegex(driver.Failure, 'NETWORK_HAS_UNEXPECTED_ATTACHMENTS'):
                driver.remove_owned('network', IDENTITY, name, OPERATION)
            self.assertEqual(command.call_count, 2)

    def test_unlabeled_reserved_volume_refuses_cleanup_and_install(self):
        name = 'uter-wizard-llm-test'
        def fake(argv, *args, **kwargs):
            if 'volume' in argv and '--filter' not in argv:
                return 0, (name+'_redis-data\n').encode()
            return 0, b''
        with patch.object(driver, 'command', side_effect=fake) as command:
            with self.assertRaisesRegex(driver.Failure, 'PROJECT_IDENTITY_CHANGED'):
                driver.project_resources(name)
            self.assertTrue(all('down' not in item.args[0] for item in command.call_args_list))

    def test_failed_prepare_never_deletes_any_project(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)/'home'; home.mkdir()
            with patch.object(driver, 'command') as command:
                driver.cleanup_compose(home, 'uter-wizard-llm-test', {'images':{}})
            command.assert_not_called()

    def test_forged_home_identity_never_runs_compose_down(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)/'home'; home.mkdir()
            (home/'install-state.json').write_text('{"status":"pending"}')
            (home/'install.json').write_text(json.dumps({'name':'different', 'backend':'compose', 'context':'default'}))
            with patch.object(driver, 'command') as command:
                with self.assertRaisesRegex(driver.Failure, 'PROJECT_IDENTITY_CHANGED'):
                    driver.cleanup_compose(home, 'uter-wizard-llm-test', {'images':{}})
            command.assert_not_called()

    def test_bad_tag_or_version_rejected_before_file_access(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(driver.Failure, 'RELEASE_TAG_INVALID'):
                driver.release_stage(Path(folder), Path(folder), '../tag', '0.1.6')
            with self.assertRaisesRegex(driver.Failure, 'RELEASE_VERSION_INVALID'):
                driver.release_stage(Path(folder), Path(folder), 'tag', '../bad')

    def test_public_workflow_has_hosted_guard_and_private_key_not_in_argv(self):
        workflow = (ROOT/'.github/workflows/wizard-real-llm.yml').read_text(encoding='utf-8')
        self.assertIn('runs-on: ubuntu-24.04', workflow)
        self.assertIn('RUNNER_ENVIRONMENT', workflow)
        self.assertIn('GIT_TERMINAL_PROMPT', workflow)
        self.assertIn("--proto '=https'", workflow)
        source = (ROOT/'scripts/wizard_real_llm_ci.py').read_text(encoding='utf-8')
        self.assertIn("'--llm-key-file', keyfile", source)
        self.assertNotIn("'--llm-key', key", source)

    def test_credentials_are_not_forwarded_through_redirect(self):
        hits = []
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(True)
                self.send_response(200); self.end_headers()
            def log_message(self, *_): pass
        target = ThreadingHTTPServer(('127.0.0.1', 0), Target)
        destination = 'http://127.0.0.1:' + str(target.server_port) + '/other'
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302); self.send_header('Location', destination); self.end_headers()
            def log_message(self, *_): pass
        redirect = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (target, redirect)]
        for thread in threads: thread.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                driver.local_json('http://127.0.0.1:' + str(redirect.server_port) + '/test', token='secret-canary')
            error.exception.close()
            self.assertEqual(hits, [])
        finally:
            for server in (target, redirect): server.shutdown(); server.server_close()
            for thread in threads: thread.join(timeout=5)

    def test_public_or_non_ip_destinations_are_rejected(self):
        for url in ('https://127.0.0.1:1234/test', 'http://example.com:1234/test',
                    'http://8.8.8.8:1234/test', 'http://127.0.0.1:1234/test?key=secret'):
            with self.subTest(url=url), self.assertRaisesRegex(driver.Failure, 'LOCAL_ENDPOINT_INVALID'):
                driver.local_json(url, token='secret-canary')


if __name__ == '__main__':
    unittest.main()
