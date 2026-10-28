import io
import json
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
import yaml
from unittest.mock import patch

from scripts import litellm_vllm_ci as ci


class CPURealLLMWorkflowTests(unittest.TestCase):
    def test_sums_generation_token_counters_without_other_metrics(self):
        metrics = '# HELP vllm:generation_tokens_total tokens\n' \
                  'vllm:generation_tokens_total{model_name="a",engine="0"} 12.0\n' \
                  'vllm:generation_tokens_total{model_name="a",engine="1"} 2e+1\n' \
                  'vllm:prompt_tokens_total 99\n'
        self.assertEqual(ci.metric_total(metrics), 32)
        with self.assertRaisesRegex(ValueError, 'metric missing'):
            ci.metric_total('vllm:generation_tokens_total NaN\n')

    def test_resources_fail_before_download_with_safe_categories(self):
        ci.preflight_resources('compose', {'avx2'}, 8 * ci.GIB, 8 * ci.GIB)
        ci.preflight_resources('kubernetes', {'avx512f'}, 10 * ci.GIB, 10 * ci.GIB)
        cases = [('compose', set(), 20, 20, 'CPU_FLAGS_UNSUPPORTED'),
                 ('compose', {'avx2'}, 20, 7, 'DISK_SPACE_INSUFFICIENT'),
                 ('kubernetes', {'avx2'}, 9, 20, 'AVAILABLE_MEMORY_INSUFFICIENT'),
                 ('kubernetes', {'avx2'}, 20, 9, 'DISK_SPACE_INSUFFICIENT')]
        for backend, flags, mem, disk, category in cases:
            with self.subTest(category=category), self.assertRaises(ci.DiagnosticError) as caught:
                ci.preflight_resources(backend, flags, mem * ci.GIB, disk * ci.GIB)
            self.assertEqual(caught.exception.category, category)

    def test_commands_report_fixed_safe_categories_without_output(self):
        failed = SimpleNamespace(returncode=1, stdout=b'confidential', stderr=b'secret-value')
        with patch.object(ci.subprocess, 'run', return_value=failed):
            for category in ('KIND_CREATE_FAILED', 'KIND_RESOURCE_LIMIT_FAILED'):
                with self.subTest(category=category), self.assertRaises(ci.DiagnosticError) as caught:
                    ci.call(['kind', 'create'], failure=category)
                self.assertEqual(caught.exception.category, category)
                self.assertNotIn('secret', str(caught.exception))
            with self.assertRaises(ValueError):
                ci.call(['kind', 'create'], failure='SECRET_MUST_NOT_BECOME_CATEGORY')

    def test_container_inspection_uses_only_fixed_state_fields(self):
        states = [(b'running false 0', False, None),
                  (b'running false 0', True, 'VLLM_READINESS_TIMEOUT_RUNNING'),
                  (b'exited true 137', False, 'VLLM_OOM_KILLED_EXIT_137'),
                  (b'exited false 1', False, 'VLLM_EXITED_1'),
                  (b'broken secret-value', True, 'VLLM_STATE_UNAVAILABLE')]
        for output, timeout, expected in states:
            with self.subTest(output=output), patch.object(ci.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=output, stderr=b'secret-value')) as run:
                self.assertEqual(ci.container_state_category('fixed-name', 'VLLM', timeout=timeout), expected)
                args = run.call_args_list[0].args[0]
                self.assertIn('--format', args)
                self.assertIn('{{.State.Status}} {{.State.OOMKilled}} {{.State.ExitCode}}', args)
                self.assertNotIn('Config', ' '.join(args))

    def test_known_log_errors_map_to_fixed_categories_only(self):
        cases = [
            ('Illegal instruction; token=secret-value', 'CPU_INSTRUCTION_UNSUPPORTED'),
            ('RuntimeError: Cannot allocate memory', 'MEMORY_ALLOCATION_FAILED'),
            ('OSError: [Errno 28] No space left on device', 'DISK_FULL'),
            ('vllm serve: error: unrecognized arguments: --bad', 'CLI_ARGUMENT_INVALID'),
            ('RevisionNotFoundError: private value', 'MODEL_REVISION_NOT_FOUND'),
            ('RepositoryNotFoundError: private value', 'MODEL_REPOSITORY_NOT_FOUND'),
            ('unsupported model architecture Something', 'MODEL_ARCHITECTURE_UNSUPPORTED'),
            ('config.json was not found', 'MODEL_CONFIG_INVALID'),
            ('float16 is not supported', 'DTYPE_OR_PLATFORM_UNSUPPORTED'),
            ('KV cache size too small', 'KV_CACHE_INSUFFICIENT'),
            ('Temporary failure in name resolution', 'DNS_RESOLUTION_FAILED'),
            ('SSL CERTIFICATE_VERIFY_FAILED', 'TLS_CERTIFICATE_FAILED'),
            ('httpx.ReadTimeout', 'NETWORK_TIMEOUT'),
            ('Network is unreachable', 'NETWORK_CONNECTION_FAILED'),
            ('ImportError: undefined symbol XYZ', 'MODULE_OR_LIBRARY_IMPORT_FAILED'),
            ('Engine core initialization failed.', 'ENGINE_INITIALIZATION_FAILED'),
            ('huggingface_hub error: 401 Client Error token=secret-value', 'HF_HTTP_401'),
            ('https://huggingface.co/model: 403 Client Error', 'HF_HTTP_403'),
            ('https://huggingface.co/model: HTTP status code 429', 'HF_HTTP_429'),
        ]
        for message, category in cases:
            with self.subTest(category=category):
                self.assertIn(category, ci.classify_container_log(message))
                self.assertNotIn('secret-value', ci.classify_container_log(message))
        self.assertIsNone(ci.classify_container_log('some unknown secret-value'))
        self.assertIsNone(ci.classify_container_log('unrelated service HTTP 401'))

    def test_vllm_032_cpu_memory_and_kv_messages(self):
        samples = [
            ('ValueError: Available memory on node 0 (4.0/16.0 GiB) on startup is less than desired CPU memory utilization (0.92, 14.72 GiB).',
             'CPU_REQUESTED_MEMORY_EXCEEDS_AVAILABLE'),
            ('ValueError: Available memory on node 0 (0.5/16.0 GiB) on kv cache allocation is less than requested memory for kv (1.0 GiB).',
             'CPU_KV_ALLOCATION_EXCEEDS_AVAILABLE'),
            ("ValueError: To serve at least one request with the model's max seq len (2048), (1.2 GiB KV cache is needed, which is larger than the available KV cache memory (1.0 GiB).",
             'KV_CACHE_TOO_SMALL_FOR_MODEL_CONTEXT'),
            ('ValueError: Invalid prefix_match_unit=31; prefix-cacheable KV cache group block sizes must be divisible by prefix_match_unit.',
             'KV_PREFIX_MATCH_INVALID'),
            ("ValueError: KV cache layout BLHNC cannot express this model's mixed page sizes (1, 2).",
             'KV_CACHE_LAYOUT_UNSUPPORTED'),
        ]
        for message, category in samples:
            with self.subTest(category=category):
                self.assertIn(category, ci.classify_container_log(message))

    def test_valueerror_keywords_are_only_allowlisted_and_only_on_valueerror_lines(self):
        output = ci.classify_container_log('ValueError: CPU memory cache secret=VERYSECRET\nRuntimeError: thread affinity super-secret')
        for word in ('VALWORD_CPU', 'VALWORD_MEMORY', 'VALWORD_CACHE'):
            self.assertIn(word, output)
        self.assertNotIn('VALWORD_THREAD', output)
        self.assertNotIn('VALWORD_AFFINITY', output)
        self.assertNotIn('VERYSECRET', output)
        self.assertNotIn('super-secret', output)

    def test_log_classifier_returns_all_safe_diagnostics_without_raw_content(self):
        message = ("PermissionError: secret=super-secret\n"
                   "sched_setaffinity failed with EACCES\n"
                   "numa binding failed\n"
                   "worker process unexpectedly exited\n"
                   "RuntimeError: Engine core initialization failed.\n"
                   "UntrustedSecretError: should never be output\n"
                   "ValueError: model download failed\n")
        actual = ci.classify_container_log(message)
        for category in ('PERMISSION_DENIED', 'THREAD_BINDING_FAILED', 'NUMA_BINDING_FAILED',
                         'WORKER_PROCESS_EXITED', 'MODEL_DOWNLOAD_FAILED',
                         'ENGINE_INITIALIZATION_FAILED', 'EXC_PERMISSIONERROR',
                         'EXC_RUNTIMEERROR', 'EXC_VALUEERROR'):
            self.assertIn(category, actual)
        self.assertNotIn('UntrustedSecretError', actual)
        self.assertNotIn('super-secret', actual)
        self.assertNotIn('should never', actual)

    def test_log_reader_inspects_only_bounded_tail_without_printing(self):
        def docker_logs(args, **kwargs):
            self.assertEqual(args, ['docker', 'logs', '--tail', '1000', 'fixture'])
            kwargs['stdout'].write(b'x' * ci.LOG_LIMIT + b'\nIllegal instruction token=secret-value')
            return SimpleNamespace(returncode=0)
        with patch.object(ci.subprocess, 'run', side_effect=docker_logs):
            self.assertEqual(ci.container_log_category('fixture'), 'CPU_INSTRUCTION_UNSUPPORTED')

    def test_exit_category_contains_only_safe_code_and_whitelisted_cause(self):
        state = SimpleNamespace(returncode=0, stdout=b'exited false 1', stderr=b'secret-value')
        with patch.object(ci.subprocess, 'run', return_value=state), \
             patch.object(ci, 'container_log_category', return_value='MODEL_CONFIG_INVALID'):
            self.assertEqual(ci.container_state_category('fixture', 'VLLM'),
                             'VLLM_EXITED_1_MODEL_CONFIG_INVALID')

    def test_readiness_stops_immediately_when_container_exited(self):
        with patch.object(ci, 'json_request', side_effect=OSError('sensitive')) as request, \
             patch.object(ci.time, 'sleep') as sleep:
            with self.assertRaises(ci.DiagnosticError) as caught:
                ci.wait_json('http://127.0.0.1:1', attempts=5, state_probe=lambda timeout: 'VLLM_EXITED_1')
        self.assertEqual(caught.exception.category, 'VLLM_EXITED_1')
        request.assert_called_once()
        sleep.assert_not_called()

    def test_kind_memory_and_swap_limits_are_set_together(self):
        args = ci.kind_resource_limit_command('isolated-kind')
        self.assertEqual(args[:2], ['docker', 'update'])
        self.assertEqual(args[args.index('--memory') + 1], '7g')
        self.assertEqual(args[args.index('--memory-swap') + 1], '7g')
        self.assertEqual(args[args.index('--cpus') + 1], '2')
        self.assertEqual(args[-1], 'isolated-kind-control-plane')

    def test_backend_uses_its_own_private_docker_gateway(self):
        bridge = [{'IPAM': {'Config': [{'Gateway': '172.17.0.1'}]}}]
        node = [{'NetworkSettings': {'Networks': {'kind': {'Gateway': '172.19.0.1'}}}}]
        self.assertEqual(ci.docker_gateway('compose', bridge), '172.17.0.1')
        self.assertEqual(ci.docker_gateway('kubernetes', node), '172.19.0.1')
        with self.assertRaisesRegex(ValueError, 'private IPv4'):
            ci.docker_gateway('compose', [{'IPAM': {'Config': [{'Gateway': '8.8.8.8'}]}}])
        with self.assertRaises(ValueError):
            ci.docker_gateway('unknown', {})

    def test_completion_requires_nonempty_openai_message(self):
        with patch.object(ci, 'json_request', return_value={'choices': [{'message': {'content': 'hello'}}]}) as request:
            self.assertTrue(ci.completion('http://127.0.0.1:1', 'test', token='example', extra_headers={'X-Test': 'x'}))
            self.assertEqual(request.call_args.kwargs['extra_headers'], {'X-Test': 'x'})
        for value in ({'choices': []}, {'choices': [{'message': {'content': ''}}]}, {}):
            with self.subTest(value=value), patch.object(ci, 'json_request', return_value=value):
                with self.assertRaises(ValueError):
                    ci.completion('http://127.0.0.1:1', 'test')

    def test_driver_refuses_non_ci_execution_before_docker(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}, clear=True), patch.object(ci, 'call') as call:
            with self.assertRaises(RuntimeError):
                ci.main()
            call.assert_not_called()

    def test_proxy_configuration_has_isolated_backend_and_external_key(self):
        config = yaml.safe_load(ci.proxy_config())
        self.assertEqual(config['model_list'][0]['model_name'], ci.MODEL_ALIAS)
        params = config['model_list'][0]['litellm_params']
        self.assertEqual(params['model'], 'hosted_vllm/' + ci.MODEL)
        self.assertEqual(params['api_base'], 'http://vllm:8000')
        self.assertEqual(config['general_settings']['master_key'], 'os.environ/LITELLM_MASTER_KEY')

    def test_release_and_third_party_inputs_are_pinned(self):
        self.assertRegex(ci.VLLM_IMAGE, r'@sha256:[0-9a-f]{64}$')
        self.assertRegex(ci.LITELLM_IMAGE, r'@sha256:[0-9a-f]{64}$')
        self.assertRegex(ci.MODEL_REVISION, r'^[0-9a-f]{40}$')
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/litellm-vllm-ci.yml').read_text(encoding='utf-8-sig')
        self.assertIn('installation_archive_sha256', workflow)
        self.assertIn('work/signed/scripts/extract_release_inputs.py', workflow)
        self.assertIn('--bundle work/signed --key work/download/publisher-public.pem', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('persist-credentials: false', workflow)
        parsed = yaml.load(workflow, Loader=yaml.BaseLoader)
        job = parsed['jobs']['real-llm']
        self.assertEqual(job['strategy']['matrix']['backend'], ['compose', 'kubernetes'])
        self.assertEqual(parsed['on']['workflow_dispatch']['inputs']['release_tag']['default'],
                         'deploy-2026.10.28-signed-5')
        self.assertEqual(parsed['permissions'], {'contents': 'read'})
        self.assertRegex(ci.KIND_IMAGE, r'@sha256:[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
