import io
import json
import os
from pathlib import Path
import unittest
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
