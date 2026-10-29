import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request, error
import unittest
from unittest.mock import patch

from scripts import networkpolicy_egress_ci as ci


class EgressCITests(unittest.TestCase):
    def test_refuses_local_execution_before_network_calls(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}, clear=True), \
                patch.object(ci, 'call') as command:
            with self.assertRaisesRegex(ci.StageError, 'DISPOSABLE_GITHUB_HOSTED_RUNNER_REQUIRED'):
                ci.run()
            command.assert_not_called()

    def test_fixture_has_real_distinct_listeners_and_narrow_label(self):
        pod = ci.fixture_pod('fixture-ns','allowed','upstream-allowed')
        self.assertEqual(pod['metadata']['labels'], {'app':'upstream-allowed'})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        containers = pod['spec']['containers']
        self.assertEqual([c['readinessProbe']['tcpSocket']['port'] for c in containers], [8080,8081])
        for c in containers:
            self.assertIn('@sha256:',c['image'])
            self.assertIn('/fixture/fixture.py',c['command'])
            self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertNotEqual(ci.fixture_pod('fixture-ns','denied','upstream-denied')['metadata']['labels'],pod['metadata']['labels'])

    def test_values_use_pod_selectors_and_only_fixture_port(self):
        values = ci.egress_values('fixture-ns')
        self.assertTrue(values['enabled'])
        self.assertEqual(values['llm'],{'mode':'pod','namespace':'fixture-ns','podLabelKey':'app',
                                        'podLabelValue':'upstream-allowed','port':8080})
        self.assertEqual(values['dns']['namespace'],'kube-system')
        self.assertEqual(values['dns']['port'],53)

    def test_dns_probes_compile_and_require_valid_answers(self):
        for protocol in ('udp','tcp'):
            source=ci.dns_probe_source(protocol)
            compile(source,'dns-probe','exec')
            self.assertIn('response[3]&15==0',source)
            self.assertIn('SOCK_DGRAM' if protocol == 'udp' else 'SOCK_STREAM',source)
        with self.assertRaises(ValueError):
            ci.dns_probe_source('other')

    def test_completion_probe_compiles_with_special_password_and_only_prints_marker(self):
        source=ci.completion_probe_source('http://guardrail:8000',"quote'\n\\marker",'unique marker')
        compile(source,'completion-probe','exec')
        self.assertIn("print('EGRESS_OK')",source)
        self.assertNotIn('print(token)',source)

    def test_fixture_counts_only_successful_completion_requests(self):
        marker='Uter fixture response '+'a'*24
        module={'__name__':'fixture_test'}
        exec(ci.fixture_source(marker),module)
        server=ThreadingHTTPServer(('127.0.0.1',0),module['Handler'])
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        def stats():
            with request.urlopen(base+'/stats',timeout=5) as response:
                return json.load(response)['completions']
        try:
            self.assertEqual(stats(),0)
            with self.assertRaises(error.HTTPError) as rejected:
                request.urlopen(request.Request(base+'/v1/chat/completions',data=b'{"model":"wrong"}'),timeout=5)
            rejected.exception.close()
            self.assertEqual(stats(),0)
            with request.urlopen(request.Request(base+'/v1/chat/completions',data=b'{"model":"test-model"}'),timeout=5) as response:
                result=json.load(response)
            self.assertEqual(result['choices'][0]['message']['content'],marker)
            self.assertEqual(stats(),1)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

    def test_completion_requires_unique_response_and_never_prints_secret(self):
        class Handler(BaseHTTPRequestHandler):
            reply={'blocked':False,'response':'Uter fixture response '+'b'*24}
            def do_POST(self):
                body=json.dumps({'access_token':'sensitive-token'} if self.path=='/auth/token' else self.reply).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port);marker='Uter fixture response '+'b'*24
        try:
            for answer,success in [({'blocked':False,'response':marker},True),
                                   ({'blocked':False,'response':'fallback'},False),
                                   ({'blocked':True,'response':marker},False)]:
                Handler.reply=answer
                output=subprocess.run([sys.executable,'-c',ci.completion_probe_source(base,'sensitive-password',marker)],
                                      capture_output=True,timeout=10)
                self.assertEqual(output.returncode==0,success)
                self.assertNotIn(b'sensitive-token',output.stdout+output.stderr)
                self.assertNotIn(b'sensitive-password',output.stdout+output.stderr)
                self.assertNotIn(marker.encode(),output.stdout+output.stderr)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

    def test_fixture_counter_rejects_invalid_results(self):
        with patch.object(ci,'call',return_value=b'17\n'):
            self.assertEqual(ci.fixture_count(['kubectl'],'fixtures',{}),17)
        for invalid in (b'-1\n',b'anything',b'1\n2\n',b''):
            with patch.object(ci,'call',return_value=invalid):
                with self.assertRaises(ci.StageError):
                    ci.fixture_count(['kubectl'],'fixtures',{})

    def test_redis_probe_uses_ephemeral_container_and_only_timeout_passes(self):
        responses=[b'redis-abc',b'',b'TIMEOUT\n']
        with patch.object(ci,'call',side_effect=responses) as calls:
            ci.redis_egress_probe(['kubectl','--context','kind-ci'],'uter-ci','uter-ci','192.168.1.12',{})
        self.assertEqual(calls.call_count,3)
        self.assertIn('debug',calls.call_args_list[1].args[0])
        args=calls.call_args_list[2].args[0]
        self.assertEqual(args[-5:],['-c','egress-probe','--','python','-'])
        source=calls.call_args_list[2].kwargs['input_data'].decode()
        compile(source,'redis-probe','exec')
        for output in (b'CONNECTED\n',b'ERROR\n',b''):
            with self.subTest(output=output),patch.object(ci,'call',side_effect=[b'redis-abc',b'',output]):
                with self.assertRaises(ci.StageError):
                    ci.redis_egress_probe(['kubectl'],'uter-ci','uter-ci','192.168.1.12',{})

    def test_invalid_ip_or_pod_name_rejected(self):
        with patch.object(ci,'call',return_value=b'not-an-address'):
            with self.assertRaisesRegex(ci.StageError,'FIXTURE_IP_INVALID'):
                ci.pod_ip(['kubectl'],'ns','name',{})
        with patch.object(ci,'call',return_value=b'--malicious'):
            # A pod name beginning with a dash cannot be a Kubernetes name, fail closed.
            with self.assertRaises(ci.StageError):
                ci.redis_egress_probe(['kubectl'],'ns','release','192.168.1.2',{})

    def test_workflow_uses_isolated_candidate_and_authenticated_assets(self):
        path=Path(__file__).resolve().parents[1]/'.github/workflows/networkpolicy-egress-e2e.yml'
        text=path.read_text(encoding='utf-8')
        self.assertIn('runs-on: ubuntu-24.04',text)
        self.assertIn('driver/scripts/networkpolicy_egress_ci.py',text)
        self.assertIn('publisher-public.pem',text)
        self.assertIn('deployment_commit',text)
        self.assertIn('persist-credentials: false',text)
        self.assertNotIn('secrets.',text)

if __name__ == '__main__':
    unittest.main()
