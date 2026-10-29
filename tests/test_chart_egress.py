import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get('UTER_TEST_HELM') or shutil.which('helm')

@unittest.skipUnless(HELM, 'Helm binary not available')
class EgressChartTests(unittest.TestCase):
    def setUp(self):
        digest = '@sha256:' + 'a' * 64
        self.values = {
            'images': {name: 'example.test/' + name + digest for name in ('agent', 'guardrail', 'redis')},
            'guardrailSecret': 'guardrail', 'agentSecret': 'agent', 'redisSecret': 'redis',
            'policyConfigMap': 'policy', 'profileConfigMap': 'profile', 'useEmbeddedModels': True,
            'networkPolicy': {'egress': {'enabled': True,
                'dns': {'mode': 'pod', 'namespace': 'kube-system', 'podLabelKey': 'k8s-app',
                        'podLabelValue': 'kube-dns', 'port': 53},
                'llm': {'mode': 'pod', 'namespace': 'llm', 'podLabelKey': 'app',
                        'podLabelValue': 'litellm', 'port': 8080}}}}

    def render(self, values=None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'values.yaml'
            path.write_text(yaml.safe_dump(values if values is not None else self.values), encoding='utf-8')
            return subprocess.run([str(HELM), 'template', 'sample', str(ROOT / 'charts/uter'), '-f', str(path)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)

    def policies(self, values=None):
        result = self.render(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {item['metadata']['name']: item for item in yaml.safe_load_all(result.stdout)
                if item and item.get('kind') == 'NetworkPolicy'}

    def test_default_disabled_preserves_ingress_only(self):
        del self.values['networkPolicy']
        policies = self.policies()
        self.assertEqual(len(policies), 3)
        self.assertTrue(all(p['spec']['policyTypes'] == ['Ingress'] for p in policies.values()))

    def test_enabled_targets_dns_llm_and_internal_ports(self):
        policies = self.policies()
        guard = policies['sample-guardrail-egress']['spec']
        agent = policies['sample-agent-egress']['spec']
        redis = policies['sample-redis-egress']['spec']
        self.assertEqual(redis['egress'], [])
        self.assertEqual(redis['policyTypes'], ['Egress'])
        dns = guard['egress'][0]
        self.assertEqual({(p['protocol'], p['port']) for p in dns['ports']}, {('UDP', 53), ('TCP', 53)})
        peer = dns['to'][0]
        self.assertEqual(peer['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'kube-system')
        self.assertEqual(peer['podSelector']['matchLabels'], {'k8s-app': 'kube-dns'})
        self.assertEqual(agent['egress'][0], dns)
        self.assertEqual(guard['egress'][1]['ports'][0]['port'], 8001)
        self.assertEqual(guard['egress'][2]['ports'][0]['port'], 6379)
        self.assertEqual(agent['egress'][1]['ports'][0]['port'], 8000)
        llm = guard['egress'][3]
        self.assertEqual(llm['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'llm')
        self.assertEqual(llm['to'][0]['podSelector']['matchLabels'], {'app': 'litellm'})
        self.assertEqual(llm['ports'], [{'protocol': 'TCP', 'port': 8080}])
        self.assertEqual(len(agent['egress']), 2)

    def test_ipv4_requires_exact_host_and_renders_single_address(self):
        self.values['networkPolicy']['egress']['dns'] = {'mode': 'ipv4', 'ipv4': '192.0.2.53', 'port': 53}
        self.values['networkPolicy']['egress']['llm'] = {'mode': 'ipv4', 'ipv4': '192.0.2.8', 'port': 443}
        egress = self.policies()['sample-guardrail-egress']['spec']['egress']
        self.assertEqual(egress[0]['to'], [{'ipBlock': {'cidr': '192.0.2.53/32'}}])
        llm = egress[3]
        self.assertEqual(llm['to'], [{'ipBlock': {'cidr': '192.0.2.8/32'}}])
        for value in ('192.0.2.8/32', '0.0.0.0/0', '256.0.0.1', '127.00.0.1', 'llm.example', '::1', ''):
            with self.subTest(value=value):
                self.values['networkPolicy']['egress']['llm']['ipv4'] = value
                self.assertNotEqual(self.render().returncode, 0)

    def test_incomplete_or_ambiguous_configuration_fails(self):
        incomplete=copy.deepcopy(self.values)
        incomplete['networkPolicy']['egress']={'enabled': True}
        self.assertNotEqual(self.render(incomplete).returncode, 0)
        for role, key, value in [('dns','mode',''), ('llm','mode','fqdn'), ('dns','namespace',''),
                ('dns','podLabelKey',''), ('llm','podLabelValue',''), ('llm','port',0),
                ('dns','port',65536), ('llm','port','443:1'), ('dns','namespace','x\ny'),
                ('llm','podLabelKey','*')]:
            with self.subTest(role=role, key=key, value=value):
                values=copy.deepcopy(self.values)
                values['networkPolicy']['egress'][role][key]=value
                self.assertNotEqual(self.render(values).returncode, 0)
        values=copy.deepcopy(self.values)
        values['networkPolicy']['egress']['enabled']='false'
        self.assertNotEqual(self.render(values).returncode, 0)

if __name__ == '__main__':
    unittest.main()
