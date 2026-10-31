import os
from pathlib import Path
import unittest
import json
import tempfile
from unittest.mock import patch
import yaml

from scripts import redis_acl_staged_product_ci as product, maintenance_compose_product_ci as maintenance


class ProductStagedCIGuards(unittest.TestCase):
    def test_requires_hosted_fixture_before_network_or_docker(self):
        with patch.dict(os.environ,{},clear=True),patch.object(product.urllib.request,'urlopen') as http, \
             patch.object(product.product,'exercise') as engine:
            with self.assertRaisesRegex(product.ProductStageError,'ENVIRONMENT_UNVERIFIED'):
                product.exercise('/unused','project','admin','acl','writer','/acl')
            http.assert_not_called();engine.assert_not_called()

    def test_maintenance_hook_refuses_invalid_project_before_docker(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
             'UTER_CI_MAINTENANCE':'true','UTER_CI_STAGED_PRODUCT':'true'}
        with patch.dict(os.environ,env,clear=True),patch.object(maintenance.Path,'resolve') as resolve, \
             patch.object(maintenance,'_docker') as docker:
            resolve.return_value=Path('/fixture/work/integration')
            with self.assertRaisesRegex(maintenance.ProbeError,'ENVIRONMENT_UNVERIFIED'):
                maintenance.exercise('/fixture/work/integration',project='uter-other',
                                     before_collect=lambda *_:None,after_collect=lambda *_:None)
            docker.assert_not_called()

    def test_manual_workflow_runs_independent_drain_and_restart_scenarios(self):
        path=Path(__file__).resolve().parents[1]/'.github/workflows/redis-staged-product-ci.yml'
        document=yaml.load(path.read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(document['on']),{'workflow_dispatch'})
        self.assertEqual(document['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(document['jobs']['product']['strategy']['matrix']['scenario'],['drain','restart'])

    def test_llm_fixture_has_bounded_input(self):
        text=(Path(__file__).resolve().parents[1]/'tests/fixtures/staged_upstream.py').read_text()
        compile(text,'staged_upstream.py','exec')
        self.assertIn('size<=1048576',text)

    def test_restart_auth_denial_must_come_from_guardrail_ip(self):
        entry=['reason','auth','username','uter-writer','client-info','id=1 addr=172.18.0.3:54321']
        self.assertTrue(product._guardrail_auth_denied([entry],'172.18.0.3'))
        self.assertFalse(product._guardrail_auth_denied([entry],'172.18.0.4'))
        self.assertFalse(product._guardrail_auth_denied([['reason','command','username','uter-writer',
                    'client-info','id=1 addr=172.18.0.3:54321']],'172.18.0.3'))
        with self.assertRaises(ValueError):
            product._guardrail_auth_denied([entry+['reason','auth']],'172.18.0.3')

    def test_ci_hooks_wrap_real_protocol_collection_in_order(self):
        project='uter-acl-'+'a'*32;ids={'agent':'1'*64,'guardrail':'2'*64,'redis':'3'*64}
        images={'agent':'sha256:'+'a'*64,'guardrail':'sha256:'+'b'*64}
        events=[]
        def docker(*args):
            if args[0]=='ps':
                service=next(x.rsplit('=',1)[1] for x in args if x.startswith('label=com.docker.compose.service='))
                return ids[service]
            if args[0]=='image':return images[args[-1].split('-')[1]]
            service=next(name for name,value in ids.items() if value==args[-1])
            return json.dumps({'id':ids[service],'image':images.get(service),'running':True,
                'started':'2026-01-01T00:00:00Z','restarts':0,'project':project,'service':service})
        def collect(inventory,**_kwargs):
            events.append('collect');return {ids['agent']:{},ids['guardrail']:{}}
        def before(_recorder,_pinned,stable):self.assertTrue(stable());events.append('before')
        def after(_recorder,_pinned,_receipts,stable):self.assertTrue(stable());events.append('after')
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)/'work/integration';home.mkdir(parents=True)
            env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                 'UTER_CI_MAINTENANCE':'true','UTER_CI_STAGED_PRODUCT':'true'}
            with patch.dict(os.environ,env,clear=True),patch.object(maintenance,'_docker',side_effect=docker), \
                 patch.object(maintenance.maintenance_protocol,'collect',side_effect=collect):
                maintenance.exercise(home,project=project,before_collect=before,after_collect=after)
        self.assertEqual(events,['before','collect','after'])
