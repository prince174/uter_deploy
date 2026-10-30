import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import uterctl
from scripts import compose_fence_recovery_plan as plans, compose_fence_start as start, redis_fence_journal as journal
from scripts import backup_crypto
from tests import test_controller as fixtures


class ObserveStageCategoryTests(unittest.TestCase):
    def test_only_fixed_exception_categories_are_exposed(self):
        cases=[(start.diagnostic.ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_QUERY_FAILED'),
                'COMPOSE_DIAGNOSTIC_QUERY_FAILED'),
               (start.diagnostic.ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_STATE_CHANGED_ALIASES_ORDER'),
                'COMPOSE_DIAGNOSTIC_STATE_CHANGED_ALIASES_ORDER'),
               (start.diagnostic.ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_STATE_CHANGED_MOUNTS_ORDER'),
                'COMPOSE_DIAGNOSTIC_STATE_CHANGED_MOUNTS_ORDER'),
               (start.fence.compose.ComposeFenceAdapterError('COMPOSE_FENCE_REDIS_CHANGED'),
                'COMPOSE_FENCE_REDIS_CHANGED'),
               (start.diagnostic.ComposeDiagnosticError('COMPOSE_DIAGNOSTIC_TOKEN_secret'),'ERROR'),
               (KeyError('secret'),'KEY_ERROR'),(TypeError('secret'),'TYPE_ERROR'),
               (RuntimeError('secret'),'ERROR')]
        for error,category in cases:
            with self.subTest(category=category):
                with self.assertRaises(start.StartError) as result:
                    with start._observe_stage('SIGNED_LIVE'):raise error
                self.assertEqual(str(result.exception),'FENCE_START_OBSERVE_SIGNED_LIVE_'+category)
                self.assertNotIn('secret',str(result.exception))

    def test_observe_rechecks_all_mount_fields_after_order_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle=Path(directory);(bundle/'checksums.json').write_text('{}')
            redis='a'*64; net='b'*64
            endpoint={'EndpointID':'c'*64,'IPAddress':'172.30.0.5','Aliases':['redis'],
                      'MacAddress':'02:42:ac:1e:00:05'}
            live={'mounts':[{'Destination':'/data','Type':'volume','Name':'test_redis-data'},
                            {'Destination':'/config','Type':'bind','Source':'fixture'}],
                  'networks':{'test_backend':endpoint},'started':'start','restart_count':0,'image_id':'image'}
            reordered=copy.deepcopy(live);reordered['mounts'].reverse()
            changed=copy.deepcopy(reordered);changed['mounts'][0]['Source']='changed'
            invalid=copy.deepcopy(reordered);invalid['mounts'].append({'Destination':'/data/nested'})
            manifest={'version':'0.1.6','images':{'redis':'image'}};cfg={'name':'test'}
            def observe(second):
                with patch.object(start.diagnostic,'inspect_installation'), \
                     patch.object(start.uterctl,'verify',return_value=manifest), \
                     patch.object(start.uterctl,'read',return_value=cfg), \
                     patch.object(start.install,'commands',return_value=(['docker','-f','old'],{})), \
                     patch.object(start,'_writers',return_value={}), \
                     patch.object(start.diagnostic,'_read',return_value=redis[:12]), \
                     patch.object(start.diagnostic,'_json',side_effect=[redis,{'Config':[{'Subnet':'s','Gateway':'g'}]}]), \
                     patch.object(start.diagnostic,'_redis_inspect',side_effect=[live,second]), \
                     patch.object(start.diagnostic,'_require_redis',return_value=(net,'volume')), \
                     patch.object(start.plans,'validate'):
                    adapter=SimpleNamespace(**{name:Mock() for name in ('_lock','_config','_state','_network_and_volume','_peers')})
                    return start._observe(bundle,bundle,bundle,b'k'*32,adapter)
            self.assertEqual(observe(reordered)[0]['container_id'],redis)
            with self.assertRaisesRegex(start.StartError,'^FENCE_START_OBSERVE_REDIS_VOLUME$'):observe(changed)
            with self.assertRaisesRegex(start.StartError,'^FENCE_START_OBSERVE_REINSPECT_COMPOSE_DIAGNOSTIC_REDIS_INVALID$'):
                observe(invalid)


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX private files')
class ComposeFenceStartTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.key=b'k'*32
        self.plan={'schema':1,'operation':'1'*32,'site':'test','container_id':'a'*64,
                   'started_at':'2026-10-30T00:00:00.123456789Z','restart_count':0,
                   'image_ref':'ghcr.io/owner/redis@sha256:'+'b'*64,'image_config_id':'sha256:'+'c'*64,
                   'restart_policy':'unless-stopped','volume_name':'test_redis-data','volume_driver':'local',
                   'network_id':'d'*64,'network_name':'test_backend','network_driver':'bridge','network_scope':'local',
                   'network_internal':True,'network_subnet':'172.30.0.0/16','network_gateway':'172.30.0.1',
                   'endpoint_id':'e'*64,'endpoint_ipv4':'172.30.0.5','endpoint_static_ipv4':None,
                   'endpoint_aliases':['redis','test-redis-1'],'endpoint_mac':'02:42:ac:1e:00:05',
                   'ipv6_enabled':False,'network_options':{},'endpoint_driver_options':{}}
        self.writers={name:{'id':identifier*64,'started':'2026-10-30T00:00:00Z','restart_count':0,
                            'image_ref':'ghcr.io/owner/'+name+'@sha256:'+'b'*64,'image_id':'sha256:'+'c'*64}
                      for name,identifier in (('guardrail','f'),('agent','9'))}
        self.adapter=Mock();self.adapter._lock=Mock()

    def _success(self,home,operation,adapter):
        journal.advance(home,operation=operation,expected='prepared',next_phase='isolating')
        journal.advance(home,operation=operation,expected='isolating',next_phase='isolated')

    def test_signed_writer_ids_and_durable_intent_exist_before_stop(self):
        def stop(*args):
            self.assertEqual(args,('stop','--time','25',self.writers['guardrail']['id'],self.writers['agent']['id']))
            record=journal.read(self.home);self.assertEqual(record['phase'],'prepared')
            envelope=json.loads((self.home/start.NAME).read_text());raw=envelope['intent']
            self.assertEqual((raw['guardrail'],raw['agent']),tuple(self.writers.values()))
            self.assertEqual(raw['plan_sha256'],record['plan_sha256'])
            derived=backup_crypto.derive_key(self.key,b'compose-fence-start-intent-v1')
            self.assertTrue(hmac.compare_digest(envelope['mac'],hmac.new(derived,start._canonical(raw),hashlib.sha256).hexdigest()))
            self.assertEqual(plans.read(self.home,self.key,record['plan_sha256'],operation=record['operation'],
                                        site='test',resource=self.plan['container_id']),self.plan)
        self.adapter._run.side_effect=stop
        with patch.object(start.fence,'Adapter',return_value=self.adapter), \
             patch.object(start,'_observe',return_value=(self.plan,self.writers,'8'*64)), \
             patch.object(start,'_writers_stopped') as stopped, \
             patch.object(start.protocol,'isolate',side_effect=self._success):
            operation=start.start(self.home,'bundle','publisher',self.key)
        self.assertEqual(operation,self.plan['operation']);self.assertEqual(journal.read(self.home)['phase'],'isolated')
        stopped.assert_called_once_with(self.writers,'test')
        current=journal.read(self.home)
        self.assertEqual(start.read_intent(self.home,self.key,current,'8'*64)['guardrail'],self.writers['guardrail'])
        for wrong_key,wrong_record,wrong_hash in ((b'x'*32,current,'8'*64),
                                                  (self.key,dict(current,operation='0'*32),'8'*64),
                                                  (self.key,current,'0'*64)):
            with self.subTest(wrong_key=wrong_key,wrong_record=wrong_record,wrong_hash=wrong_hash):
                with self.assertRaisesRegex(start.StartError,'^FENCE_START_INTENT_UNVERIFIED$'):
                    start.read_intent(self.home,wrong_key,wrong_record,wrong_hash)
        intent_path=self.home/start.NAME;original=intent_path.read_bytes()
        intent_path.write_bytes(original.replace(b'"guardrail"',b'"guardraim"'))
        with self.assertRaisesRegex(start.StartError,'^FENCE_START_INTENT_UNVERIFIED$'):
            start.read_intent(self.home,self.key,current,'8'*64)
        intent_path.write_bytes(original)
        self.adapter.close.assert_called_once()

    def test_faults_never_resume_and_preserve_existing_evidence(self):
        for stage in ('observe','intent','journal','recheck','stop','writer_exit','isolate'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as folder:
                home=Path(folder);adapter=Mock();adapter._lock=Mock()
                responses=[(self.plan,self.writers,'8'*64),(self.plan,self.writers,'8'*64)]
                if stage=='observe':responses[0]=RuntimeError('uncertain')
                if stage=='recheck':responses[1]=RuntimeError('uncertain')
                if stage=='stop':adapter._run.side_effect=RuntimeError('stop timeout')
                with patch.object(start.fence,'Adapter',return_value=adapter), \
                     patch.object(start,'_observe',side_effect=responses), \
                     patch.object(start,'_write_intent',side_effect=RuntimeError('uncertain') if stage=='intent' else start._write_intent), \
                     patch.object(start.journal,'create',side_effect=RuntimeError('uncertain') if stage=='journal' else journal.create), \
                     patch.object(start,'_writers_stopped',side_effect=RuntimeError('uncertain') if stage=='writer_exit' else None), \
                     patch.object(start.protocol,'isolate',side_effect=RuntimeError('uncertain') if stage=='isolate' else self._success):
                    with self.assertRaises(start.StartError):start.start(home,'bundle','publisher',self.key)
                self.assertEqual(adapter._run.call_count,1 if stage in ('stop','writer_exit','isolate') else 0)
                if stage in ('recheck','stop','writer_exit','isolate'):
                    self.assertEqual(journal.read(home)['phase'],'prepared')
                    self.assertTrue((home/start.NAME).is_file())
                if stage in ('intent','journal'):
                    self.assertTrue((home/plans.NAME).exists())
                self.assertFalse(any('start' in str(c).lower() or 'up' in str(c).lower() for c in adapter._run.call_args_list))
                adapter.close.assert_called_once()

    def test_existing_evidence_blocks_before_observation_or_stop(self):
        (self.home/start.NAME).symlink_to(self.home/'missing')
        with patch.object(start.fence,'Adapter',return_value=self.adapter),patch.object(start,'_observe') as observe:
            with self.assertRaisesRegex(start.StartError,'^FENCE_START_PRIOR_OPERATION$'):
                start.start(self.home,'bundle','publisher',self.key)
        observe.assert_not_called();self.adapter._run.assert_not_called()

    def test_writer_exit_requires_same_instance_and_unforced_success(self):
        writer=self.writers['guardrail']
        good={'id':writer['id'],'running':False,'started':writer['started'],
              'finished':'2026-10-30T00:01:00Z','exit':0,'oom':False,'error':'',
              'restart_count':writer['restart_count'],'project':'test','service':'guardrail',
              'image_ref':writer['image_ref'],'image_id':writer['image_id']}
        with patch.object(start.diagnostic,'_json',return_value=good):
            start._writers_stopped({'guardrail':writer},'test')
        cases=(({'id':'0'*64},'IDENTITY'),({'running':True},'RUNNING'),({'exit':True},'EXIT_TYPE'),
               ({'exit':137},'EXIT_NONZERO'),({'oom':True},'OOM'),({'error':'secret-canary'},'ENGINE_ERROR'),
               ({'started':'changed'},'STARTED'),({'restart_count':1},'RESTART_COUNT'),
               ({'project':'other'},'PROJECT'),({'service':'other'},'SERVICE'),({'image_ref':'other'},'IMAGE_REF'),
               ({'image_id':'sha256:'+'0'*64},'IMAGE_ID'),({'finished':'0001-01-01T00:00:00Z'},'FINISHED'))
        for service in ('agent','guardrail'):
            expected=self.writers[service]
            base=dict(good,id=expected['id'],started=expected['started'],restart_count=expected['restart_count'],
                      image_ref=expected['image_ref'],image_id=expected['image_id'],service=service)
            for changes,category in cases:
                with self.subTest(service=service,category=category),patch.object(start.diagnostic,'_json',return_value=dict(base,**changes)):
                    with self.assertRaises(start.StartError) as error:
                        start._writers_stopped({service:expected},'test')
                    self.assertEqual(str(error.exception),'FENCE_START_WRITER_STOP_'+service.upper()+'_'+category)
                    self.assertNotIn('secret-canary',str(error.exception))
            with patch.object(start.diagnostic,'_json',return_value='secret-canary'):
                with self.assertRaises(start.StartError) as error:start._writers_stopped({service:expected},'test')
                self.assertEqual(str(error.exception),'FENCE_START_WRITER_STOP_'+service.upper()+'_RESPONSE')

    def test_fixed_diagnostic_classes_never_expose_changed_values(self):
        examples={'container_id':'PROCESS','image_ref':'IMAGE','network_id':'NETWORK_ID',
                  'network_driver':'NETWORK_POLICY','network_subnet':'IPAM','endpoint_id':'ENDPOINT_ID',
                  'endpoint_ipv4':'ENDPOINT_ADDRESS','endpoint_aliases':'ENDPOINT_ALIASES',
                  'endpoint_mac':'ENDPOINT_MAC','endpoint_driver_options':'ENDPOINT_OPTIONS','volume_name':'VOLUME',
                  'site':'OTHER'}
        for field,category in examples.items():
            with self.subTest(field=field):
                altered=dict(self.plan,**{field:'secret-canary'})
                code=start._plan_change(self.plan,altered)
                self.assertEqual(code,'FENCE_START_RECHECK_PLAN_'+category)
                self.assertNotIn('secret-canary',code)
        for field,category in (('id','IDENTITY'),('image_id','IDENTITY'),('started','STARTED'),('restart_count','RESTART')):
            changed={name:dict(value) for name,value in self.writers.items()}
            changed['agent'][field]='secret-canary'
            code=start._writers_change(self.writers,changed,'FENCE_START_RECHECK_WRITERS')
            self.assertEqual(code,'FENCE_START_RECHECK_WRITERS_'+category)


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX private files')
class FenceStartCLITests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.ControllerTests(methodName='test_signed_bundle');self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.fx.home.chmod(0o700);self.key=self.fx.prepare_adopted();self.bundle=self.fx.home/'releases'/'1.0.0'
        guard=patch.object(uterctl,'_load_signed_fence_executor');guard.start();self.addCleanup(guard.stop)

    def test_cli_holds_lock_while_calling_start_and_never_deploys(self):
        def fake(home,bundle,publisher,key):
            self.assertEqual((home/'operation.lock').read_text(),str(os.getpid()))
            self.assertEqual(key,b'k'*32);return '1'*32
        out=io.StringIO()
        with patch.object(start,'start',side_effect=fake),patch.object(uterctl,'deploy') as deploy,contextlib.redirect_stdout(out):
            uterctl.main(['fence-start-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                          '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        deploy.assert_not_called();self.assertIn('no update or session migration is authorized',out.getvalue())
        self.assertFalse((self.fx.home/'operation.lock').exists())

    def test_tampered_product_rejected_before_docker_and_journal(self):
        (self.bundle/'compose/compose.yaml').write_text('tampered',encoding='utf-8')
        with patch.object(start.diagnostic,'_read') as docker:
            with self.assertRaises(start.StartError):
                uterctl.main(['fence-start-redis','--home',str(self.fx.home),'--bundle',str(self.bundle),
                              '--key',str(self.fx.pub),'--executor-key',str(self.fx.pub),'--backup-key',str(self.key)])
        docker.assert_not_called()
        self.assertFalse((self.fx.home/journal.NAME).exists())
        self.assertFalse((self.fx.home/plans.NAME).exists())
        self.assertFalse((self.fx.home/start.NAME).exists())
