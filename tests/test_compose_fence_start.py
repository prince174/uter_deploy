import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import uterctl
from scripts import compose_fence_recovery_plan as plans, compose_fence_start as start, redis_fence_journal as journal
from scripts import backup_crypto
from tests import test_controller as fixtures


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
        for changes in ({'id':'0'*64},{'running':True},{'exit':137},{'oom':True},{'error':'error'},
                        {'started':'2026-10-30T00:00:01Z'},{'restart_count':1},
                        {'finished':'0001-01-01T00:00:00Z'},{'image_id':'sha256:'+'0'*64}):
            with self.subTest(changes=changes),patch.object(start.diagnostic,'_json',return_value=dict(good,**changes)):
                with self.assertRaisesRegex(start.StartError,'^FENCE_START_WRITER_EXIT_UNVERIFIED$'):
                    start._writers_stopped({'guardrail':writer},'test')


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
