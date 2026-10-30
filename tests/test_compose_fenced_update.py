import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from scripts import compose_fenced_update as update
from scripts import redis_fence_journal as journal
from tests import test_controller as fixtures


class ComposeFencedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.old={'version':'1.0.0','data_epoch':1,'images':{'redis':'r','agent':'a','guardrail':'g'}}
        self.new={'version':'1.1.0','data_epoch':1,'upgrade_from':['1.0.0'],
                  'images':{'redis':'r','agent':'new-a','guardrail':'new-g'}}
        self.base={'services':{k:{'image':v,'networks':['backend']} for k,v in self.old['images'].items()},
                   'networks':{'backend':{'internal':True}},'volumes':{'redis-data':{'driver':'local'}}}
        self.target=copy.deepcopy(self.base)
        self.target['services']['agent']['image']='new-a';self.target['services']['guardrail']['image']='new-g'

    def test_only_signed_writer_images_may_differ_in_complete_config(self):
        update._compare_configs(self.base,self.target,self.old,self.new)
        for path in ('redis_image','volume','network','writer_env','extra_service'):
            changed=copy.deepcopy(self.target)
            if path=='redis_image':changed['services']['redis']['image']='other'
            if path=='volume':changed['volumes']['redis-data']['driver']='other'
            if path=='network':changed['networks']['backend']['internal']=False
            if path=='writer_env':changed['services']['guardrail']['environment']={'UNEXPECTED':'1'}
            if path=='extra_service':changed['services']['extra']={}
            with self.subTest(path=path),self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_CONFIG_CHANGED$'):
                update._compare_configs(self.base,changed,self.old,self.new)

    def test_config_runs_with_bounded_clean_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);bundle=home/'signed';site={'name':'test','port':8080,'guardrail_cpus':2}
            with patch.dict(os.environ,{'DOCKER_HOST':'tcp://evil','COMPOSE_PROFILES':'evil','API_KEY':'secret'}), \
                 patch.object(update.install_recovery,'run_readonly',return_value='{}') as run:
                self.assertEqual(update._config(home,bundle,self.old,site),{})
            command=run.call_args.args[0];env=run.call_args.kwargs['env']
            self.assertNotIn('DOCKER_HOST',env);self.assertNotIn('COMPOSE_PROFILES',env);self.assertNotIn('API_KEY',env)
            self.assertEqual(command[:3],['/usr/bin/docker','--context','default'])
            self.assertEqual(command[-3:],['config','--format','json'])
            self.assertEqual(run.call_args.kwargs['timeout'],30)

    def test_cross_epoch_or_changed_redis_refused_before_config(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);source=home/'old';target=home/'new';source.mkdir();target.mkdir()
            site={'backend':'compose','context':'default','name':'test','namespace':'test'}
            state={'adopted_installer':True,'current':self.old,'pending':None}
            for scenario in ('epoch','redis'):
                newer=copy.deepcopy(self.new)
                if scenario=='epoch':newer['data_epoch']=2
                else:newer['images']['redis']='other'
                with patch.object(update.uterctl,'verify',side_effect=[self.old,newer]), \
                     patch.object(update.uterctl,'transition'),patch.object(update,'_config') as config:
                    with self.subTest(scenario=scenario),self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_PREFLIGHT_UNVERIFIED$'):
                        update.preflight(home,source,target,'key',state,site)
                    config.assert_not_called()

    def test_same_epoch_signed_preflight_requires_identical_files_and_full_config(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);source=home/'old';target=home/'new'
            for path in (source,target):
                (path/'compose').mkdir(parents=True)
                (path/'examples').mkdir()
                (path/'compose/compose.yaml').write_text('signed compose')
                (path/'empty.env').write_bytes(b'')
                (path/'examples/redis.conf.example').write_text('fixed redis template')
            site={'backend':'compose','context':'default','name':'test','namespace':'test'}
            state={'adopted_installer':True,'current':self.old,'pending':None}
            with patch.object(update.uterctl,'verify',side_effect=[self.old,self.new]), \
                 patch.object(update.uterctl,'transition') as transition, \
                 patch.object(update,'_config',side_effect=[self.base,self.target]):
                self.assertEqual(update.preflight(home,source,target,'key',state,site),(self.old,self.new))
                transition.assert_called_once_with(self.old,self.new)
            (target/'compose/compose.yaml').write_text('changed')
            with patch.object(update.uterctl,'verify',side_effect=[self.old,self.new]), \
                 patch.object(update.uterctl,'transition'),patch.object(update,'_config') as config:
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_PREFLIGHT_UNVERIFIED$'):
                    update.preflight(home,source,target,'key',state,site)
                config.assert_not_called()

    @unittest.skipUnless(os.name=='posix','POSIX durable target staging')
    def test_target_bundle_is_verified_copied_and_reverified_without_workload_access(self):
        fixture=fixtures.ControllerTests(methodName='test_signed_bundle');fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.home.chmod(0o700);releases=fixture.home/'releases';releases.mkdir()
        (fixture.home/'operation.lock').write_text(str(os.getpid()));(fixture.home/'operation.lock').chmod(0o600)
        manifest=fixtures.manifest('1.1.0',['1.0.0']);bundle=fixture.bundle(manifest,'new')
        destination=update.stage_target(fixture.home,bundle,fixture.pub,manifest)
        self.assertEqual(destination,releases/'1.1.0')
        self.assertEqual(update.uterctl.verify(destination,fixture.pub),manifest)
        self.assertEqual(update.stage_target(fixture.home,bundle,fixture.pub,manifest),destination)
        (destination/'source.py').write_text('tampered')
        with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_TARGET_STAGE_UNCERTAIN$'):
            update.stage_target(fixture.home,bundle,fixture.pub,manifest)

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_durable_intent_is_write_once_bound_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);key=b'k'*32
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            (home/'operation.lock').write_text(str(os.getpid()));(home/'operation.lock').chmod(0o600)
            value=update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            self.assertEqual(update.read_intent(home,key,record),value)
            self.assertTrue(journal.blocks_mutation(home))
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_INTENT_UNCERTAIN$'):
                update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            path=home/journal.UPDATE_INTENT
            raw=path.read_bytes();path.write_bytes(raw.replace(b'"source_sha256":"cccc',b'"source_sha256":"dddd'))
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_INTENT_UNVERIFIED$'):
                update.read_intent(home,key,record)
            self.assertTrue(path.exists())

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_capture_stage_persists_target_intent_and_does_not_release(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);key=b'k'*32
            source=home/'releases'/'1.0.0';source.mkdir(parents=True);target=home/'target';target.mkdir()
            (source/'checksums.json').write_text('signed source');(target/'checksums.json').write_text('signed target')
            (home/'state.json').write_text('{}');(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600);destination=home.parent/'unused-test-backup'
            adapter=Mock();adapter.attach_before_capture_recovery.return_value=True;adapter.verify_fenced.return_value=True
            def start(*args):
                record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
                for old,new in (('prepared','isolating'),('isolating','isolated')):
                    record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
                return record['operation']
            def capture(*args):
                record=journal.read(home)
                for old,new in (('isolated','capturing'),('capturing','captured')):
                    journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
                return 'f'*32
            with patch.object(update.backup_installation,'private_directory'),patch.object(update.uterctl,'site_config',return_value={}), \
                 patch.object(update,'preflight',return_value=(self.old,self.new)), \
                 patch.object(update.snapshot,'_executor',return_value='a'*64), \
                 patch.object(update.compose_fence_start,'start',side_effect=start), \
                 patch.object(update.compose_nsfirewall_adapter,'Adapter',return_value=adapter), \
                 patch.object(update.snapshot,'capture_for_mutation',side_effect=capture), \
                 patch.object(update.receipts,'read_receipt',return_value=({'backup_id':'f'*32},'b'*64)), \
                 patch.object(update.snapshot,'recover') as recover:
                record,old,new=update.capture_for_update(home,source,target,'publisher','executor',key,destination)
            self.assertEqual(record['phase'],'captured');self.assertEqual((old,new),(self.old,self.new))
            self.assertEqual(update.read_intent(home,key,record)['receipt_sha256'],'b'*64)
            adapter.close.assert_called_once();recover.assert_not_called()

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_release_uncertainty_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600)
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            update.create_intent(home,b'k'*32,record,*('cdef1'[i]*64 for i in range(5)))
            adapter=Mock()
            def release(*args):
                journal.advance(home,operation=record['operation'],expected='captured',next_phase='snapshot_releasing')
                raise RuntimeError('outcome unknown')
            with patch.object(update,'_verify_binding'), \
                 patch.object(update.compose_nsfirewall_adapter,'Adapter',return_value=adapter), \
                 patch.object(update.snapshot,'release_for_mutation',side_effect=release) as recover:
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_RELEASE_INCOMPLETE$'):
                    update.release_for_update(home,'source','target','publisher','executor',b'k'*32,'backup')
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_RELEASE_STATE_UNVERIFIED$'):
                    update.release_for_update(home,'source','target','publisher','executor',b'k'*32,'backup')
            recover.assert_called_once();adapter.close.assert_called_once()
            self.assertTrue(os.path.lexists(home/journal.UPDATE_INTENT))
            self.assertEqual(journal.read(home)['phase'],'snapshot_releasing')

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_target_start_intent_is_single_use_and_authenticated(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600);key=b'k'*32
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            intent=update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            for old,new in (('captured','snapshot_releasing'),('snapshot_releasing','redis_released')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            value=update.create_target_start(home,key,record,intent)
            self.assertEqual(update.read_target_start(home,key,record,intent),value)
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_START_INTENT_UNCERTAIN$'):
                update.create_target_start(home,key,record,intent)
            path=home/update.TARGET_START;path.write_text('{"start":{},"mac":"forged"}')
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_START_INTENT_UNVERIFIED$'):
                update.read_target_start(home,key,record,intent)

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_uncertain_target_start_retains_journal_and_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600);key=b'k'*32
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            intent=update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            for old,new in (('captured','snapshot_releasing'),('snapshot_releasing','redis_released')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            adapter=Mock();adapter._plan.return_value={};original={'agent':{},'guardrail':{}}
            def uncertain(command,**kwargs):
                self.assertEqual(journal.read(home)['phase'],'target_starting')
                self.assertEqual(update.read_target_start(home,key,record,intent)['operation'],record['operation'])
                self.assertEqual(command[-2:],['agent','guardrail']);self.assertIn('--no-deps',command)
                self.assertNotIn('redis',command);self.assertEqual(kwargs['env']['HOME'],'/nonexistent')
                raise TimeoutError('unknown daemon outcome')
            with patch.object(update,'_verify_binding',return_value=(intent,self.old,self.new)), \
                 patch.object(update.uterctl,'site_config',return_value={'name':'test'}), \
                 patch.object(update.compose_nsfirewall_adapter,'Adapter',return_value=adapter), \
                 patch.object(update.compose_fence_finalize.checkpoint,'read',return_value={}), \
                 patch.object(update.compose_fence_finalize,'_attach_running_redis'), \
                 patch.object(update,'_released_binding',return_value={}), \
                 patch.object(update,'_verify_mutation_backup') as verify_backup, \
                 patch.object(update.compose_fence_start,'read_intent',return_value=original), \
                 patch.object(update.compose_fence_start,'_writers_stopped'), \
                 patch.object(update.compose_fence_resume,'_current_writer_ids'), \
                 patch.object(update.subprocess,'run',side_effect=uncertain) as run:
                verify_backup.side_effect=update.FencedUpdateError('FENCED_UPDATE_BACKUP_UNVERIFIED')
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_BACKUP_UNVERIFIED$'):
                    update.start_target(home,'source','target','publisher','executor',key,'backup')
                run.assert_not_called();self.assertFalse(os.path.lexists(home/update.TARGET_START))
                self.assertEqual(journal.read(home)['phase'],'redis_released');verify_backup.side_effect=None
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_START_INCOMPLETE$'):
                    update.start_target(home,'source','target','publisher','executor',key,'backup')
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_START_STATE_UNVERIFIED$'):
                    update.start_target(home,'source','target','publisher','executor',key,'backup')
            run.assert_called_once();self.assertEqual(adapter.close.call_count,2)
            self.assertTrue(os.path.lexists(home/journal.UPDATE_INTENT));self.assertTrue(os.path.lexists(home/update.TARGET_START))

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_target_result_is_bound_to_operation_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600);key=b'k'*32
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            intent=update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            for old,new in (('captured','snapshot_releasing'),('snapshot_releasing','redis_released')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            update.create_target_start(home,key,record,intent)
            record=journal.advance(home,operation=record['operation'],expected='redis_released',next_phase='target_starting')
            writers={service:{'id':ident*64,'started':'2026-10-30T00:00:00Z','restart_count':0,
                              'image_ref':'registry.example/'+service+'@sha256:'+'1'*64,'image_id':'sha256:'+'2'*64}
                     for service,ident in (('agent','d'),('guardrail','e'))}
            value=update.create_target_result(home,key,record,intent,writers)
            self.assertEqual(update.read_target_result(home,key,record,intent),value)
            path=home/update.TARGET_RESULT;path.write_bytes(path.read_bytes().replace(b'"restart_count":0',b'"restart_count":1',1))
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_RESULT_UNVERIFIED$'):
                update.read_target_result(home,key,record,intent)

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_finalize_persists_target_then_cleans_journal_and_preserves_backup(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);home=root/'home';home.mkdir(mode=0o700);key=b'k'*32
            (home/'operation.lock').write_text(str(os.getpid()));(home/'operation.lock').chmod(0o600)
            source=home/'releases'/'1.0.0';target=home/'releases'/'1.1.0'
            source.mkdir(parents=True);target.mkdir();destination=root/'backup';destination.mkdir()
            (destination/'keep').write_text('unchanged')
            update.uterctl.write(home/'state.json',{'current':self.old,'previous':None,'pending':None,'adopted_installer':True})
            update.uterctl.write(home/'install.json',{'images':self.old['images']})
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            intent=update.create_intent(home,key,record,*('cdef1'[i]*64 for i in range(5)))
            for old,new in (('captured','snapshot_releasing'),('snapshot_releasing','redis_released')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            update.create_target_start(home,key,record,intent)
            record=journal.advance(home,operation=record['operation'],expected='redis_released',next_phase='target_starting')
            writers={service:{'id':ident*64,'started':'2026-10-30T00:00:00Z','restart_count':0,
                              'image_ref':'registry.example/'+service+'@sha256:'+'1'*64,'image_id':'sha256:'+'2'*64}
                     for service,ident in (('agent','d'),('guardrail','e'))}
            update.create_target_result(home,key,record,intent,writers)
            record=journal.advance(home,operation=record['operation'],expected='target_starting',next_phase='target_running')
            for name in (update.compose_fence_recovery_plan.NAME,update.compose_fence_finalize.checkpoint.NAME,
                         update.compose_fence_start.NAME,update.compose_fence_origin.NAME,update.receipts.DESCRIPTOR,
                         update.receipts.RECEIPT,update.receipts.DECISION):
                path=home/name;path.write_text('fixture');path.chmod(0o600)
            adapter=Mock();adapter._plan.return_value={}
            with patch.object(update,'_verify_binding',return_value=(intent,self.old,self.new)), \
                 patch.object(update,'_verify_mutation_backup',return_value={'id':'f'*32}), \
                 patch.object(update,'_verify_running_source',return_value={'images':self.old['images']}), \
                 patch.object(update.snapshot,'_executor',return_value='e'*64), \
                 patch.object(update.compose_nsfirewall_adapter,'Adapter',return_value=adapter), \
                 patch.object(update.compose_fence_finalize.checkpoint,'read',return_value={}), \
                 patch.object(update.compose_fence_finalize,'_attach_running_redis'), \
                 patch.object(update.compose_fence_start,'read_intent') as start_intent, \
                 patch.object(update.uterctl,'site_config',return_value={'name':'test'}), \
                 patch.object(update.compose_fence_start,'_writers',return_value=writers), \
                 patch.object(update.compose_fence_resume,'_healthy'):
                start_intent.side_effect=ValueError('tampered old writer intent')
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_FINALIZE_INCOMPLETE$'):
                    update.finalize_target(home,source,target,'publisher','executor',key,destination)
                self.assertEqual(journal.read(home)['phase'],'target_running')
                self.assertEqual(update.uterctl.read(home/'state.json')['current'],self.old)
                start_intent.side_effect=None
                durable=update._durable_json
                def fail_after_install(directory,name,value):
                    if name=='state.json':raise OSError('injected state fsync failure')
                    return durable(directory,name,value)
                with patch.object(update,'_durable_json',side_effect=fail_after_install):
                    with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_FINALIZE_INCOMPLETE$'):
                        update.finalize_target(home,source,target,'publisher','executor',key,destination)
                self.assertEqual(journal.read(home)['phase'],'update_finalizing')
                self.assertEqual(update.uterctl.read(home/'install.json')['images'],self.new['images'])
                self.assertEqual(update.uterctl.read(home/'state.json')['current'],self.old)
                def fail_after_state(directory,name,value):
                    durable(directory,name,value)
                    if name=='state.json':raise OSError('injected post-replace failure')
                with patch.object(update,'_durable_json',side_effect=fail_after_state):
                    with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_FINALIZE_INCOMPLETE$'):
                        update.finalize_target(home,source,target,'publisher','executor',key,destination)
                self.assertEqual(journal.read(home)['phase'],'update_finalizing')
                self.assertEqual(update.uterctl.read(home/'state.json')['current'],self.new)
                self.assertEqual(update.finalize_target(home,source,target,'publisher','executor',key,destination),self.new)
            self.assertEqual(update.uterctl.read(home/'state.json')['current'],self.new)
            self.assertFalse(journal.blocks_mutation(home));self.assertEqual((destination/'keep').read_text(),'unchanged')
            self.assertEqual(adapter.close.call_count,3)

    @unittest.skipUnless(os.name=='posix','private POSIX state')
    def test_running_source_verification_does_not_assume_stopped_writers(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);source=home/'releases'/'1.0.0';source.mkdir(parents=True)
            cfg={'backend':'compose','context':'default','name':'test','images':self.old['images']}
            for name,value in (('state.json',{'current':self.old}),('install.json',cfg)):
                path=home/name;path.write_text(__import__('json').dumps(value));path.chmod(0o600)
            adapter=Mock();adapter.home=home;adapter._lock=Mock();adapter._json.return_value='unix:///var/run/docker.sock'
            site={'name':'test','context':'default','namespace':'test'}
            with patch.object(update.uterctl,'verify',return_value=self.old),patch.dict(os.environ,{'DOCKER_CONTEXT':'default'},clear=True):
                self.assertEqual(update._verify_running_source(adapter,{'site':'test'},{'image_ref':'r'},source,'key',self.old,self.new,site),cfg)
            adapter._signed.assert_not_called();adapter._config.assert_called_once_with(source)

    @unittest.skipUnless(os.name=='posix','private POSIX journal')
    def test_partial_finalization_with_missing_evidence_refuses_state_or_workload_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);home.chmod(0o700);(home/'operation.lock').write_text(str(os.getpid()))
            (home/'operation.lock').chmod(0o600);key=b'k'*32
            record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
            for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured'),
                            ('captured','snapshot_releasing'),('snapshot_releasing','redis_released'),('redis_released','target_starting'),
                            ('target_starting','target_running'),('target_running','update_finalizing')):
                record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
            with patch.object(update,'_durable_json') as write, \
                 patch.object(update.compose_nsfirewall_adapter,'Adapter') as adapter, \
                 patch.object(update.subprocess,'run') as run:
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_FINALIZE_INCOMPLETE$'):
                    update.finalize_target(home,'source','target','publisher','executor',key,'backup')
            write.assert_not_called();adapter.assert_not_called();run.assert_not_called()
            self.assertEqual(journal.read(home)['phase'],'update_finalizing')


if __name__=='__main__':unittest.main()
