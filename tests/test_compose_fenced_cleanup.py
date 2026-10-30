import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from scripts import compose_fenced_update as update, redis_fence_journal as journal
from tests import test_compose_fence_start as start_fixtures, test_controller as controller_fixtures


@unittest.skipUnless(os.name=='posix','durable POSIX cleanup')
class SealedCleanupTests(unittest.TestCase):
    def setUp(self):
        guard=patch.object(update.backup_snapshot,'_require_fenced_operation_lock')
        guard.start();self.addCleanup(guard.stop)

    def make_fixture(self,root):
        home=root/'home';home.mkdir(mode=0o700);key=b'k'*32
        (home/'operation.lock').write_text(str(os.getpid()));(home/'operation.lock').chmod(0o600)
        source=home/'releases'/'1.0.0';target=home/'releases'/'1.1.0';source.mkdir(parents=True);target.mkdir()
        (source/'checksums.json').write_text('old');(target/'checksums.json').write_text('new')
        dest=root/'backup';dest.mkdir(mode=0o700);(dest/'manifest.json').write_text('backup');(dest/'keep').write_text('data')
        old=controller_fixtures.manifest();new=controller_fixtures.manifest('1.1.0',['1.0.0'])
        site={'backend':'compose','name':'test','namespace':'test','context':'default','smoke_command':['true']}
        state={'current':new,'previous':old,'pending':None,'adopted_installer':True,
               'last_backup':{'id':'f'*32,'path':str(dest.resolve()),'version':old['version']}}
        cfg={'backend':'compose','name':'test','context':'default','images':new['images']}
        for name,value in (('state.json',state),('install.json',cfg)):
            p=home/name;p.write_text(json.dumps(value));p.chmod(0o600)
        record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        for previous,next_phase in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),
                ('capturing','captured'),('captured','snapshot_releasing'),('snapshot_releasing','redis_released'),
                ('redis_released','target_starting'),('target_starting','target_running'),('target_running','update_finalizing')):
            record=journal.advance(home,operation=record['operation'],expected=previous,next_phase=next_phase)
        fixture=start_fixtures.ComposeFenceStartTests(methodName='test_writer_exit_requires_same_instance_and_unforced_success')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        plan=copy.deepcopy(fixture.plan);plan.update(operation=record['operation'],image_ref=old['images']['redis'])
        saved={'schema':1,**{n:record[n] for n in ('operation','site','resource','plan_sha256')},
               'boot_id':'11111111-1111-1111-1111-111111111111','pid':1,'pid_start':1,'net_dev':1,'net_ino':1,'firewall_sha256':'c'*64}
        intent={'schema':1,**{n:record[n] for n in ('operation','site','resource','plan_sha256')},
                'source_sha256':hashlib.sha256((source/'checksums.json').read_bytes()).hexdigest(),
                'target_sha256':hashlib.sha256((target/'checksums.json').read_bytes()).hexdigest(),
                'executor_sha256':'e'*64,'receipt_sha256':'f'*64,
                'destination_sha256':hashlib.sha256(str(dest.resolve()).encode()).hexdigest()}
        writers=copy.deepcopy(fixture.writers)
        for service in writers:writers[service]['image_ref']=new['images'][service]
        result=update._target_value(record,intent,writers)
        for name in update._evidence_names():
            path=home/name;path.write_text('fixture-'+name);path.chmod(0o600)
        with update.compose_fence_finalize._pin_files(home,list(update._evidence_names())) as (directory,files):
            update.seal_cleanup(home,key,record,plan,saved,intent,result,old,new,site,{'id':'f'*32},dest,directory,files)
        return home,key,source,target,dest,old,new,site,writers

    def mocked_runtime(self,fixture):
        home,key,source,target,dest,old,new,site,writers=fixture
        adapter=Mock();adapter.home=home;adapter._lock=Mock();adapter._json.return_value='unix:///var/run/docker.sock'
        stack=__import__('contextlib').ExitStack()
        stack.enter_context(patch.object(update.uterctl,'verify',side_effect=lambda path,publisher:old if Path(path)==source else new))
        stack.enter_context(patch.object(update.uterctl,'site_config',return_value=site))
        stack.enter_context(patch.object(update.snapshot,'_executor',return_value='e'*64))
        stack.enter_context(patch.object(update,'preflight',return_value=(old,new)))
        stack.enter_context(patch.object(update.backup_store,'verify_set',return_value={'id':'f'*32}))
        stack.enter_context(patch.object(update.compose_nsfirewall_adapter,'Adapter',return_value=adapter))
        stack.enter_context(patch.object(update.compose_fence_finalize,'_attach_running_redis'))
        stack.enter_context(patch.object(update.compose_fence_start,'_writers',return_value=writers))
        stack.enter_context(patch.object(update.compose_fence_resume,'_healthy'))
        stack.enter_context(patch.dict(os.environ,{'DOCKER_CONTEXT':'default'},clear=True))
        return stack

    def test_recovery_after_each_evidence_and_journal_unlink(self):
        for boundary in update._evidence_names()+(journal.NAME,):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory() as temp:
                fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
                real_unlink=os.unlink
                def crash(name,*args,**kwargs):
                    result=real_unlink(name,*args,**kwargs)
                    if name==boundary:raise OSError('injected unknown result')
                    return result
                with self.mocked_runtime(fixture):
                    with patch.object(update.os,'unlink',side_effect=crash):
                        with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                            update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
                    self.assertTrue(os.path.lexists(home/journal.CLEANUP_INTENT))
                    self.assertTrue(journal.blocks_mutation(home))
                    self.assertEqual(update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest),new)
                self.assertFalse(journal.blocks_mutation(home));self.assertEqual((dest/'keep').read_text(),'data')

    def test_tampered_remaining_evidence_or_sealed_proof_never_cleans(self):
        for tamper in ('evidence','manifest','state'):
            with self.subTest(tamper=tamper),tempfile.TemporaryDirectory() as temp:
                fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
                path={'evidence':home/update._evidence_names()[0],'manifest':home/journal.CLEANUP_INTENT,'state':home/'state.json'}[tamper]
                path.write_bytes(path.read_bytes()+b'altered')
                with self.mocked_runtime(fixture):
                    with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                        update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
                self.assertTrue(journal.blocks_mutation(home));self.assertTrue(os.path.lexists(home/journal.NAME))

    def test_changed_signed_binding_backup_or_live_identity_blocks_cleanup(self):
        for tamper in ('source','target','backup','writer','redis'):
            with self.subTest(tamper=tamper),tempfile.TemporaryDirectory() as temp:
                fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
                if tamper in ('source','target','backup'):
                    path={'source':source/'checksums.json','target':target/'checksums.json','backup':dest/'manifest.json'}[tamper]
                    path.write_bytes(path.read_bytes()+b'altered')
                with self.mocked_runtime(fixture):
                    with __import__('contextlib').ExitStack() as stack:
                        if tamper=='writer':
                            changed=copy.deepcopy(writers);changed['agent']['id']='8'*64
                            stack.enter_context(patch.object(update.compose_fence_start,'_writers',return_value=changed))
                        if tamper=='redis':
                            stack.enter_context(patch.object(update.compose_fence_finalize,'_attach_running_redis',side_effect=ValueError('changed')))
                        with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                            update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
                self.assertTrue(journal.blocks_mutation(home));self.assertTrue(os.path.lexists(home/journal.NAME))

    def test_failure_after_last_manifest_unlink_cannot_promise_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
            real_unlink=os.unlink
            def crash(name,*args,**kwargs):
                result=real_unlink(name,*args,**kwargs)
                if name==journal.CLEANUP_INTENT:raise OSError('injected failure after unlink')
                return result
            with self.mocked_runtime(fixture),patch.object(update.os,'unlink',side_effect=crash):
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                    update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
            self.assertFalse(journal.blocks_mutation(home))
            self.assertEqual(json.loads((home/'state.json').read_text())['current'],new)
            self.assertEqual((dest/'keep').read_text(),'data')

    def test_fsync_failure_after_journal_unlink_leaves_resumable_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
            real_fsync=os.fsync
            def fail(fd):
                if not os.path.lexists(home/journal.NAME) and os.path.lexists(home/journal.CLEANUP_INTENT):
                    raise OSError('injected post-journal fsync failure')
                return real_fsync(fd)
            with self.mocked_runtime(fixture):
                with patch.object(update.os,'fsync',side_effect=fail):
                    with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                        update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
                self.assertTrue(os.path.lexists(home/journal.CLEANUP_INTENT))
                self.assertTrue(journal.blocks_mutation(home))
                self.assertEqual(update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest),new)
            self.assertFalse(journal.blocks_mutation(home));self.assertEqual((dest/'keep').read_text(),'data')

    def test_manifest_must_fsync_before_any_evidence_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
            with self.mocked_runtime(fixture),patch.object(update.os,'fsync',side_effect=OSError('not durable')):
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                    update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
            self.assertTrue(all(os.path.lexists(home/name) for name in update._evidence_names()))
            self.assertTrue(os.path.lexists(home/journal.NAME));self.assertTrue(os.path.lexists(home/journal.CLEANUP_INTENT))

    def test_authenticated_seal_authorizes_only_lock_reclaim_even_without_journal(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
            update.verify_reclaimable_finish(home,key)
            (home/journal.NAME).unlink();update.verify_reclaimable_finish(home,key)
            path=home/journal.CLEANUP_INTENT;path.write_bytes(path.read_bytes()+b'corrupt')
            with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_UPDATE_RECLAIM_UNVERIFIED$'):
                update.verify_reclaimable_finish(home,key)

    def test_fsync_failure_after_last_manifest_unlink_cannot_promise_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture=self.make_fixture(Path(temp));home,key,source,target,dest,old,new,site,writers=fixture
            real_fsync=os.fsync
            def fail(fd):
                if not os.path.lexists(home/journal.CLEANUP_INTENT) and not os.path.lexists(home/journal.NAME):
                    raise OSError('injected final directory fsync failure')
                return real_fsync(fd)
            with self.mocked_runtime(fixture),patch.object(update.os,'fsync',side_effect=fail):
                with self.assertRaisesRegex(update.FencedUpdateError,'^FENCED_CLEANUP_INCOMPLETE$'):
                    update.finish_sealed_cleanup(home,target,'publisher','executor',key,dest)
            self.assertFalse(journal.blocks_mutation(home))
            self.assertEqual(json.loads((home/'state.json').read_text())['current'],new)
            self.assertEqual((dest/'keep').read_text(),'data')
