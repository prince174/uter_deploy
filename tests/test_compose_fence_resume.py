import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from scripts import (compose_fence_origin as origin, compose_fence_resume as resume, compose_fence_start as start, redis_fence_journal as journal,
                     snapshot_only_receipts as receipts)


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'requires POSIX private files')
class ComposeFenceResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.bundle=self.home/'bundle';self.bundle.mkdir()
        (self.bundle/'checksums.json').write_text('{}')
        self.key=b'k'*32
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','pre_capture_aborting')):
            self.record=journal.advance(self.home,operation=self.record['operation'],expected=old,next_phase=new)
        origin.ensure(self.home,self.key,self.record,'pre_capture')
        self.record=journal.advance(self.home,operation=self.record['operation'],expected='pre_capture_aborting',next_phase='redis_released')
        self.writers={name:{'id':identifier*64,'started':'2026-10-30T00:00:00Z','restart_count':0,
                            'image_ref':'ghcr.io/owner/'+name+'@sha256:'+'c'*64,'image_id':'sha256:'+'d'*64}
                      for name,identifier in (('guardrail','e'),('agent','f'))}
        self.original={'schema':1,'operation':self.record['operation'],'site':'test','redis':'a'*64,
                       'guardrail':self.writers['guardrail'],'agent':self.writers['agent'],
                       'plan_sha256':'b'*64,'bundle_sha256':hashlib.sha256(b'{}').hexdigest()}
        start._write_intent(self.home,self.original,self.key)
        self.adapter=Mock();self.adapter.home=self.home;self.adapter.bundle=self.bundle
        self.adapter.backup_key=self.key;self.adapter.installed=False
        self.adapter._plan.return_value={'site':'test'};self.adapter._attach_recovery.return_value=True

    def test_no_start_until_intent_and_journal_are_durable(self):
        def command(*args):
            current=journal.read(self.home)
            self.assertEqual(current['phase'],'writers_resuming')
            intent=resume.read_intent(self.home,self.key,current)
            self.assertEqual(intent['operation'],self.record['operation'])
            self.assertEqual(intent['start_intent_sha256'],hashlib.sha256(start._canonical(self.original)).hexdigest())
        self.adapter._run.side_effect=command
        with patch.object(start,'_writers_stopped') as stopped,patch.object(resume,'_current_writer_ids') as ids, \
             patch.object(resume,'_backup_evidence',return_value='0'*64), \
             patch.object(resume.snapshot,'_executor',return_value='8'*64),patch.object(resume,'_healthy') as health:
            resume.resume(self.adapter,self.record,'executor-key',None)
        self.assertEqual([c.args for c in self.adapter._run.call_args_list],
                         [('start',self.writers['agent']['id']),('start',self.writers['guardrail']['id'])])
        stopped.assert_called_once();ids.assert_called_once();self.assertEqual(health.call_count,4)
        self.assertEqual(journal.read(self.home)['phase'],'writers_resumed')
        self.assertTrue((self.home/journal.NAME).exists());self.assertTrue((self.home/resume.NAME).exists())

    def test_failures_never_retry_start_or_restore_older_backup(self):
        for step in ('intent','transition','first_start','first_health','second_start','second_health','redis_check'):
            with self.subTest(step=step),tempfile.TemporaryDirectory() as folder:
                home=Path(folder);record=journal.create(home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
                for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','pre_capture_aborting')):
                    record=journal.advance(home,operation=record['operation'],expected=old,next_phase=new)
                origin.ensure(home,self.key,record,'pre_capture')
                record=journal.advance(home,operation=record['operation'],expected='pre_capture_aborting',next_phase='redis_released')
                original=dict(self.original,operation=record['operation']);start._write_intent(home,original,self.key)
                adapter=Mock();adapter.home=home;adapter.bundle=self.bundle;adapter.backup_key=self.key;adapter.installed=False
                adapter._plan.return_value={'site':'test'};adapter._attach_recovery.return_value=True
                if step=='first_start':adapter._run.side_effect=RuntimeError('uncertain')
                if step=='second_start':adapter._run.side_effect=[None,RuntimeError('uncertain')]
                if step=='redis_check':adapter._redis_config.side_effect=RuntimeError('uncertain')
                health_calls=[0]
                def healthy(*args):
                    health_calls[0]+=1
                    if (step=='first_health' and health_calls[0]==1) or (step=='second_health' and health_calls[0]==2):
                        raise RuntimeError('uncertain')
                real_write=resume._write_intent;real_advance=journal.advance
                def write(*args):
                    if step=='intent':raise OSError('uncertain')
                    return real_write(*args)
                def advance(*args,**kwargs):
                    if step=='transition':raise OSError('uncertain')
                    return real_advance(*args,**kwargs)
                with patch.object(start,'_writers_stopped'),patch.object(resume,'_current_writer_ids'), \
                     patch.object(resume,'_backup_evidence',return_value='0'*64), \
                     patch.object(resume.snapshot,'_executor',return_value='8'*64), \
                     patch.object(resume,'_write_intent',side_effect=write),patch.object(journal,'advance',side_effect=advance), \
                     patch.object(resume,'_healthy',side_effect=healthy):
                    with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_INCOMPLETE$'):
                        resume.resume(adapter,record,'executor-key',None)
                expected=0 if step in ('intent','transition') else 1 if step in ('first_start','first_health') else 2
                self.assertEqual(adapter._run.call_count,expected)
                self.assertEqual(journal.read(home)['phase'],'redis_released' if step in ('intent','transition') else 'writers_resuming')
                self.assertTrue((home/journal.NAME).exists())
                self.assertFalse(any(call.args and call.args[0] in ('stop','rm','restart') for call in adapter._run.call_args_list))

    def test_tampered_or_foreign_resume_intent_is_rejected(self):
        intent={'schema':1,'operation':self.record['operation'],'plan_sha256':self.record['plan_sha256'],
                'start_intent_sha256':'1'*64,'bundle_sha256':'2'*64,'executor_sha256':'3'*64,'backup_receipt_sha256':'0'*64}
        resume._write_intent(self.home,self.key,intent)
        self.assertEqual(resume.read_intent(self.home,self.key,self.record),intent)
        for key,record in ((b'x'*32,self.record),(self.key,dict(self.record,operation='0'*32))):
            with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_INTENT_UNVERIFIED$'):
                resume.read_intent(self.home,key,record)
        path=self.home/resume.NAME;path.write_text(path.read_text().replace('"schema":1','"schema":2'))
        with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_INTENT_UNVERIFIED$'):
            resume.read_intent(self.home,self.key,self.record)

    def test_wrong_or_unhealthy_instance_is_never_accepted(self):
        writer=self.writers['agent']
        good={'id':writer['id'],'running':True,'health':'healthy','restart_count':0,
              'project':'test','service':'agent','image_ref':writer['image_ref'],'image_id':writer['image_id']}
        self.adapter._json.return_value=good;resume._healthy(self.adapter,writer,'agent','test',timeout=1)
        for change in ({'id':'0'*64},{'running':False},{'health':'unhealthy'},{'restart_count':1},
                       {'project':'other'},{'service':'other'},{'image_id':'sha256:'+'0'*64}):
            with self.subTest(change=change):
                self.adapter._json.return_value=dict(good,**change)
                with self.assertRaises(resume.ResumeError):resume._healthy(self.adapter,writer,'agent','test',timeout=1)

    def test_mutation_decision_never_authorizes_resume(self):
        desc={'schema':1,'operation':self.record['operation'],'backend':'compose','site':'test','resource':'a'*64,
              'release_version':'1.0.0','bundle_sha256':'1'*64,'fence_checkpoint_sha256':'2'*64,
              'identity_sha256':'b'*64,'backup_id':'3'*32,'backup_location_sha256':'4'*64,'executor_sha256':'5'*64}
        digest=receipts.write_descriptor(self.home,self.key,desc)
        receipt={'schema':1,'operation':self.record['operation'],'descriptor_sha256':digest,
                 'backup_id':'3'*32,'manifest_sha256':'6'*64}
        receipts.write_receipt(self.home,self.key,receipt);receipts.write_decision(self.home,self.key,'mutation')
        binding={'current':{'version':'1.0.0'},'bundle':'1'*64,'checkpoint':'2'*64,'destination':'4'*64,
                 'executor':'5'*64,'site':{'backend':'compose','name':'test','namespace':'test'}}
        with patch.object(resume.snapshot,'_bound',return_value=binding), \
             patch.object(resume.backup_store,'verify_set') as verify:
            with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_BACKUP_UNVERIFIED$'):
                resume._backup_evidence(self.adapter,self.record,'executor-key',self.home/'backup',
                                        {'origin':'snapshot','receipt_sha256':receipts.read_receipt(self.home,self.key)[1]})
        verify.assert_not_called()

    def test_incomplete_snapshot_evidence_always_refuses_resume(self):
        (self.home/receipts.DESCRIPTOR).write_text('incomplete')
        with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_BACKUP_UNVERIFIED$'):
            resume._backup_evidence(self.adapter,self.record,'executor-key',self.home/'backup',
                                    {'origin':'snapshot','receipt_sha256':'1'*64})

    def test_missing_origin_never_proves_pre_capture(self):
        (self.home/origin.NAME).unlink()
        with patch.object(start,'_writers_stopped'),patch.object(resume,'_current_writer_ids'), \
             patch.object(resume.snapshot,'_executor',return_value='8'*64):
            with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_INCOMPLETE$'):
                resume.resume(self.adapter,self.record,'executor-key',None)
        self.adapter._run.assert_not_called()
        self.assertFalse((self.home/resume.NAME).exists())
        self.assertEqual(journal.read(self.home)['phase'],'redis_released')

    def test_snapshot_origin_with_all_receipts_missing_never_falls_back_to_pre_capture(self):
        with self.assertRaisesRegex(resume.ResumeError,'^FENCE_RESUME_BACKUP_UNVERIFIED$'):
            resume._backup_evidence(self.adapter,self.record,'executor-key',None,
                                    {'origin':'snapshot','receipt_sha256':'1'*64})
