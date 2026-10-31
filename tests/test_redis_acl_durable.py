import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import redis_acl_durable as subject


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,
                     'requires root Linux ownership and no-follow support')
class DurableACLTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.directory=self.root/'acl';self.directory.mkdir()
        os.chown(self.directory,0,1000);self.directory.chmod(0o710)
        self.writer='a'*64;self.admin='b'*64;self.admin_user='uter-maint-ci'
        self.before=subject.render(admin_user=self.admin_user,writer_hash=self.writer,admin_hash=self.admin,writer_on=True)
        self.after=subject.render(admin_user=self.admin_user,writer_hash=self.writer,admin_hash=self.admin,writer_on=False)
        self.file=self.directory/subject.NAME;self.file.write_bytes(self.before)
        os.chown(self.file,999,1000);self.file.chmod(0o400)
        self.intents=[];self.receipts=[];self.guard=True
        self.profile=patch.object(subject.redis_acl_staged,'verify_profile',return_value={'version':'fixture'})
        self.profile.start();self.addCleanup(self.profile.stop)
        self.prepare=subject.DurablePrepare(bundle='/bundle',publisher='/pub',directory=self.directory,
            admin_user=self.admin_user,writer_hash=self.writer,admin_hash=self.admin,
            lock_guard=lambda:self.guard,record_intent=self.intent,record_receipt=self.receipt)

    def intent(self,stage):self.intents.append(stage);return True
    def receipt(self,stage,digest):self.receipts.append((stage,digest));return True

    def test_fsync_atomic_off_and_no_production_authority(self):
        result=self.prepare.prepare_off()
        self.assertEqual(self.file.read_bytes(),self.after)
        self.assertEqual((self.file.stat().st_uid,self.file.stat().st_gid,self.file.stat().st_mode&0o777),(999,1000,0o400))
        self.assertTrue(result['disk_off_prepared'])
        self.assertFalse(result['redis_state_verified']);self.assertFalse(result['continuous_fence_verified'])
        self.assertFalse(result['safe_to_update']);self.assertEqual(self.intents,['persist-writer-off'])
        self.assertEqual(self.receipts,[('writer-off-file-durable',result['version_sha256'])])
        self.assertTrue(self.prepare.verify_off())
        with self.assertRaises(subject.DurableError):self.prepare.prepare_off()

    def test_replaced_file_is_detected_after_preparation(self):
        self.prepare.prepare_off()
        replacement=self.directory/'replacement';replacement.write_bytes(self.after)
        os.chown(replacement,999,1000);replacement.chmod(0o400);os.replace(replacement,self.file)
        with self.assertRaisesRegex(subject.DurableError,'REDIS_DURABLE_FILE_UNVERIFIED'):
            self.prepare.verify_off()

    def test_directory_replacement_during_receipt_is_uncertain(self):
        def replace_directory(stage,digest):
            self.directory.rename(self.root/'old-acl')
            self.directory.mkdir();os.chown(self.directory,0,1000);self.directory.chmod(0o710)
            return True
        self.prepare.receipt=replace_directory
        with self.assertRaisesRegex(subject.DurableError,'REDIS_DURABLE_PREPARE_UNCERTAIN'):
            self.prepare.prepare_off()
        self.assertIsNone(self.prepare.prepared)

    def test_failure_before_rename_leaves_original_and_blocks_retry(self):
        with patch.object(subject.os,'replace',side_effect=OSError('secret-canary')):
            with self.assertRaises(subject.DurableError) as error:self.prepare.prepare_off()
        self.assertNotIn('secret-canary',str(error.exception));self.assertEqual(self.file.read_bytes(),self.before)
        self.assertEqual(self.intents,['persist-writer-off']);self.assertFalse(self.receipts)
        with self.assertRaises(subject.DurableError):self.prepare.prepare_off()

    def test_lost_response_after_rename_blocks_retry_without_receipt(self):
        replace=subject.os.replace
        def lost(*args,**kwargs):replace(*args,**kwargs);raise OSError('unknown')
        with patch.object(subject.os,'replace',side_effect=lost):
            with self.assertRaises(subject.DurableError):self.prepare.prepare_off()
        self.assertEqual(self.file.read_bytes(),self.after);self.assertFalse(self.receipts)
        with self.assertRaises(subject.DurableError):self.prepare.prepare_off()

    def test_bad_file_owner_hardlink_or_symlink_rejected_before_intent(self):
        self.file.chmod(0o444)
        with self.assertRaises(subject.DurableError):self.prepare.prepare_off()
        self.assertFalse(self.intents)
        self.file.chmod(0o400);os.link(self.file,self.directory/'extra')
        with self.assertRaises(subject.DurableError):
            subject.DurablePrepare(bundle='/bundle',publisher='/pub',directory=self.directory,
              admin_user=self.admin_user,writer_hash=self.writer,admin_hash=self.admin,
              lock_guard=lambda:True,record_intent=self.intent,record_receipt=self.receipt).prepare_off()
        self.assertFalse(self.intents)

    def test_regular_and_dangling_symlink_are_rejected_before_intent(self):
        self.file.unlink();other=self.directory/'other';other.write_bytes(self.before)
        os.chown(other,999,1000);other.chmod(0o400)
        for target in (other,self.directory/'missing'):
            self.file.symlink_to(target)
            item=subject.DurablePrepare(bundle='/bundle',publisher='/pub',directory=self.directory,
              admin_user=self.admin_user,writer_hash=self.writer,admin_hash=self.admin,
              lock_guard=lambda:True,record_intent=self.intent,record_receipt=self.receipt)
            with self.subTest(target=target),self.assertRaises(subject.DurableError):item.prepare_off()
            self.file.unlink()
        self.assertFalse(self.intents)

    def test_lost_lock_during_intent_does_not_replace_file(self):
        def lose(stage):self.guard=False;return True
        self.prepare.intent=lose
        with self.assertRaises(subject.DurableError):self.prepare.prepare_off()
        self.assertEqual(self.file.read_bytes(),self.before);self.assertFalse(self.receipts)

    def test_fsync_failure_after_rename_is_uncertain_without_receipt(self):
        fsync=subject.os.fsync;calls=[]
        def fail_second(fd):
            calls.append(fd)
            if len(calls)==2:raise OSError('fsync failed')
            return fsync(fd)
        with patch.object(subject.os,'fsync',side_effect=fail_second):
            with self.assertRaises(subject.DurableError):self.prepare.prepare_off()
        self.assertEqual(self.file.read_bytes(),self.after);self.assertFalse(self.receipts)

    def test_staged_admission_persists_off_before_volatile_acl_change(self):
        calls=[]
        def execute(*args):
            calls.append(args)
            if args==('CLIENT','LIST'):return 'fixture'
            if args==('ACL','SETUSER','uter-writer','off'):
                self.assertEqual(self.file.read_bytes(),self.after)
                self.assertTrue(self.prepare.verify_off())
                return 'OK'
            raise AssertionError(args)
        session=subject.redis_acl_staged.StagedAdmission(execute,bundle='/bundle',publisher='/pub',
            admin_user=self.admin_user,run_id='a'*40,client_id='7',record_intent=self.intent,
            record_receipt=lambda stage:True,identity_guard=lambda:True,durable_prepare=self.prepare)
        with patch.object(session,'_observe'), \
             patch.object(subject.redis_acl_staged,'_clients',return_value=frozenset({'8'})):
            result=session.disable_new_auth()
        self.assertTrue(result['host_acl_file_verified'])
        self.assertFalse(result['redis_acl_source_verified']);self.assertFalse(result['safe_to_update'])
        self.assertLess(self.intents.index('disable-writer-auth'),self.intents.index('persist-writer-off'))
        self.assertIn(('ACL','SETUSER','uter-writer','off'),calls)

    def test_receipt_written_then_guard_lost_prevents_volatile_off(self):
        calls=[]
        def execute(*args):
            calls.append(args)
            if args==('CLIENT','LIST'):return 'fixture'
            raise AssertionError(args)
        def lose_after_receipt(stage,digest):
            self.receipts.append((stage,digest));self.guard=False;return True
        self.prepare.receipt=lose_after_receipt
        session=subject.redis_acl_staged.StagedAdmission(execute,bundle='/bundle',publisher='/pub',
            admin_user=self.admin_user,run_id='a'*40,client_id='7',record_intent=self.intent,
            record_receipt=lambda stage:True,identity_guard=lambda:self.guard,durable_prepare=self.prepare)
        with patch.object(session,'_observe'),patch.object(subject.redis_acl_staged,'_clients',return_value=frozenset({'8'})):
            with self.assertRaises(subject.redis_acl_staged.StagedError):session.disable_new_auth()
            with self.assertRaises(subject.redis_acl_staged.StagedError):session.disable_new_auth()
        self.assertEqual(self.file.read_bytes(),self.after)
        self.assertEqual(len(self.receipts),1);self.assertIsNone(self.prepare.prepared)
        self.assertNotIn(('ACL','SETUSER','uter-writer','off'),calls)
