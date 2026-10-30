from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_backup_coordinator as coordinator


@unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
class BackupCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.home=self.root/'home';self.home.mkdir(mode=0o700);self.key_path=self.root/'key';self.key_path.write_bytes(b'k'*32)
        self.key_path.chmod(0o600);self.operation='a'*32
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2},home=self.home,_key_path=self.key_path,
            _profile_digest='d'*64,site='uter-test',manifest={'version':'0.1.6'},_scope=lambda:None,
            _query=lambda args:{'kind':'Pod'})
        self.dest=self.root/'backup';self.site={'backend':'helm','name':'uter-test','namespace':'uter-test'}
        self.plan={'operation':self.operation,'reader_name':'uter-test-audit-reader-'+'a'*12}
        self.created={'uid':'33333333-3333-3333-3333-333333333333'}
        self.manifest={'id':'b'*32}
        self.finish_count=0
        outer=self
        class Writer:
            def __init__(inner,*args):Path(args[0]).mkdir(mode=0o700)
            def finish(inner):outer.finish_count+=1;return outer.manifest
        self.writer=Writer

    def run_case(self,*,fail=None,verify=False):
        original_read=coordinator.storage._read
        def fake_read(home,name,key):
            if name==coordinator.audit.CREATED:return self.created
            if name=='kubernetes-audit-reader-plan.json':return self.plan
            return original_read(home,name,key)
        with ExitStack() as stack:
            stack.enter_context(patch.object(coordinator.backup_installation,'safe_file',side_effect=lambda p,**kw:
                b'k'*32 if Path(p)==self.key_path else b'finished-manifest'))
            stack.enter_context(patch.object(coordinator.uterctl,'site_config',return_value=self.site))
            stack.enter_context(patch.object(coordinator.storage,'_read',side_effect=fake_read))
            stack.enter_context(patch.object(coordinator.audit,'pod_spec'))
            stack.enter_context(patch.object(coordinator.writer_guard,'verify'))
            stack.enter_context(patch.object(coordinator.runtime_pin,'verify',return_value='e'*64))
            stack.enter_context(patch.object(coordinator.runtime_pin,'verify_archive'))
            stack.enter_context(patch.object(coordinator.config,'reverify'))
            stack.enter_context(patch.object(coordinator.config,'capture'))
            stack.enter_context(patch.object(coordinator.redis,'assert_loopback'))
            stack.enter_context(patch.object(coordinator.redis,'capture_component'))
            stack.enter_context(patch.object(coordinator.redis,'verify_component'))
            stack.enter_context(patch.object(coordinator.backup_store,'BackupWriter',self.writer))
            stack.enter_context(patch.object(coordinator.backup_store,'verify_set',return_value=self.manifest))
            stack.enter_context(patch.object(coordinator.backup_snapshot,'archive_runtime'))
            stack.enter_context(patch.object(coordinator.backup_snapshot,'verify_encrypted_tar'))
            stack.enter_context(patch.object(coordinator.audit,'create'))
            stack.enter_context(patch.object(coordinator.audit,'verify_pod',return_value={'ready':True}))
            stack.enter_context(patch.object(coordinator.audit,'capture_audit',side_effect=fail))
            stack.enter_context(patch.object(coordinator.audit,'delete'))
            stack.enter_context(patch.object(coordinator.audit,'observe_deletion',return_value={'reader_old_uid_gone':True}))
            result=coordinator.capture(self.session,self.operation,'pod','uid',self.dest,timeout=1)
            if verify:
                self.assertEqual(coordinator.verify_receipt(self.session,self.operation,'pod','uid',self.dest),
                    {'backup_receipt_verified':True,'audit_integrity':'structure_only','safe_to_update':False})
                with self.assertRaises(coordinator.BackupCoordinatorError):
                    coordinator.verify_receipt(self.session,'f'*32,'pod','uid',self.dest)
                self.session._profile_digest='f'*64
                with self.assertRaises(coordinator.BackupCoordinatorError):
                    coordinator.verify_receipt(self.session,self.operation,'pod','uid',self.dest)
                self.session._profile_digest='d'*64
                other=self.root/'other';other.mkdir(mode=0o700)
                with self.assertRaises(coordinator.BackupCoordinatorError):
                    coordinator.verify_receipt(self.session,self.operation,'pod','uid',other)
            return result

    def test_receipt_is_written_only_after_all_components(self):
        self.assertEqual(self.run_case(verify=True),{'backup_set_verified':True,'backup_id':'b'*32,'safe_to_update':False})
        self.assertEqual(self.finish_count,1)
        self.assertTrue((self.home/coordinator.ATTEMPT).exists());self.assertTrue((self.home/coordinator.RECEIPT).exists())

    def test_component_failure_keeps_intent_but_no_manifest_or_receipt(self):
        with self.assertRaises(coordinator.BackupCoordinatorError):self.run_case(fail=ValueError())
        self.assertEqual(self.finish_count,0)
        self.assertTrue((self.home/coordinator.ATTEMPT).exists());self.assertFalse((self.home/coordinator.RECEIPT).exists())
