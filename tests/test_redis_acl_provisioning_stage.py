import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import backup_crypto, redis_acl_credential_capsule as capsule, redis_acl_provisioning_stage as stage


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root-only secure filesystem profile')
class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700);self.key=b'k'*32
        mock=patch.object(capsule.redis_acl_staged,'verify_profile',return_value={'version':'fixture'})
        mock.start();self.addCleanup(mock.stop)
        capsule.create('/bundle','/publisher',self.root,self.key,'site-1','compose')

    def prepare(self):return stage.prepare('/bundle','/publisher',self.root,self.key,'site-1')

    def test_bound_receipt_permissions_and_no_workload_activation(self):
        result=self.prepare()
        for flag in ('workloads_configured','safe_to_install','safe_to_backup','safe_to_update'):
            self.assertFalse(result[flag])
        draft=self.root/stage.STAGE;acl=draft/'acl';credentials=capsule.read('/bundle','/publisher',self.root,self.key,'site-1','compose')
        self.assertEqual((draft.stat().st_uid,draft.stat().st_gid,draft.stat().st_mode&0o777),(0,0,0o700))
        self.assertEqual((acl.stat().st_uid,acl.stat().st_gid,acl.stat().st_mode&0o777),(0,1000,0o710))
        self.assertEqual(((acl/'users.acl').stat().st_uid,(acl/'users.acl').stat().st_gid,(acl/'users.acl').stat().st_mode&0o777),(999,1000,0o400))
        for filename,key in (('writer-password','writer'),('admin-password','admin')):
            self.assertEqual((draft/filename).read_text(),credentials[key])
            self.assertEqual((draft/filename).stat().st_mode&0o777,0o600)
        document=json.loads((draft/'receipt.json').read_text());record=document['record']
        key=backup_crypto.derive_key(self.key,b'redis-acl-offline-stage')
        backup_crypto.verify_manifest(record,document['hmac'],key)
        self.assertEqual(record['binding']['capsule_sha256'],hashlib.sha256((self.root/capsule.NAME).read_bytes()).hexdigest())
        self.assertEqual(record['acl_sha256'],hashlib.sha256(credentials['acl'].encode()).hexdigest())
        self.assertNotIn(credentials['writer'],json.dumps(document));self.assertNotIn(credentials['admin'],json.dumps(document))
        with self.assertRaises(stage.StageError):self.prepare()

    def test_tampered_capsule_or_extra_file_rejected_before_mkdir(self):
        path=self.root/capsule.NAME;original=path.read_bytes();path.write_bytes(original[:-1]+bytes([original[-1]^1]))
        with self.assertRaises(stage.StageError):self.prepare()
        self.assertFalse((self.root/stage.STAGE).exists())
        path.write_bytes(original);(self.root/'unexpected').write_text('x')
        with self.assertRaises(stage.StageError):self.prepare()
        self.assertFalse((self.root/stage.STAGE).exists())

    def test_interrupted_staging_is_never_replayed(self):
        real_write=stage._write
        def fail_at_admin(directory,name,data,uid,gid,mode):
            if name=='admin-password':raise OSError('sensitive-canary')
            return real_write(directory,name,data,uid,gid,mode)
        with patch.object(stage,'_write',side_effect=fail_at_admin):
            with self.assertRaises(stage.StageError) as exc:self.prepare()
        self.assertNotIn('sensitive-canary',str(exc.exception))
        draft=self.root/stage.STAGE
        self.assertTrue((draft/'intent.json').exists());self.assertFalse((draft/'receipt.json').exists())
        with self.assertRaises(stage.StageError):self.prepare()

    def test_secret_replacement_before_receipt_is_uncertain(self):
        real_write=stage._write
        def tamper_after_receipt(directory,name,data,uid,gid,mode):
            real_write(directory,name,data,uid,gid,mode)
            if name=='receipt.json':(self.root/stage.STAGE/'writer-password').write_text('tampered')
        with patch.object(stage,'_write',side_effect=tamper_after_receipt):
            with self.assertRaises(stage.StageError):self.prepare()
        self.assertTrue((self.root/stage.STAGE/'receipt.json').exists())
        with self.assertRaises(stage.StageError):self.prepare()

    def test_untrusted_profile_or_bad_key_fails_before_stage(self):
        with patch.object(stage.redis_acl_staged,'verify_profile',side_effect=ValueError):
            with self.assertRaises(stage.StageError):self.prepare()
        with self.assertRaises(stage.StageError):stage.prepare('/bundle','/publisher',self.root,b'x'*32,'site-1')
        self.assertFalse((self.root/stage.STAGE).exists())

    def test_lost_response_after_receipt_never_reports_success(self):
        original=stage._write
        def lost_after_receipt(directory,name,data,uid,gid,mode):
            original(directory,name,data,uid,gid,mode)
            if name=='receipt.json':raise OSError('unknown outcome')
        with patch.object(stage,'_write',side_effect=lost_after_receipt):
            with self.assertRaises(stage.StageError):self.prepare()
        self.assertTrue((self.root/stage.STAGE/'receipt.json').exists())
        with self.assertRaises(stage.StageError):self.prepare()

    def test_fsync_failures_at_directory_boundaries_are_uncertain(self):
        real_fsync=os.fsync
        for failure in (1,3,7,10,11):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);directory.chmod(0o700)
                capsule.create('/bundle','/publisher',directory,self.key,'site-1','compose')
                calls=[]
                def fail_at_boundary(fd):
                    calls.append(fd)
                    if len(calls)==failure:raise OSError('sensitive-canary')
                    return real_fsync(fd)
                with patch.object(stage.os,'fsync',side_effect=fail_at_boundary):
                    with self.assertRaises(stage.StageError) as exc:
                        stage.prepare('/bundle','/publisher',directory,self.key,'site-1')
                self.assertNotIn('sensitive-canary',str(exc.exception))
                self.assertTrue((directory/stage.STAGE).exists())
                with self.assertRaises(stage.StageError):
                    stage.prepare('/bundle','/publisher',directory,self.key,'site-1')

    def test_stage_directory_replacement_after_receipt_is_uncertain(self):
        real_write=stage._write
        def replace_after_receipt(directory,name,data,uid,gid,mode):
            real_write(directory,name,data,uid,gid,mode)
            if name=='receipt.json':
                (self.root/stage.STAGE).rename(self.root/'old-stage')
                (self.root/stage.STAGE).mkdir(mode=0o700)
        with patch.object(stage,'_write',side_effect=replace_after_receipt):
            with self.assertRaises(stage.StageError):self.prepare()
        self.assertTrue((self.root/'old-stage'/'receipt.json').exists())


if __name__=='__main__':unittest.main()
