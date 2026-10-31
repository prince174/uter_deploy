import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import redis_acl_credential_capsule as capsule


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root-only secure filesystem profile')
class CapsuleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.key=b'k'*32
        self.verify=patch.object(capsule.redis_acl_staged,'verify_profile',return_value={'version':'fixture'})
        self.verify.start();self.addCleanup(self.verify.stop)

    def create(self,**changes):
        args={'bundle':'/bundle','publisher':'/publisher','directory':self.root,'backup_key':self.key,'site':'site-1','backend':'compose'}
        args.update(changes);return capsule.create(**args)

    def read(self,**changes):
        args={'bundle':'/bundle','publisher':'/publisher','directory':self.root,'backup_key':self.key,'site':'site-1','backend':'compose'}
        args.update(changes);return capsule.read(**args)

    def test_encrypted_roundtrip_and_exclusive_creation(self):
        result=self.create();self.assertFalse(result['safe_to_update']);self.assertFalse(result['workloads_configured'])
        path=self.root/capsule.NAME;data=self.read();raw=path.read_bytes()
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertNotEqual(data['writer'],data['admin'])
        for secret in (data['writer'],data['admin'],data['acl']):self.assertNotIn(secret.encode(),raw)
        with self.assertRaises(capsule.CapsuleError):self.create()
        self.assertEqual(path.read_bytes(),raw)

    def test_wrong_key_site_backend_or_signed_profile_rejected(self):
        self.create()
        for changes in ({'backup_key':b'x'*32},{'site':'site-2'},{'backend':'kubernetes'}):
            with self.subTest(changes=changes),self.assertRaises(capsule.CapsuleError):self.read(**changes)
        with patch.object(capsule.redis_acl_staged,'verify_profile',return_value={'version':'other'}):
            with self.assertRaises(capsule.CapsuleError):self.read()

    def test_unapproved_backend_fails_before_write(self):
        with self.assertRaises(capsule.CapsuleError):self.create(backend='kubernetes')
        self.assertEqual(list(self.root.iterdir()),[])

    def test_restrictive_umask_does_not_publish_unreadable_capsule(self):
        old=os.umask(0o777)
        try:self.create()
        finally:os.umask(old)
        self.assertEqual((self.root/capsule.NAME).stat().st_mode&0o777,0o600)
        self.assertEqual(self.read()['schema'],1)

    def test_tampering_truncation_and_symlink_rejected(self):
        self.create();path=self.root/capsule.NAME;raw=path.read_bytes()
        for replacement in (raw[:-1],raw[:-1]+bytes([raw[-1]^1])):
            path.write_bytes(replacement)
            with self.assertRaises(capsule.CapsuleError):self.read()
        path.unlink();path.symlink_to('/etc/passwd')
        with self.assertRaises(capsule.CapsuleError):self.read()

    def test_untrusted_profile_and_invalid_directory_fail_before_write(self):
        with patch.object(capsule.redis_acl_staged,'verify_profile',side_effect=ValueError('secret-canary')):
            with self.assertRaises(capsule.CapsuleError) as exc:self.create()
            self.assertNotIn('secret-canary',str(exc.exception))
        self.assertEqual(list(self.root.iterdir()),[])
        self.root.chmod(0o755)
        with self.assertRaises(capsule.CapsuleError):self.create()
        self.assertEqual(list(self.root.iterdir()),[])

    def test_profile_change_before_publish_rejects_draft(self):
        with patch.object(capsule.redis_acl_staged,'verify_profile',side_effect=[{'v':1},{'v':2}]):
            with self.assertRaises(capsule.CapsuleError):self.create()
        self.assertEqual(list(self.root.iterdir()),[])

    def test_signed_fixture_profile_and_tamper(self):
        from scripts.redis_acl_staged_ci import make_fixture_profile
        self.verify.stop()
        fixture=self.root/'fixture';fixture.mkdir(mode=0o700)
        draft=self.root/'draft';draft.mkdir(mode=0o700)
        # A Windows-mounted checkout can copy its permissive mode bits into the
        # fixture. Construct it first, then secure every copied file before
        # exercising the real signature/capability verifier below.
        with patch.object(capsule.redis_acl_staged,'verify_profile',side_effect=lambda *_: __import__('json').loads((fixture/'fixture-manifest.json').read_text())):
            bundle,publisher=make_fixture_profile(fixture)
        for path in bundle.rglob('*'):
            path.chmod(path.stat().st_mode&~0o022)
        capsule.redis_acl_staged.verify_profile(bundle,publisher)
        result=capsule.create(bundle,publisher,draft,self.key,'site-1','compose')
        self.assertFalse(result['safe_to_update'])
        self.assertEqual(capsule.read(bundle,publisher,draft,self.key,'site-1','compose')['schema'],1)
        (bundle/'compose/redis-acl-maintenance.json').write_bytes(b'{}')
        with self.assertRaises(capsule.CapsuleError):
            capsule.read(bundle,publisher,draft,self.key,'site-1','compose')

    def test_failed_fsync_after_link_is_uncertain_but_capsule_authenticates(self):
        real_fsync=os.fsync;calls=[]
        def fail_second(fd):
            calls.append(fd)
            if len(calls)==2:raise OSError('secret-canary')
            return real_fsync(fd)
        with patch.object(capsule.os,'fsync',side_effect=fail_second):
            with self.assertRaises(capsule.CapsuleError) as exc:self.create()
        self.assertNotIn('secret-canary',str(exc.exception))
        self.assertEqual(set(p.name for p in self.root.iterdir()),{capsule.NAME})
        self.assertEqual(self.read()['schema'],1)
        with self.assertRaises(capsule.CapsuleError):self.create()

    def test_publication_failure_never_overwrites_or_returns_success(self):
        with patch.object(capsule.os,'link',side_effect=OSError('secret-canary')):
            with self.assertRaises(capsule.CapsuleError):self.create()
        self.assertEqual(list(self.root.iterdir()),[])
        real_unlink=os.unlink;calls=[]
        def fail_first(name,*args,**kwargs):
            calls.append(name)
            if len(calls)==1:raise OSError('unknown')
            return real_unlink(name,*args,**kwargs)
        with patch.object(capsule.os,'unlink',side_effect=fail_first):
            with self.assertRaises(capsule.CapsuleError):self.create()
        self.assertEqual(self.read()['schema'],1)

    def test_changed_named_capsule_after_publish_is_uncertain(self):
        real_stat=capsule.os.stat
        def altered(path,*args,**kwargs):
            result=real_stat(path,*args,**kwargs)
            if path==capsule.NAME:
                values=list(result);values[1]+=1;return os.stat_result(values)
            return result
        with patch.object(capsule.os,'stat',side_effect=altered):
            with self.assertRaises(capsule.CapsuleError):self.create()

    def test_hardlink_and_replaced_directory_rejected(self):
        self.create();path=self.root/capsule.NAME;os.link(path,self.root/'extra')
        with self.assertRaises(capsule.CapsuleError):self.read()
        (self.root/'extra').unlink()
        original=capsule._same_directory
        def swapped(path,fd,info):
            moved=Path(str(path)+'-moved');Path(path).rename(moved);Path(path).mkdir(mode=0o700)
            try:original(path,fd,info)
            finally:Path(path).rmdir();moved.rename(path)
        with patch.object(capsule,'_same_directory',side_effect=swapped):
            with self.assertRaises(capsule.CapsuleError):self.read()


if __name__=='__main__':unittest.main()
