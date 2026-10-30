import json
import os
import contextlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import backup_crypto, update_installation
from scripts.bundle import build


@unittest.skipUnless(os.name=='posix','Managed update requires POSIX')
class ManagedUpdateTests(unittest.TestCase):
    def setUp(self):
        # Exercise legacy validation branches independently of the new gate.
        gate=patch.object(uterctl,'require_live_update_support',lambda: None)
        gate.start();self.addCleanup(gate.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.home=self.root/'home';(self.home/'runtime').mkdir(parents=True)
        self.backups=self.root/'backups';self.backups.mkdir(mode=0o700)
        keys=self.root/'keys';keys.mkdir(mode=0o700);self.backup_key=keys/'backup.key'
        key=Ed25519PrivateKey.generate();private=keys/'private.pem';self.public=keys/'public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.images={s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')}
        self.old={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0','source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],'images':self.images}
        self.new=dict(self.old,version='1.1.0',upgrade_from=['1.0.0'])
        for label,manifest in [('old',self.old),('new',self.new)]:
            path=self.root/(label+'.json');path.write_text(json.dumps(manifest));build(path,self.root/label,private)
        uterctl.write(self.home/'install.json',{'backend':'compose','name':'uter-test','context':'default','port':18000,'images':self.images})

    def test_unsupported_transition_rejected_before_adoption_or_key_creation(self):
        with patch.object(update_installation.uterctl,'transition',side_effect=ValueError('Unsupported upgrade path')),patch.object(update_installation.adopt_managed,'adopt') as adopt:
            with self.assertRaisesRegex(ValueError,'Unsupported upgrade path'):
                update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,current_bundle=self.root/'old',create_backup_key=True)
            adopt.assert_not_called()
        self.assertFalse(self.backup_key.exists());self.assertEqual(list((self.home/'runtime').iterdir()),[])

    def test_failed_adoption_removes_created_smoke_files(self):
        with patch.object(update_installation.adopt_managed.adopt_installation,'adopt',side_effect=ValueError('smoke failed')):
            with self.assertRaisesRegex(ValueError,'smoke failed'):
                update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,current_bundle=self.root/'old',create_backup_key=True)
        self.assertEqual(list((self.home/'runtime').iterdir()),[])
        self.assertEqual(len(backup_crypto.read_key(self.backup_key)),32)
        self.assertFalse((self.home/'state.json').exists())

    def test_incomplete_redis_fence_blocks_before_key_creation(self):
        for name in ('redis-fence-operation.json','compose-fence-finalize-anchor.json','compose-fenced-update-intent.json','compose-fenced-target-start.json','compose-fenced-target-result.json','compose-fenced-cleanup.json'):
            with self.subTest(name=name):
                marker=self.home/name;marker.symlink_to(self.home/'missing')
                with patch('scripts.update_installation.adopt_managed.adopt') as adopt:
                    with self.assertRaisesRegex(ValueError, '^REDIS_FENCE_REQUIRES_INSPECTION$'):
                        update_installation.update(self.home, self.root/'new', self.public,
                                                   self.backups, self.backup_key, create_backup_key=True)
                adopt.assert_not_called();marker.unlink()
                self.assertFalse(self.backup_key.exists())

    def test_fence_appearing_after_initial_check_blocks_under_lock_before_key_or_adoption(self):
        marker=self.home/'redis-fence-operation.json'
        verify=update_installation.uterctl.verify
        def insert_fence(*args, **kwargs):
            result=verify(*args, **kwargs)
            if not os.path.lexists(marker): marker.symlink_to(self.home/'missing')
            return result
        with patch.object(update_installation.uterctl,'verify',side_effect=insert_fence), \
                patch.object(update_installation.adopt_managed,'adopt') as adopt:
            with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,
                                           current_bundle=self.root/'old',create_backup_key=True)
        adopt.assert_not_called()
        self.assertFalse(self.backup_key.exists())
        self.assertTrue(marker.is_symlink())
        self.assertFalse((self.home/'operation.lock').exists())

    def test_fence_created_after_preflight_is_rechecked_by_adoption(self):
        marker=self.home/'redis-fence-operation.json'
        real_lock=uterctl.locked
        @contextlib.contextmanager
        def fence_after_preflight(path):
            with real_lock(path):
                yield
            if self.backup_key.exists() and not os.path.lexists(marker):
                # A cooperating fence may acquire the same lock between the
                # updater's preflight and the later adoption transaction.
                with real_lock(path): marker.symlink_to(self.home/'missing')
        # Supply the ordinary ready state and matching signed deployment assets.
        (self.home/'install-state.json').write_text('{"status":"ready"}')
        shutil.copytree(self.root/'old'/'compose',self.home/'compose')
        shutil.copytree(self.root/'old'/'charts',self.home/'charts')
        with patch.object(uterctl,'locked',side_effect=fence_after_preflight), \
                patch.object(update_installation.adopt_managed.managed_smoke,'prepare') as smoke:
            with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,
                                           current_bundle=self.root/'old',create_backup_key=True)
        smoke.assert_not_called()
        self.assertTrue(self.backup_key.exists())  # Never silently delete a newly created encryption key.
        self.assertFalse((self.home/'state.json').exists())
        self.assertFalse((self.home/'operation.lock').exists())

    def test_backup_key_cannot_be_inside_backup_directory(self):
        with self.assertRaisesRegex(ValueError,'stored separately'):
            update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backups/'key',current_bundle=self.root/'old')

    def test_existing_backup_key_is_never_replaced(self):
        backup_crypto.create_key(self.backup_key);before=self.backup_key.read_bytes()
        with self.assertRaisesRegex(ValueError,'already exists'):
            update_installation.update(self.home,self.root/'new',self.public,self.backups,self.backup_key,current_bundle=self.root/'old',create_backup_key=True)
        self.assertEqual(self.backup_key.read_bytes(),before)
