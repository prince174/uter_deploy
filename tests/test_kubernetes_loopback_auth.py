import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_loopback_auth as auth


@unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
class LoopbackAuthTests(unittest.TestCase):
    def test_changed_intent_refuses_both_directions(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder);key=b'k'*32;operation='a'*32
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2},_key_path='key',home=home,api=object())
            auth.storage._write(home,'kubernetes-fence-recovery-auth.json',{'operation':operation},key)
            record={'operation':operation,'resource_version':'1'}
            with patch.object(auth.backup_installation,'safe_file',return_value=key), \
                 patch.object(auth.finalizer,'read_plan',return_value={}),patch.object(auth.forward,'_bound'), \
                 patch.object(auth.forward,'_read',return_value=record),patch.object(auth.reverse,'_record',return_value=(record,{})):
                for direction in ('forward','reverse'):
                    auth.seal(session,operation,key,direction)
                    auth.verify(session,operation,key,direction)
                    record['resource_version']='2'
                    with self.assertRaises(auth.IntentAuthError):auth.verify(session,operation,key,direction)
                    record['resource_version']='1'
