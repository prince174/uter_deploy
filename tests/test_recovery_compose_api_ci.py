import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import recovery_compose_api_ci as ci
from scripts import adopt_backup_ci


class RecoveryComposeCiTests(unittest.TestCase):
    def test_custom_name_and_port_keep_resource_ownership_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'work').mkdir()
            marker = 'a'*32
            def restore(home, backup, key, public, target, name, port):
                self.assertEqual((name,port),('uter-restored-after-ci',18006))
                target.mkdir()
                (target/'recovery-operation.json').write_text(json.dumps({'id':marker}))
                (target/'install.json').write_text('{}')
                return {'name':name}
            inspected=[]; downs=[]
            def execute(args, **kwargs):
                if args[:5] == ['docker','--context','default','volume','inspect']:
                    inspected.append(args[-1]); return subprocess.CompletedProcess(args,0,json.dumps([{'Labels':{'uter.recovery.id':marker}}]).encode())
                downs.append(args); return subprocess.CompletedProcess(args,0,b'')
            env={'GITHUB_ACTIONS':'true'}
            with mock.patch.dict(os.environ,env), mock.patch.object(ci.os,'geteuid',return_value=0), \
                 mock.patch.object(ci,'ROOT',root), mock.patch.object(ci.recover_compose,'run',return_value=b''), \
                 mock.patch.object(ci.recover_compose,'restore',side_effect=restore), \
                 mock.patch.object(ci.install,'commands',return_value=(['docker','compose'],{})), \
                 mock.patch.object(ci.uterctl,'site_config',return_value={'smoke_command':['/new/path']}), \
                 mock.patch.object(adopt_backup_ci,'audit_and_redis',return_value={'first_sha256':'abc'}), \
                 mock.patch.object(ci.subprocess,'run',side_effect=execute):
                ci.test(root/'old',root/'backup',root/'key',root/'public',{'first_sha256':'abc'},
                        name='uter-restored-after-ci',port=18006)
            self.assertEqual(inspected,['uter-restored-after-ci_redis-data','uter-restored-after-ci_audit-data'])
            self.assertEqual(downs,[['docker','compose','down','--volumes','--remove-orphans']])

    def test_invalid_name_and_port_fail_before_resource_lookup(self):
        with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), mock.patch.object(ci.os,'geteuid',return_value=0), \
             mock.patch.object(ci.recover_compose,'run') as lookup:
            for name,port in (('../unsafe',18006),('valid-ci',0),('valid-ci',True)):
                with self.assertRaisesRegex(ValueError,'Invalid disposable recovery project or port'):
                    ci.test('/old','/backup','/key','/public',{},name=name,port=port)
            lookup.assert_not_called()

    def test_unrelated_volume_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'work').mkdir(); downs=[]
            def restore(home, backup, key, public, target, name, port):
                target.mkdir(); (target/'recovery-operation.json').write_text(json.dumps({'id':'a'*32}))
                (target/'install.json').write_text('{}'); return {'name':name}
            def execute(args, **kwargs):
                if args[:5] == ['docker','--context','default','volume','inspect']:
                    return subprocess.CompletedProcess(args,0,json.dumps([{'Labels':{'uter.recovery.id':'b'*32}}]).encode())
                downs.append(args); return subprocess.CompletedProcess(args,0,b'')
            with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), mock.patch.object(ci.os,'geteuid',return_value=0), \
                 mock.patch.object(ci,'ROOT',root), mock.patch.object(ci.recover_compose,'run',return_value=b''), \
                 mock.patch.object(ci.recover_compose,'restore',side_effect=restore), \
                 mock.patch.object(ci.install,'commands',return_value=(['docker','compose'],{})), \
                 mock.patch.object(ci.uterctl,'site_config',return_value={'smoke_command':['/new/path']}), \
                 mock.patch.object(adopt_backup_ci,'audit_and_redis',return_value={'first_sha256':'abc'}), \
                 mock.patch.object(ci.subprocess,'run',side_effect=execute):
                with self.assertRaisesRegex(ValueError,'Refusing to clean an unrelated recovery volume'):
                    ci.test(root/'old',root/'backup',root/'key',root/'public',{'first_sha256':'abc'},
                            name='uter-restored-after-ci',port=18006)
            self.assertFalse(downs)


if __name__ == '__main__':
    unittest.main()
