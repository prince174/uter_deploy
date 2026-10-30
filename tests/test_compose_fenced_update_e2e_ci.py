import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import compose_fenced_update_e2e_ci as ci
from tests import test_controller as fixtures


class SyntheticUpdateCITests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ControllerTests(methodName='test_tampering')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.pub=self.fixture.pub

    def test_pair_is_re_signed_and_cannot_claim_changed_images(self):
        original=self.fixture.bundle(fixtures.manifest('0.1.6'))
        directory=self.root/'ephemeral';directory.mkdir()
        old,target,pub,before,after=ci.synthetic_pair(original,directory)
        self.assertEqual(before['images'],after['images'])
        self.assertEqual(before['data_epoch'],after['data_epoch'])
        self.assertEqual(after['upgrade_from'],['0.1.6'])
        with self.assertRaises(Exception):ci.uterctl.verify(old,self.pub)
        with self.assertRaises(Exception):ci.uterctl.verify(target,self.pub)
        (target/'manifest.json').write_text('{}')
        with self.assertRaises(Exception):ci.uterctl.verify(target,pub)

    def test_redis_identity_keeps_mount_fields_and_normalizes_order(self):
        original={'id':'redis','pid':1,'started':'start',
                  'mounts':[{'Destination':'/data','Name':'volume'}, {'Destination':'/secret','Name':'secret'}],
                  'networks':{'backend':{'EndpointID':'id'}}}
        reordered=copy.deepcopy(original);reordered['mounts'].reverse()
        changed=copy.deepcopy(reordered);changed['mounts'][1]['Name']='other'
        def inspect(value):
            with mock.patch.object(ci,'run',return_value=json.dumps(value).encode()) as query:
                identity=ci.redis_identity('redis')
                self.assertNotIn('.Config.Env',str(query.call_args))
                return identity
        self.assertEqual(inspect(original),inspect(reordered))
        self.assertNotEqual(inspect(original),inspect(changed))

    def test_install_diagnostic_rejects_untrusted_state_without_exposing_it(self):
        cfg={'name':'uter-fenced-synthetic-ci','backend':'compose',
             'images':{name:'example/'+name+'@sha256:'+'a'*64 for name in ('redis','agent','guardrail')}}
        success=mock.Mock(returncode=0)
        with mock.patch.object(ci.subprocess,'run',return_value=success), \
             mock.patch.object(ci.install,'commands',return_value=(['docker','compose','-p',cfg['name']],{})), \
             mock.patch.object(ci,'run',side_effect=[b'a'*64,b'{"running":true,"oom":false,"health":"secret-canary"}']):
            code=ci.install_failure_category(self.root,cfg)
        self.assertEqual(code,'INSTALL_INSPECTION_UNCERTAIN')
        self.assertIn(code,ci.INSTALL_CODES);self.assertNotIn('secret',code.lower())
        with mock.patch.object(ci.subprocess,'run') as docker:
            self.assertEqual(ci.install_failure_category(self.root,dict(cfg,name='wrong')),'INSTALL_INSPECTION_UNCERTAIN')
            docker.assert_not_called()

    def test_staged_fixtures_are_required_before_exercise(self):
        folder=self.root/'scripts';folder.mkdir()
        with self.assertRaisesRegex(ci.Failure,'STAGED_FIXTURES_MISSING'):ci.staged_fixtures(self.root)
        (folder/'ci_upstream_fixture.py').write_text('fixture')
        with self.assertRaisesRegex(ci.Failure,'STAGED_FIXTURES_MISSING'):ci.staged_fixtures(self.root)
        (folder/'ci_fault_before_state_replace.c').write_text('fixture')
        self.assertEqual(ci.staged_fixtures(self.root),(folder/'ci_upstream_fixture.py',folder/'ci_fault_before_state_replace.c'))

    def test_apply_error_reports_only_exact_allowlisted_code(self):
        self.assertEqual(ci.apply_error(b'uterctl: FencedUpdateError: FENCED_UPDATE_CAPTURE_INCOMPLETE\n',self.root),
                         'APPLY_FENCED_UPDATE_CAPTURE_INCOMPLETE_PHASE_NONE')
        self.assertEqual(ci.apply_error(b'uterctl: FencedUpdateError: FENCED_UPDATE_CAPTURE_FENCE_START_WRITER_STOP_GUARDRAIL_EXIT_TERM_LIKE_OOM_FALSE\n',self.root),
                         'APPLY_FENCED_UPDATE_CAPTURE_FENCE_START_WRITER_STOP_GUARDRAIL_EXIT_TERM_LIKE_OOM_FALSE_PHASE_NONE')
        for stage in ('PRECHECK','FENCE_START','ADAPTER_ATTACH','BACKUP_CAPTURE','RECEIPT','INTENT'):
            code='FENCED_UPDATE_CAPTURE_'+stage+'_UNCERTAIN'
            self.assertEqual(ci.apply_error(('uterctl: FencedUpdateError: '+code+'\n').encode(),self.root),
                             'APPLY_'+code+'_PHASE_NONE')
        self.assertNotIn('FENCED_UPDATE_CAPTURE_FENCE_START_UNTRUSTED_SECRET',ci.APPLY_CODES)
        for bad in (b'uterctl: FencedUpdateError: FENCED_UPDATE_CAPTURE_INCOMPLETE secret\n',
                    b'uterctl: ValueError: FENCED_UPDATE_CAPTURE_INCOMPLETE\n',
                    b'uterctl: FencedUpdateError: FENCED_UPDATE_SECRET\n',
                    b'secret\nuterctl: FencedUpdateError: FENCED_UPDATE_CAPTURE_INCOMPLETE\n'):
            self.assertEqual(ci.apply_error(bad,self.root),'APPLY_UNKNOWN_PHASE_NONE')
        with mock.patch.object(ci.os.path,'lexists',return_value=True), \
             mock.patch.object(ci.journal,'read',return_value={'phase':'isolating'}):
            self.assertEqual(ci.apply_error(b'uterctl: FencedUpdateError: FENCED_UPDATE_CAPTURE_INCOMPLETE\n',self.root),
                             'APPLY_FENCED_UPDATE_CAPTURE_INCOMPLETE_PHASE_ISOLATING')

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'LD_PRELOAD fault requires Linux and C compiler')
    def test_fault_injection_is_scoped_to_state_in_selected_directory(self):
        shim=self.root/'fault.so'
        subprocess.run(['cc','-shared','-fPIC','-o',str(shim),
                        str(ci.ROOT/'scripts/ci_fault_before_state_replace.c'),'-ldl'],check=True)
        home=self.root/'home';home.mkdir();other=self.root/'other';other.mkdir()
        child='import os,sys; d=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); os.replace("tmp",sys.argv[2],src_dir_fd=d,dst_dir_fd=d)'
        env=dict(os.environ,LD_PRELOAD=str(shim),UTER_CI_FAULT_HOME=str(home))
        for folder,name,expected in ((other,'state.json',0),(home,'other.json',0),(home,'state.json',88)):
            (folder/'tmp').write_text('new')
            result=subprocess.run([sys.executable,'-I','-c',child,str(folder),name],env=env)
            self.assertEqual(result.returncode,expected)
            if expected==88:self.assertTrue((folder/'tmp').exists())


if __name__=='__main__':unittest.main()
