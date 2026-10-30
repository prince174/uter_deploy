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

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'LD_PRELOAD fault requires Linux and C compiler')
    def test_fault_injection_is_scoped_to_state_in_selected_directory(self):
        shim=self.root/'fault.so'
        subprocess.run(['cc','-shared','-fPIC','-o',str(shim),
                        str(ci.ROOT/'tests/fixtures/ci_fault_before_state_replace.c'),'-ldl'],check=True)
        home=self.root/'home';home.mkdir();other=self.root/'other';other.mkdir()
        child='import os,sys; d=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); os.replace("tmp",sys.argv[2],src_dir_fd=d,dst_dir_fd=d)'
        env=dict(os.environ,LD_PRELOAD=str(shim),UTER_CI_FAULT_HOME=str(home))
        for folder,name,expected in ((other,'state.json',0),(home,'other.json',0),(home,'state.json',88)):
            (folder/'tmp').write_text('new')
            result=subprocess.run([sys.executable,'-I','-c',child,str(folder),name],env=env)
            self.assertEqual(result.returncode,expected)
            if expected==88:self.assertTrue((folder/'tmp').exists())


if __name__=='__main__':unittest.main()
