import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml

from scripts import kubernetes_fence_pin as pin
from tests.test_kubernetes_fence_pin import KubernetesPinTests

if sys.platform.startswith('linux'):
    import fcntl
    from scripts import kubernetes_sealed_config as sealed
    from scripts import kubernetes_fence_finalizer as finalizer
else:
    fcntl=sealed=finalizer=None


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os,'memfd_create'),'Linux sealed memfd required')
class SealedConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):KubernetesPinTests.setUpClass()

    def setUp(self):
        fixture=KubernetesPinTests();fixture.setUp()
        self.raw=yaml.safe_dump(fixture.config).encode();self.profile=fixture.profile

    def test_seals_fd_hash_and_passes_exact_bytes_only_to_explicit_child(self):
        with sealed.sealed(self.raw,self.profile) as (fd,digest):
            self.assertEqual(digest,hashlib.sha256(self.raw).hexdigest())
            self.assertTrue(fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC)
            self.assertEqual(sealed.verify_sealed(fd,digest),digest)
            with self.assertRaises(OSError):os.pwrite(fd,b'x',0)
            code='import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())'
            result=subprocess.run([sys.executable,'-c',code,'/proc/self/fd/'+str(fd)],
                                  pass_fds=(fd,),capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout.strip(),digest)
            with self.assertRaises(sealed.SealedConfigError):sealed.verify_sealed(fd,'0'*64)
            fcntl.fcntl(fd,fcntl.F_SETFD,0)
            with self.assertRaises(sealed.SealedConfigError):sealed.verify_sealed(fd,digest)
            fcntl.fcntl(fd,fcntl.F_SETFD,fcntl.FD_CLOEXEC)
        with self.assertRaises(OSError):os.fstat(fd)

    def test_unsealed_and_bad_profile_are_rejected_before_use(self):
        fd=os.memfd_create('unsafe',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close,fd);os.write(fd,self.raw)
        with self.assertRaises(sealed.SealedConfigError):sealed.verify_sealed(fd)
        with patch.object(sealed.os,'memfd_create') as create:
            with self.assertRaises(pin.PinError):
                with sealed.sealed(self.raw,{}):pass
            create.assert_not_called()

    def test_callers_exception_is_not_relabelled_and_fd_is_closed(self):
        with self.assertRaisesRegex(ValueError,'caller'):
            with sealed.sealed(self.raw,self.profile) as (fd,_):
                raise ValueError('caller')
        with self.assertRaises(OSError):os.fstat(fd)

    def test_kubectl_child_receives_only_the_explicit_sealed_fd(self):
        with tempfile.TemporaryDirectory() as folder:
            script=Path(folder)/'kubectl'
            script.write_text('#!/usr/bin/env python3\nimport hashlib,sys\n'
                              'p=next(x.split("=",1)[1] for x in sys.argv if x.startswith("--kubeconfig="))\n'
                              'print(hashlib.sha256(open(p,"rb").read()).hexdigest())\n',encoding='utf-8')
            script.chmod(0o700)
            env=dict(os.environ,PATH=folder+os.pathsep+os.environ['PATH'])
            with sealed.sealed(self.raw,self.profile) as (fd,digest):
                api=finalizer.Kubectl(context='test',namespace='test',env=env,config_fd=fd,config_sha256=digest)
                self.assertEqual(api._call(['version']).decode().strip(),digest)
                api.config_sha256='0'*64
                with patch.object(finalizer.subprocess,'Popen') as spawn:
                    with self.assertRaises(finalizer.FinalizerError):api._call(['version'])
                    spawn.assert_not_called()
