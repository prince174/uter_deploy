import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

if os.name=='posix':
    from scripts import kubernetes_trusted_kubectl as binary, kubernetes_fence_finalizer as finalizer
else:
    binary=finalizer=None


@unittest.skipUnless(os.name=='posix' and os.path.exists('/usr/bin/true'),'Linux executable required')
class TrustedKubectlTests(unittest.TestCase):
    def test_api_executes_open_fd_with_attacker_path_and_proxy(self):
        path=Path('/usr/bin/true').resolve();digest=hashlib.sha256(path.read_bytes()).hexdigest()
        fd=binary.open_binary(path,digest)
        try:
            api=finalizer.Kubectl(context='test',namespace='test',binary_fd=fd,binary_sha256=digest)
            with patch.dict(os.environ,{'PATH':'/attacker','HTTPS_PROXY':'http://127.0.0.1:1',
                                        'KUBECTL_EXTERNAL_DIFF':'/attacker'}):
                self.assertEqual(api._call(['version']),b'')
            with self.assertRaises(finalizer.FinalizerError):
                finalizer.Kubectl(context='test',namespace='test',binary_fd=fd,binary_sha256='0'*64)._call(['version'])
        finally:os.close(fd)

    def test_untrusted_paths_and_hashes_are_rejected(self):
        path=Path('/usr/bin/true').resolve();digest=hashlib.sha256(path.read_bytes()).hexdigest()
        for supplied,expected in (('true',digest),(path,'0'*64)):
            with self.subTest(path=supplied),self.assertRaises(ValueError):binary.open_binary(supplied,expected)
