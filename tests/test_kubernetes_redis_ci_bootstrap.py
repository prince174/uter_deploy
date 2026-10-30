import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import bundle
import uterctl


class SignedChildBootstrapTests(unittest.TestCase):
    def test_child_loads_verified_package_before_failing_missing_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/'home';home.mkdir()
            signer=Ed25519PrivateKey.generate();secret=root/'private';public=root/'public'
            secret.write_bytes(signer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            public.write_bytes(signer.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'0.1.7',
                'source_commit':'a'*40,'data_epoch':1,'upgrade_from':['0.1.6'],
                'images':{s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('agent','guardrail','redis')},
                'maintenance_protocol':{'version':1,'services':['agent','guardrail']}}
            manifest_file=root/'manifest.json';manifest_file.write_text(json.dumps(manifest))
            executor=root/'executor'
            with redirect_stdout(io.StringIO()): bundle.build(manifest_file,executor,secret)
            for name in ('kubernetes_redis_readonly_transport.py','redis_acl_operation_inspection.py',
                         'redis_acl_experiment.py','kubernetes_redis_readonly_ci_child.py'):
                shutil.copy2(uterctl.ROOT/'scripts'/name,executor/'scripts'/name)
            inventory=json.dumps(uterctl.inventory(executor),sort_keys=True,indent=2).encode()
            (executor/'checksums.json').write_bytes(inventory)
            (executor/'checksums.sig').write_bytes(base64.b64encode(signer.sign(inventory)))
            args=[sys.executable,'-I','-B',str(executor/'scripts/kubernetes_redis_readonly_ci_child.py'),
                str(home),str(executor),str(public),str(root/'missing-config'),str(root/'missing-profile'),
                str(root/'missing-key'),'/usr/bin/false','a'*32,str(root/'missing-admin'),'b'*40]
            result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'READONLY_TRANSPORT_REFUSED_PROFILE',result.stdout)
            self.assertNotIn(b'KUBE_EXECUTOR_MODULE_UNTRUSTED',result.stdout)


if __name__ == '__main__': unittest.main()
