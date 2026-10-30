import base64
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml

from scripts import kubernetes_fence_pin as pin


class KubernetesPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic-test-ca')])
        now=datetime.now(timezone.utc)
        cls.ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                .sign(key,hashes.SHA256())
                .public_bytes(serialization.Encoding.PEM))

    def setUp(self):
        self.server='https://127.0.0.1:6443'
        uids=['7a1ae129-82a8-490f-86e3-84dfd735d330','7a1ae129-82a8-490f-86e3-84dfd735d331',
              '7a1ae129-82a8-490f-86e3-84dfd735d332','7a1ae129-82a8-490f-86e3-84dfd735d333']
        self.profile={'schema':1,'context':'test','server_sha256':hashlib.sha256(self.server.encode()).hexdigest(),
                      'ca_sha256':hashlib.sha256(self.ca).hexdigest(),
                      **dict(zip(('kube_system_uid','namespace_uid','redis_pvc_uid','redis_deployment_uid'),uids))}
        self.config={'apiVersion':'v1','kind':'Config','clusters':[{'name':'cluster','cluster':{
                     'server':self.server,'certificate-authority-data':base64.b64encode(self.ca).decode()}}],
                     'contexts':[{'name':'test','context':{'cluster':'cluster','user':'operator'}}],
                     'users':[{'name':'operator','user':{'token':'synthetic-token'}}]}
        self.resources={'kube_system':{'kind':'Namespace','metadata':{'name':'kube-system','uid':uids[0]}},
                        'namespace':{'kind':'Namespace','metadata':{'name':'test','uid':uids[1]}},
                        'pvc':{'kind':'PersistentVolumeClaim','metadata':{'name':'test-redis','namespace':'test','uid':uids[2]}},
                        'deployment':{'kind':'Deployment','metadata':{'name':'test-redis','namespace':'test','uid':uids[3]}}}

    def check(self,config=None,profile=None):
        return pin.verify_config(yaml.safe_dump(self.config if config is None else config).encode(),
                                 self.profile if profile is None else profile)

    def test_valid_config_is_not_authority_to_update(self):
        result=self.check()
        self.assertEqual(result,{'result':'pinned_kubeconfig_match','cluster_authenticated':False,
                                 'redis_isolated':False,'safe_to_update':False})
        self.assertEqual(pin.verify_resources(self.profile,**self.resources)['safe_to_update'],False)

    def test_untrusted_endpoints_or_plugins_fail_without_disclosing_secrets(self):
        for change in ('endpoint','ca','exec','authprovider','file','insecure','proxy','duplicate'):
            config=copy.deepcopy(self.config)
            cluster=config['clusters'][0]['cluster'];user=config['users'][0]['user']
            if change=='endpoint':cluster['server']='https://other.example:6443'
            if change=='ca':cluster['certificate-authority-data']=base64.b64encode(b'not-a-certificate').decode()
            if change=='exec':user['exec']={'command':'echo','args':['secret']}
            if change=='authprovider':user['auth-provider']={'name':'secret'}
            if change=='file':user.clear();user['tokenFile']='/tmp/secret'
            if change=='insecure':cluster['insecure-skip-tls-verify']=True
            if change=='proxy':cluster['proxy-url']='http://attacker'
            if change=='duplicate':config['clusters'].append(copy.deepcopy(config['clusters'][0]))
            with self.subTest(change=change),self.assertRaises(pin.PinError) as error:self.check(config)
            self.assertEqual(str(error.exception),'KUBE_PIN_CONFIG_UNVERIFIED')
            self.assertNotIn('secret',str(error.exception))

    def test_unknown_profile_and_replaced_resources_fail_closed(self):
        with self.assertRaises(pin.PinError):self.check(profile={})
        for object_name in self.resources:
            changed=copy.deepcopy(self.resources);changed[object_name]['metadata']['uid']='00000000-0000-0000-0000-000000000000'
            with self.subTest(object_name=object_name),self.assertRaises(pin.PinError):
                pin.verify_resources(self.profile,**changed)
        changed=copy.deepcopy(self.resources);changed['pvc']['metadata']['deletionTimestamp']='now'
        with self.assertRaises(pin.PinError):pin.verify_resources(self.profile,**changed)

    def test_duplicate_yaml_keys_refused(self):
        raw=yaml.safe_dump(self.config).encode()+b'kind: Config\n'
        with self.assertRaises(pin.PinError):pin.verify_config(raw,self.profile)
