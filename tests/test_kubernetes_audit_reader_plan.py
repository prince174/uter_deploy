import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_audit_reader_plan as plan


class AuditReaderPlanTests(unittest.TestCase):
    def setUp(self):
        image='ghcr.io/prince174/uter-guardrail@sha256:'+'c'*64
        uid='11111111-1111-1111-1111-111111111111'
        self.pod={'metadata':{'uid':uid,'resourceVersion':'1'},'spec':{'containers':[{
            'image':image,'volumeMounts':[{'name':'data','mountPath':'/var/lib/uter/audit'}]}],
            'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'uter-test-guardrail'}}],
            'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,
                               'seccompProfile':{'type':'RuntimeDefault'}}}}
        self.record={'pod':'uter-test-guardrail-p','uid':uid,'rv':'1','spec_sha256':plan.finalizer._digest(self.pod['spec'])}
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':'22222222-2222-2222-2222-222222222222'},
            _key_path='key',home='home',site='uter-test',manifest={'images':{'guardrail':image}},
            reverify=lambda:None,_scope=lambda:None,api=SimpleNamespace(get=lambda name:self.pod))

    def test_plans_only_exact_pinned_volume_and_signed_image(self):
        with patch.object(plan.backup_installation,'safe_file',return_value=b'k'*32), \
             patch.object(plan.writer_finalizer,'_record',return_value=(self.record,{})), \
             patch.object(plan.writer_finalizer,'_pod'),patch.object(plan.storage,'_read',return_value={'binding':'x'}), \
             patch.object(plan.storage,'_write') as write:
            self.assertEqual(plan.prepare(self.session,'a'*32,b'k'*32),
                {'audit_reader_plan_saved':True,'reader_created':False,'safe_to_backup':False})
            value=write.call_args.args[2]
            self.assertEqual(value['audit_pvc_uid'],self.session._record['audit_pvc_uid'])
            self.assertEqual(value['reader_image'],self.session.manifest['images']['guardrail'])
            self.pod['spec']['volumes'][0]['persistentVolumeClaim']['claimName']='other'
            self.record['spec_sha256']=plan.finalizer._digest(self.pod['spec'])
            with self.assertRaises(plan.AuditPlanError):plan.prepare(self.session,'a'*32,b'k'*32)
            self.assertEqual(write.call_count,1)
