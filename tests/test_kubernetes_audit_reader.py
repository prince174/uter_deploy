import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_audit_reader as reader


class AuditReaderTests(unittest.TestCase):
    def setUp(self):
        self.plan={'schema':1,'operation':'a'*32,'site':'uter-test',
            'audit_pvc_uid':'11111111-1111-1111-1111-111111111111','audit_pvc_name':'uter-test-guardrail',
            'guardrail_pod_uid':'22222222-2222-2222-2222-222222222222','guardrail_pod_sha256':'b'*64,
            'reader_image':'ghcr.io/prince174/uter-guardrail@sha256:'+'c'*64,
            'reader_name':'uter-test-audit-reader-'+'a'*12,'recovery_binding_sha256':'d'*64}

    def test_request_is_fixed_readonly_and_nonprivileged(self):
        obj=reader.pod_spec(self.plan);spec=obj['spec'];container=spec['containers'][0]
        self.assertFalse(spec['automountServiceAccountToken']);self.assertFalse(spec['hostNetwork'])
        self.assertTrue(container['volumeMounts'][0]['readOnly'])
        self.assertTrue(spec['volumes'][0]['persistentVolumeClaim']['readOnly'])
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
        self.assertEqual(container['image'],self.plan['reader_image'])

    @unittest.skipUnless(os.name=='posix' and os.path.exists('/usr/bin/cat'),'Linux process required')
    def test_bounded_input_process_roundtrip(self):
        fd=os.open('/dev/null',os.O_RDONLY)
        try:self.assertEqual(reader._call_input(['/usr/bin/cat'],b'bounded-test',fd,fd),b'bounded-test')
        finally:os.close(fd)

    def test_mismatched_scope_mutable_image_or_injected_fields_fail(self):
        for field,value in (('audit_pvc_name','other'),('reader_image','untrusted:latest'),
                            ('reader_name','other'),('operation','x'*32),('other','injected')):
            candidate=copy.deepcopy(self.plan);candidate[field]=value
            with self.subTest(field=field),self.assertRaises(reader.AuditReaderError):reader.pod_spec(candidate)

    def test_admitted_pod_must_match_uid_and_strict_reader_spec(self):
        pod=reader.pod_spec(self.plan);uid='33333333-3333-3333-3333-333333333333'
        pod['metadata']['uid']=uid
        pod['status']={'phase':'Running','containerStatuses':[{'name':'reader','ready':True,'restartCount':0,
                                                               'containerID':'containerd://'+'e'*64,
                                                               'imageID':'docker-pullable://example@sha256:'+'c'*64,
                                                               'state':{'running':{}}}]}
        self.assertEqual(reader.verify_pod(self.plan,pod,uid,ready=True),
                         {'reader_identity_observed':True,'safe_to_backup':False})
        for mutation in ('uid','env','volume','sidecar','host','restart'):
            changed=copy.deepcopy(pod)
            if mutation=='uid':changed['metadata']['uid']='44444444-4444-4444-4444-444444444444'
            elif mutation=='env':changed['spec']['containers'][0]['env']=[{'name':'INJECTED','value':'1'}]
            elif mutation=='volume':changed['spec']['volumes'][0]['persistentVolumeClaim']['readOnly']=False
            elif mutation=='sidecar':changed['spec']['containers'].append({'name':'evil'})
            elif mutation=='host':changed['spec']['hostNetwork']=True
            else:changed['status']['containerStatuses'][0]['restartCount']=True
            with self.subTest(mutation=mutation),self.assertRaises(reader.AuditReaderError):
                reader.verify_pod(self.plan,changed,uid,ready=True)

    @unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
    def test_one_shot_create_rejects_timeout_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            key=b'k'*32;home=Path(folder);binding={'operation':self.plan['operation']}
            self.plan['recovery_binding_sha256']=reader.storage._hash(binding)
            reader.storage._write(home,'kubernetes-audit-reader-plan.json',self.plan,key)
            reader.storage._write(home,'kubernetes-fence-recovery-auth.json',binding,key)
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':self.plan['audit_pvc_uid'],
                'kubectl_sha256':'f'*64},_inner=SimpleNamespace(config_fd=11,api=SimpleNamespace(binary_fd=12)),
                home=home,_key_path='key',site=self.plan['site'],manifest={'images':{'guardrail':self.plan['reader_image']}},
                api=SimpleNamespace(context='test'),config_sha256='e'*64,_scope=lambda:None)
            with patch.object(reader.backup_installation,'safe_file',return_value=key), \
                 patch.object(reader.writer_guard,'verify'),patch.object(reader.sealed,'verify_sealed'), \
                 patch.object(reader.binary,'verify'),patch.object(reader,'_call_input',side_effect=subprocess.TimeoutExpired('kubectl',30)) as run:
                with self.assertRaises(reader.AuditReaderError):reader.create(session,self.plan['operation'],key)
                with self.assertRaises(reader.AuditReaderError):reader.create(session,self.plan['operation'],key)
                self.assertEqual(run.call_count,1)
                self.assertEqual(run.call_args.args[2:],(11,12))
                self.assertEqual(run.call_args.args[0][0],'/proc/self/fd/12')
            self.assertTrue((home/reader.CREATE_ATTEMPT).is_file())
            self.assertFalse((home/reader.CREATED).exists())

    @unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
    def test_exact_created_uid_is_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            key=b'k'*32;home=Path(folder);binding={'operation':self.plan['operation']}
            self.plan['recovery_binding_sha256']=reader.storage._hash(binding)
            reader.storage._write(home,'kubernetes-audit-reader-plan.json',self.plan,key)
            reader.storage._write(home,'kubernetes-fence-recovery-auth.json',binding,key)
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':self.plan['audit_pvc_uid'],
                'kubectl_sha256':'f'*64},_inner=SimpleNamespace(config_fd=11,api=SimpleNamespace(binary_fd=12)),
                home=home,_key_path='key',site=self.plan['site'],manifest={'images':{'guardrail':self.plan['reader_image']}},
                api=SimpleNamespace(context='test'),config_sha256='e'*64,_scope=lambda:None)
            pod=reader.pod_spec(self.plan);uid='33333333-3333-3333-3333-333333333333';pod['metadata']['uid']=uid
            with patch.object(reader.backup_installation,'safe_file',return_value=key), \
                 patch.object(reader.writer_guard,'verify'),patch.object(reader.sealed,'verify_sealed'), \
                 patch.object(reader.binary,'verify'),patch.object(reader,'_call_input',return_value=json.dumps(pod).encode()):
                self.assertEqual(reader.create(session,self.plan['operation'],key),{'reader_created':True,'safe_to_backup':False})
            self.assertEqual(reader.storage._read(home,reader.CREATED,key)['uid'],uid)

    @unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
    def test_deletion_uses_exact_uid_and_never_replays(self):
        with tempfile.TemporaryDirectory() as folder:
            key=b'k'*32;home=Path(folder);uid='33333333-3333-3333-3333-333333333333'
            reader.storage._write(home,'kubernetes-audit-reader-plan.json',self.plan,key)
            reader.storage._write(home,reader.CREATED,{'operation':self.plan['operation'],
                    'plan_sha256':reader.storage._hash(self.plan),'uid':uid},key)
            pod=reader.pod_spec(self.plan);pod['metadata']['uid']=uid
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':self.plan['audit_pvc_uid'],
                'kubectl_sha256':'f'*64},_inner=SimpleNamespace(config_fd=11,api=SimpleNamespace(binary_fd=12)),
                home=home,_key_path='key',site=self.plan['site'],_query=lambda args:pod,
                api=SimpleNamespace(context='test'),config_sha256='e'*64,_scope=lambda:None)
            with patch.object(reader.backup_installation,'safe_file',return_value=key), \
                 patch.object(reader.writer_guard,'verify'),patch.object(reader.sealed,'verify_sealed'), \
                 patch.object(reader.binary,'verify'),patch.object(reader,'_call_input',return_value=b'{"kind":"Status","status":"Success"}') as run:
                self.assertEqual(reader.delete(session,self.plan['operation'],key),
                    {'reader_deletion_requested':True,'old_uid_gone':False,'safe_to_backup':False})
                self.assertEqual(json.loads(run.call_args.args[1])['preconditions']['uid'],uid)
                with self.assertRaises(reader.AuditReaderError):reader.delete(session,self.plan['operation'],key)
                self.assertEqual(run.call_count,1)

    @unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
    def test_uncertain_delete_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            key=b'k'*32;home=Path(folder);uid='33333333-3333-3333-3333-333333333333'
            reader.storage._write(home,'kubernetes-audit-reader-plan.json',self.plan,key)
            reader.storage._write(home,reader.CREATED,{'operation':self.plan['operation'],
                    'plan_sha256':reader.storage._hash(self.plan),'uid':uid},key)
            pod=reader.pod_spec(self.plan);pod['metadata']['uid']=uid
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':self.plan['audit_pvc_uid'],
                'kubectl_sha256':'f'*64},_inner=SimpleNamespace(config_fd=11,api=SimpleNamespace(binary_fd=12)),
                home=home,_key_path='key',site=self.plan['site'],_query=lambda args:pod,
                api=SimpleNamespace(context='test'),config_sha256='e'*64,_scope=lambda:None)
            with patch.object(reader.backup_installation,'safe_file',return_value=key), \
                 patch.object(reader.writer_guard,'verify'),patch.object(reader.sealed,'verify_sealed'), \
                 patch.object(reader.binary,'verify'), \
                 patch.object(reader,'_call_input',side_effect=subprocess.TimeoutExpired('kubectl',30)) as call:
                for _ in range(2):
                    with self.assertRaises(reader.AuditReaderError):reader.delete(session,self.plan['operation'],key)
                self.assertEqual(call.call_count,1)
                with patch.object(reader,'_call_input',return_value=b''):
                    self.assertEqual(reader.observe_deletion(session,self.plan['operation'],key),
                                     {'reader_old_uid_gone':True,'safe_to_backup':False})
                replacement=reader.pod_spec(self.plan)
                replacement['metadata']['uid']='44444444-4444-4444-4444-444444444444'
                with patch.object(reader,'_call_input',return_value=json.dumps(replacement).encode()):
                    with self.assertRaises(reader.AuditReaderError):reader.observe_deletion(session,self.plan['operation'],key)

    @unittest.skipUnless(os.name=='posix','authenticated records require POSIX')
    def test_capture_checks_same_uid_and_container_before_and_after(self):
        with tempfile.TemporaryDirectory() as folder:
            key=b'k'*32;home=Path(folder);uid='33333333-3333-3333-3333-333333333333'
            reader.storage._write(home,'kubernetes-audit-reader-plan.json',self.plan,key)
            reader.storage._write(home,reader.CREATED,{'operation':self.plan['operation'],
                    'plan_sha256':reader.storage._hash(self.plan),'uid':uid},key)
            pod=reader.pod_spec(self.plan);pod['metadata']['uid']=uid
            pod['status']={'phase':'Running','containerStatuses':[{'name':'reader','ready':True,'restartCount':0,
                'containerID':'containerd://'+'e'*64,'imageID':'repo@sha256:'+'c'*64,'state':{'running':{}}}]}
            session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'audit_pvc_uid':self.plan['audit_pvc_uid'],
                'kubectl_sha256':'f'*64},_inner=SimpleNamespace(config_fd=11,api=SimpleNamespace(binary_fd=12)),
                home=home,_key_path='key',site=self.plan['site'],_query=lambda args:copy.deepcopy(pod),
                manifest={'images':{'guardrail':self.plan['reader_image']}},api=SimpleNamespace(context='test'),
                config_sha256='e'*64,_scope=lambda:None)
            class Process:
                def __init__(inner,command,**kwargs):self.command=command;self.kwargs=kwargs;inner.stdout=io.BytesIO(b'tar')
                def poll(inner):return 0
                def wait(inner,timeout=None):return 0
                def kill(inner):pass
            class Writer:
                manifest={'files':{}}
                def put(inner,label,stream):self.label=label;self.content=stream.read(100)
            with patch.object(reader.backup_installation,'safe_file',return_value=key), \
                 patch.object(reader.writer_guard,'verify'),patch.object(reader.sealed,'verify_sealed'), \
                 patch.object(reader.binary,'verify'),patch.object(reader.subprocess,'Popen',Process), \
                 patch.object(reader.backup_snapshot,'verify_encrypted_tar') as verify:
                result=reader.capture_audit(session,self.plan['operation'],key,Writer())
                self.assertEqual(result,{'audit_component_captured':True,'complete_backup':False,'safe_to_update':False})
                self.assertEqual(self.label,'audit');self.assertEqual(self.content,b'tar')
                self.assertIn('pod/'+self.plan['reader_name'],self.command)
                self.assertEqual(self.kwargs['pass_fds'],(11,12));verify.assert_called_once()
