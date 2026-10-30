import io
import hashlib
import os
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_loopback_snapshot as snapshot


class SnapshotExecutorTests(unittest.TestCase):
    def setUp(self):
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2,'kubectl_sha256':'d'*64},
            _inner=SimpleNamespace(config_fd=13,api=SimpleNamespace(binary_fd=19,binary_sha256='d'*64)),
            config_sha256='a'*64,site='uter-test',api=SimpleNamespace(context='test'))
        self.pod='uter-test-redis-a1b2c3-d4e5f';self.uid='11111111-1111-1111-1111-111111111111'
        self.observed={'uid':self.uid,'container_id':'containerd://'+'b'*64,'pod_spec_sha256':'c'*64,'replicaset_uid':self.uid}
        class Process:
            def __init__(inner,*args,**kwargs):
                self.command=args[0];self.kwargs=kwargs;inner.stdout=io.BytesIO(b'REDIS0009-data')
            def poll(inner):return 0
            def wait(inner,timeout=None):return 0
            def kill(inner):pass
        self.process=Process
        class Writer:
            def put(inner,label,stream):self.label=label;self.raw=stream.read(1024)
        self.writer=Writer()

    def capture(self):return snapshot.capture_component(self.session,'a'*32,self.pod,self.uid,self.writer)

    def test_exact_pod_sealed_fd_and_encrypted_writer_are_used(self):
        with patch.object(snapshot,'_observe',return_value=self.observed), \
             patch.object(snapshot.sealed,'verify_sealed') as seal, \
             patch.object(snapshot.kubectl_binary,'verify'), \
             patch.object(snapshot.subprocess,'Popen',self.process):
            result=self.capture()
        self.assertEqual(result,{'redis_component_captured':True,'complete_backup':False,'safe_to_update':False})
        self.assertEqual(self.label,'redis');self.assertEqual(self.raw,b'REDIS')
        self.assertIn('pod/'+self.pod,self.command);self.assertIn('--kubeconfig=/proc/self/fd/13',self.command)
        self.assertEqual(self.kwargs['pass_fds'],(13,19));seal.assert_called_once_with(13,'a'*64)
        self.assertEqual(self.command[0],'/proc/self/fd/19')
        self.assertEqual(self.kwargs['env'],{'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C'})

    def test_changed_identity_or_unsigned_executor_is_never_accepted(self):
        changed=dict(self.observed,container_id='changed')
        with patch.object(snapshot,'_observe',side_effect=[self.observed,changed]), \
             patch.object(snapshot.sealed,'verify_sealed'),patch.object(snapshot.kubectl_binary,'verify'), \
             patch.object(snapshot.subprocess,'Popen',self.process):
            with self.assertRaises(snapshot.SnapshotError):self.capture()
        self.session._executor=None
        with self.assertRaises(snapshot.SnapshotError):self.capture()

    def test_cleanup_timeout_preserves_primary_failure_and_invalidates_success(self):
        class Process(self.process):
            def __init__(inner,*args,**kwargs):super().__init__(*args,**kwargs);inner.waits=0
            def wait(inner,timeout=None):
                inner.waits+=1
                if inner.waits==1:return 0
                raise subprocess.TimeoutExpired('kubectl',timeout)
        for changed,code in ((True,'KUBE_LOOPBACK_SNAPSHOT_UNVERIFIED'),
                             (False,'KUBE_LOOPBACK_SNAPSHOT_CLEANUP_UNVERIFIED')):
            after=dict(self.observed,container_id='changed') if changed else self.observed
            with self.subTest(changed=changed),patch.object(snapshot,'_observe',side_effect=[self.observed,after]), \
                 patch.object(snapshot.sealed,'verify_sealed'),patch.object(snapshot.kubectl_binary,'verify'), \
                 patch.object(snapshot.subprocess,'Popen',Process):
                with self.assertRaisesRegex(snapshot.SnapshotError,code):self.capture()

    def test_checker_uses_same_sealed_identity_and_fd(self):
        class Checker:
            def __init__(inner,command,**kwargs):self.command=command;self.kwargs=kwargs;inner.stdin=io.BytesIO()
            def poll(inner):return 0
            def wait(inner,timeout=None):return 0
            def kill(inner):pass
        writer=SimpleNamespace(path=Path('/unused'),key=b'k'*32,
                               manifest={'id':'a'*32,'files':{'redis':{'plaintext_bytes':5}}})
        def decrypt(path,key,aad,meta,sink):sink.write(b'REDIS')
        with patch.object(snapshot,'_observe',return_value=self.observed), \
             patch.object(snapshot.sealed,'verify_sealed'),patch.object(snapshot.kubectl_binary,'verify'), \
             patch.object(snapshot.subprocess,'Popen',Checker),patch.object(snapshot.backup_crypto,'decrypt_verify',side_effect=decrypt):
            self.assertEqual(snapshot.verify_component(self.session,'a'*32,self.pod,self.uid,writer),
                {'redis_component_verified':True,'complete_backup':False,'safe_to_update':False})
            self.assertEqual(self.kwargs['pass_fds'],(13,19))
            self.assertIn('redis-check-rdb',self.command)

    def test_actual_bind_must_be_loopback_and_identity_unchanged(self):
        from scripts import kubernetes_audit_reader as audit
        with patch.object(snapshot,'_observe',return_value=self.observed), \
             patch.object(snapshot.sealed,'verify_sealed'),patch.object(snapshot.kubectl_binary,'verify'), \
             patch.object(audit,'_call_input',return_value=b'bind\n127.0.0.1\n'):
            self.assertEqual(snapshot.assert_loopback(self.session,'a'*32,self.pod,self.uid),
                {'loopback_bind_observed':True,'redis_isolated':False,'safe_to_update':False})
        with patch.object(snapshot,'_observe',return_value=self.observed), \
             patch.object(snapshot.sealed,'verify_sealed'),patch.object(snapshot.kubectl_binary,'verify'), \
             patch.object(audit,'_call_input',return_value=b'bind\n0.0.0.0\n'):
            with self.assertRaises(snapshot.SnapshotError):snapshot.assert_loopback(self.session,'a'*32,self.pod,self.uid)

    @unittest.skipUnless(os.name=='posix' and os.path.isfile('/usr/bin/true'),'trusted Linux executable required')
    def test_binary_path_and_hash_are_checked_independent_of_path_and_proxy(self):
        binary=Path('/usr/bin/true').resolve()
        digest=hashlib.sha256(binary.read_bytes()).hexdigest()
        with patch.dict(os.environ,{'PATH':'/attacker','HTTPS_PROXY':'http://attacker','KUBECTL_PLUGIN':'evil'}):
            fd=snapshot.kubectl_binary.open_binary(binary,digest)
            os.close(fd)
            with self.assertRaises(ValueError):snapshot.kubectl_binary.open_binary(binary,'0'*64)
            with self.assertRaises(ValueError):snapshot.kubectl_binary.open_binary('true',digest)
