import io
import itertools
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import yaml

from scripts import backup_crypto, backup_snapshot, backup_store, recover_kubernetes, restore_backup
import uterctl


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'), 'requires POSIX operation lock')
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)
        self.home=self.root/'home';(self.home/'runtime/policies').mkdir(parents=True);(self.home/'runtime/profiles').mkdir()
        (self.home/'runtime/policies/runtime.toml').write_text('[policy]')
        (self.home/'runtime/profiles/model_profiles.toml').write_text('[profile]')
        (self.home/'runtime/guardrail.env').write_text('secret-data')
        (self.home/'install.json').write_text('{}');(self.home/'install-state.json').write_text('{"status":"ready"}')
        (self.home/'credentials.json').write_text('{"admin":"secret"}')
        (self.home/'releases/1.0.0/compose').mkdir(parents=True)
        (self.home/'releases/1.0.0/compose/compose.yaml').write_text('services: {}')
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}
        self.images={s:f'registry.example/{s}@sha256:'+'a'*64 for s in ('guardrail','agent','redis')}
        self.cfg={'backend':'compose','name':'uter-test','context':'default','port':18000,'guardrail_cpus':2,'images':self.images}
        self.current={'version':'1.0.0','images':self.images};self.key=b'k'*32
        # All real callers hold this lock while capture or resume mutates workloads.
        self.lock=uterctl.locked(self.home);self.lock.__enter__()
        self.addCleanup(self.lock.__exit__,None,None,None)

    def fake_checked(self,args,**kwargs):
        if 'ps' in args:return b'container-id\n'
        return b''

    def test_resume_refuses_any_fence_marker_before_touching_either_backend(self):
        for backend,kind,marker_name in itertools.product(('compose','helm'),('file','dangling_symlink'),
                                                            ('redis-fence-operation.json','compose-fence-finalize-anchor.json','compose-fenced-update-intent.json','compose-fenced-target-start.json','compose-fenced-target-result.json','compose-fenced-cleanup.json')):
            with self.subTest(backend=backend,kind=kind,marker_name=marker_name):
                marker=self.home/marker_name
                if kind=='file':marker.write_text('invalid',encoding='utf-8')
                else:marker.symlink_to(self.home/'missing')
                with patch.object(backup_snapshot,'checked') as checked:
                    with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                        backup_snapshot.resume_writers(self.home,self.cfg,dict(self.site,backend=backend),self.current)
                    checked.assert_not_called()
                marker.unlink()

    def test_snapshot_failure_does_not_resume_if_fence_appears(self):
        marker=self.home/'redis-fence-operation.json'
        def fail_with_marker(*args,**kwargs):
            marker.write_text('incomplete',encoding='utf-8')
            raise RuntimeError('snapshot interrupted')
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), \
             patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as checked, \
             patch.object(backup_snapshot,'process_component',side_effect=fail_with_marker):
            with self.assertRaisesRegex(ValueError,'^REDIS_FENCE_REQUIRES_INSPECTION$'):
                backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertTrue((self.home/'backup-operation.json').exists())
        self.assertTrue(marker.exists())
        self.assertFalse(any('up' in call.args[0] for call in checked.call_args_list))

    def test_unowned_or_unsafe_lock_blocks_capture_and_resume_before_workloads(self):
        for scenario in ('absent','other_pid','dangling_symlink','hardlink','unsafe_mode'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as folder:
                home=Path(folder);sentinel=home/'operation.lock'
                if scenario=='other_pid':sentinel.write_text(str(os.getpid()+1))
                elif scenario=='dangling_symlink':sentinel.symlink_to(home/'missing')
                elif scenario=='hardlink':
                    sentinel.write_text(str(os.getpid()));os.link(sentinel,home/'anchor')
                elif scenario=='unsafe_mode':sentinel.write_text(str(os.getpid()))
                if scenario in ('other_pid','hardlink'):sentinel.chmod(0o600)
                if scenario=='unsafe_mode':sentinel.chmod(0o644)
                with patch.object(backup_snapshot.adopt_installation,'verify_live') as live, \
                     patch.object(backup_snapshot,'checked') as checked:
                    with self.assertRaisesRegex(ValueError,'^BACKUP_LOCK_UNVERIFIED$'):
                        backup_snapshot.capture(home,self.cfg,self.site,self.current,home/'backup',self.key)
                    with self.assertRaisesRegex(ValueError,'^BACKUP_LOCK_UNVERIFIED$'):
                        backup_snapshot.resume_writers(home,self.cfg,self.site,self.current)
                live.assert_not_called();checked.assert_not_called()
                self.assertFalse((home/'backup').exists())

    def test_lost_lock_during_snapshot_preserves_journal_and_stopped_writers(self):
        sentinel=self.home/'operation.lock'
        def fail_after_losing_lock(*args,**kwargs):
            sentinel.write_text(str(os.getpid()+1),encoding='ascii')
            raise RuntimeError('snapshot interrupted')
        try:
            with patch.object(backup_snapshot.adopt_installation,'verify_live'), \
                 patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as checked, \
                 patch.object(backup_snapshot,'process_component',side_effect=fail_after_losing_lock):
                with self.assertRaisesRegex(ValueError,'^BACKUP_LOCK_UNVERIFIED$'):
                    backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
            self.assertTrue((self.home/'backup-operation.json').exists())
            self.assertFalse(any('up' in call.args[0] for call in checked.call_args_list))
        finally:
            sentinel.write_text(str(os.getpid()),encoding='ascii')

    def fake_component(self,writer,label,command,**kwargs):
        if label=='redis': data=b'REDIS-snapshot'
        else:
            buf=io.BytesIO()
            with tarfile.open(fileobj=buf,mode='w') as tar:
                payload=b'audit';info=tarfile.TarInfo('audit.jsonl');info.size=len(payload)
                tar.addfile(info,io.BytesIO(payload))
            data=buf.getvalue()
        writer.put(label,io.BytesIO(data))

    def test_snapshot_is_encrypted_and_restarts_on_success(self):
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as cmd, patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot') as check:
            result=backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertEqual(check.call_args.args[1][-5:], ['exec','-T','redis','redis-check-rdb','/dev/stdin'])
        self.assertEqual(result['version'],'1.0.0')
        store=backup_store.verify_set(self.root/'backup',self.key,home=self.home,site=self.site,version='1.0.0')
        self.assertEqual(set(store['files']),{'runtime','redis','audit'})
        self.assertNotIn(b'secret-data',(self.root/'backup/runtime.enc').read_bytes())
        self.assertFalse((self.home/'backup-operation.json').exists())
        self.assertTrue(any('stop' in c.args[0] for c in cmd.call_args_list))
        self.assertTrue(any('up' in c.args[0] for c in cmd.call_args_list))

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX symlink handling')
    def test_fence_journal_refuses_snapshot_before_workloads_change(self):
        for name in ('redis-fence-operation.json','compose-fence-finalize-anchor.json','compose-fenced-update-intent.json','compose-fenced-target-start.json','compose-fenced-target-result.json','compose-fenced-cleanup.json'):
            with self.subTest(name=name):
                marker=self.home/name;marker.symlink_to(self.home/'missing')
                with patch.object(backup_snapshot.adopt_installation,'verify_live') as live, \
                     patch.object(backup_snapshot,'checked') as checked:
                    with self.assertRaisesRegex(ValueError, '^REDIS_FENCE_REQUIRES_INSPECTION$'):
                        backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
                live.assert_not_called();checked.assert_not_called();marker.unlink()
                self.assertFalse((self.root/'backup').exists())

    def test_optional_ca_bundle_is_preserved_in_encrypted_runtime(self):
        ca = b'example CA bundle content'
        (self.home/'runtime/policies/upstream-ca.pem').write_bytes(ca)
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked), patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot'):
            result=backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        encrypted=self.root/'backup/runtime.enc'
        self.assertNotIn(ca,encrypted.read_bytes())
        plain=io.BytesIO()
        backup_crypto.decrypt_verify(encrypted,self.key,backup_store.aad(result['id'],'runtime'),
                                     result['files']['runtime'],plain)
        plain.seek(0)
        with tarfile.open(fileobj=plain,mode='r:') as archive:
            self.assertEqual(archive.extractfile('runtime/policies/upstream-ca.pem').read(),ca)

    def test_compose_llm_max_tokens_survives_backup_and_recovery_staging(self):
        env = b'UPSTREAM_OPENAI_MAX_TOKENS=64\n'
        (self.home/'runtime/guardrail.env').write_bytes(env)
        keyfile = self.root/'backup-key'; keyfile.write_bytes(self.key); keyfile.chmod(0o600)
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked), patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot'):
            backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertNotIn(env,(self.root/'backup/runtime.enc').read_bytes())
        stage = self.root/'staged'
        restore_backup.prepare_staging(self.root/'backup',keyfile,stage)
        self.assertEqual((stage/'runtime-staged/runtime/guardrail.env').read_bytes(),env)

    def test_kubernetes_llm_max_tokens_survives_live_backup_and_resource_mapping(self):
        self.site['backend']='helm'; self.cfg['backend']='kubernetes'
        values={'useEmbeddedModels':True,'guardrailSecret':'old-g','agentSecret':'old-a',
                'redisSecret':'old-r','policyConfigMap':'old-p','profileConfigMap':'old-m'}
        (self.home/'runtime/values.yaml').write_text(yaml.safe_dump(values))
        mapping=recover_kubernetes.resource_mapping(dict(values),'new-test')
        items=[]
        for name in mapping:
            kind='ConfigMap' if name in ('old-p','old-m') else 'Secret'
            data={'UPSTREAM_OPENAI_MAX_TOKENS':'NjQ='} if name == 'old-g' else {'key':'dmFsdWU='}
            items.append({'kind':kind,'metadata':{'name':name,'namespace':'uter-test'},'data':data})
        for suffix,size in (('redis','2Gi'),('guardrail','10Gi')):
            items.append({'kind':'PersistentVolumeClaim','metadata':{'name':'uter-test-'+suffix,'namespace':'uter-test'},
                          'spec':{'resources':{'requests':{'storage':size}}}})
        cluster=json.dumps({'items':items}).encode()
        def checked(args,**kwargs):
            if 'pods' in args:
                return json.dumps({'items':[{'metadata':{'name':'guard','labels':{'app.kubernetes.io/name':'guardrail'}}}]}).encode()
            if 'hpa' in args: return b'{"items":[]}'
            if 'deployment' in args: return b'{"spec":{"replicas":1}}'
            if 'get' in args: return cluster
            return b''
        keyfile=self.root/'backup-key';keyfile.write_bytes(self.key);keyfile.chmod(0o600)
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=checked), \
             patch.object(backup_snapshot,'wait_no_pods'), patch.object(backup_snapshot,'audit_pod',return_value='audit-reader'), \
             patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot') as check:
            backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertEqual(check.call_args.args[1][-5:], ['-c','redis','--','redis-check-rdb','/dev/stdin'])
        self.assertNotIn(b'UPSTREAM_OPENAI_MAX_TOKENS',(self.root/'backup/kubernetes.enc').read_bytes())
        stage=self.root/'staged'; restore_backup.prepare_staging(self.root/'backup',keyfile,stage)
        saved=json.loads((stage/'kubernetes.json').read_text())['items']
        objects,_=recover_kubernetes.prepare_objects(saved,mapping,'uter-test','new-test')
        guard=next(x for x in objects if x['metadata']['name']=='new-test-guardrail-env')
        self.assertEqual(guard['data']['UPSTREAM_OPENAI_MAX_TOKENS'],'NjQ=')

    def test_failure_restarts_and_never_writes_complete_manifest(self):
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as cmd, patch.object(backup_snapshot,'process_component',side_effect=RuntimeError('failed')):
            with self.assertRaisesRegex(RuntimeError,'failed'):
                backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertTrue(any('up' in c.args[0] for c in cmd.call_args_list))
        self.assertFalse((self.root/'backup/manifest.json').exists())
        self.assertFalse((self.home/'backup-operation.json').exists())

    def test_leave_stopped_keeps_recovery_journal(self):
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as cmd, patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot'):
            backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key,leave_stopped=True)
        self.assertFalse(any('up' in c.args[0] for c in cmd.call_args_list))
        self.assertEqual(uterctl.read(self.home/'backup-operation.json')['phase'],'quiesced')

    def test_invalid_rdb_resumes_writers_and_never_issues_backup(self):
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as cmd, patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot',side_effect=ValueError('invalid RDB')):
            with self.assertRaisesRegex(ValueError,'invalid RDB'):
                backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key,leave_stopped=True)
        self.assertFalse((self.root/'backup/manifest.json').exists())
        self.assertTrue(any('up' in c.args[0] for c in cmd.call_args_list))
        self.assertFalse((self.home/'backup-operation.json').exists())

    def test_rejects_unsafe_encrypted_tar(self):
        writer=backup_store.BackupWriter(self.root/'backup',self.key,self.home,self.site,'1.0.0')
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode='w') as tar:
            info=tarfile.TarInfo('../escape');info.size=1;tar.addfile(info,io.BytesIO(b'x'))
        writer.put('audit',io.BytesIO(buf.getvalue()))
        with self.assertRaisesRegex(ValueError,'Unsafe path'):
            backup_snapshot.verify_encrypted_tar(writer,'audit')

    def test_kubernetes_rejects_unbacked_model_volume(self):
        self.site['backend']='helm';(self.home/'runtime/values.yaml').write_text(yaml.safe_dump({'useEmbeddedModels':False}))
        with self.assertRaisesRegex(ValueError,'External model PVC'):backup_snapshot.kube_objects(self.home,self.site)
