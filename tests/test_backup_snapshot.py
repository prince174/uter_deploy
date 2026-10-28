import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import yaml

from scripts import backup_snapshot, backup_store
import uterctl


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

    def fake_checked(self,args,**kwargs):
        if 'ps' in args:return b'container-id\n'
        return b''

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
        with patch.object(backup_snapshot.adopt_installation,'verify_live'), patch.object(backup_snapshot,'checked',side_effect=self.fake_checked) as cmd, patch.object(backup_snapshot,'process_component',side_effect=self.fake_component), patch.object(backup_snapshot,'verify_redis_snapshot'):
            result=backup_snapshot.capture(self.home,self.cfg,self.site,self.current,self.root/'backup',self.key)
        self.assertEqual(result['version'],'1.0.0')
        store=backup_store.verify_set(self.root/'backup',self.key,home=self.home,site=self.site,version='1.0.0')
        self.assertEqual(set(store['files']),{'runtime','redis','audit'})
        self.assertNotIn(b'secret-data',(self.root/'backup/runtime.enc').read_bytes())
        self.assertFalse((self.home/'backup-operation.json').exists())
        self.assertTrue(any('stop' in c.args[0] for c in cmd.call_args_list))
        self.assertTrue(any('up' in c.args[0] for c in cmd.call_args_list))

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
