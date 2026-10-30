import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import backup_store, redis_recovery_experiment as recovery, redis_recovery_experiment_ci as ci


class RedisRecoveryExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir()
        self.key=b'k'*32;self.site={'backend':'compose','name':'test','namespace':'test','context':'default'}
        self.backup=self.root/'backup'

    def backup_set(self, rdb=b'REDIS-fixture'):
        writer=backup_store.BackupWriter(self.backup,self.key,self.home,self.site,'1.0.0')
        for name,value in [('runtime',b'fixture'),('audit',b'fixture'),('redis',rdb)]:
            writer.put(name,io.BytesIO(value))
        writer.finish()

    def prepare(self,**kwargs):
        args={'key':self.key,'home':self.home,'site':self.site,'version':'1.0.0'};args.update(kwargs)
        return recovery.prepare(self.backup,**args)

    def test_authenticated_fixture_is_bounded_and_does_not_authorize(self):
        self.backup_set();result=self.prepare()
        self.assertEqual(result['rdb'],b'REDIS-fixture')
        self.assertIs(result['safe_to_update'],False);self.assertIs(result['safe_to_resume'],False)
        with patch.object(recovery,'MAX_RDB_BYTES',6),self.assertRaises(recovery.RecoveryExperimentError):self.prepare()

    def test_rejects_wrong_key_identity_version_and_corruption(self):
        self.backup_set();other=self.root/'other';other.mkdir()
        for args in ({'key':b'x'*32},{'home':other},{'version':'1.0.1'}):
            with self.subTest(args=args),self.assertRaises(recovery.RecoveryExperimentError):self.prepare(**args)
        path=self.backup/'redis.enc';raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        with self.assertRaises(recovery.RecoveryExperimentError):self.prepare()

    def test_invalid_header_and_missing_component_are_rejected(self):
        self.backup_set(b'other fixture')
        with self.assertRaises(recovery.RecoveryExperimentError):self.prepare()

    def test_manifest_and_other_component_corruption_rejected(self):
        self.backup_set()
        for name in ('runtime.enc','audit.enc','manifest.json'):
            path=self.backup/name;original=path.read_bytes()
            if name=='manifest.json':
                item=json.loads(original);item['manifest']['version']='2.0.0';path.write_text(json.dumps(item))
            else:
                damaged=bytearray(original);damaged[-1]^=1;path.write_bytes(damaged)
            with self.subTest(name=name),self.assertRaises(recovery.RecoveryExperimentError):self.prepare()
            path.write_bytes(original)
        (self.backup/'runtime.enc').unlink()
        with self.assertRaises(recovery.RecoveryExperimentError):self.prepare()

    def test_changed_backup_between_checks_is_rejected(self):
        self.backup_set();original=recovery.backup_store.verify_set;count=0
        def changed(*args,**kwargs):
            nonlocal count
            result=original(*args,**kwargs);count+=1
            if count==2:return dict(result,id='0'*32)
            return result
        with patch.object(recovery.backup_store,'verify_set',side_effect=changed):
            with self.assertRaises(recovery.RecoveryExperimentError):self.prepare()

    def test_ci_refuses_non_hosted_before_any_docker(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted',
                                   'RUNNER_OS':'Linux'},clear=True),patch.object(ci,'docker') as docker:
            with self.assertRaises(ValueError):ci.main()
            docker.assert_not_called()

    def test_uncertain_container_cleanup_uses_exact_id_and_label(self):
        identifier='a'*64
        with patch.object(ci,'docker',side_effect=[identifier,'nonce','', '']) as docker:
            ci.cleanup('fixture','nonce',None)
        commands=[entry.args for entry in docker.call_args_list]
        self.assertEqual(commands[1][-1],identifier);self.assertEqual(commands[2][-1],identifier)
        with patch.object(ci,'docker',side_effect=[identifier,'not-ours']) as docker:
            with self.assertRaises(ValueError):ci.cleanup('fixture','nonce',None)
        self.assertEqual(docker.call_count,2)
        with patch.object(ci,'docker',return_value='') as docker:
            with self.assertRaises(ValueError):ci.cleanup('fixture','nonce',None)
        self.assertEqual(docker.call_count,1)

    def test_uncertain_network_cleanup_uses_exact_id_and_label(self):
        identifier='b'*64
        with patch.object(ci,'docker',side_effect=[identifier,'net nonce','','']) as docker:
            ci.cleanup_network('net','nonce',None)
        self.assertEqual(docker.call_args_list[1].args[-1],identifier)
        self.assertEqual(docker.call_args_list[2].args[-1],identifier)
        with patch.object(ci,'docker',side_effect=[identifier,'other nonce']) as docker:
            with self.assertRaises(ValueError):ci.cleanup_network('net','nonce',None)
        self.assertEqual(docker.call_count,2)

    def test_cleanup_continues_after_close_or_container_failure(self):
        class Broken:
            def close(self):raise OSError
        class Fine:
            def close(self):pass
        with patch.object(ci,'cleanup',side_effect=[OSError(),None]) as containers, \
             patch.object(ci,'cleanup_network') as network:
            self.assertFalse(ci.cleanup_all([(Broken(),Fine())],['source','target'],'nonce',
                                            [True,True],['a'*64,'b'*64],True,'net','c'*64))
        self.assertEqual(containers.call_count,2);network.assert_called_once()


if __name__=='__main__':unittest.main()
