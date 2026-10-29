import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.bundle import build
from scripts import workload_preflight as p


@unittest.skipUnless(os.name == 'posix', 'Linux/POSIX preflight semantics')
class WorkloadPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.key = self.root/'key'
        self.key.write_text('fixture-test-key')
        self.key.chmod(0o600)
        self.args = argparse.Namespace(llm_url='https://litellm.example/v1',
            allow_http_llm=False, llm_model='fixture-model', health_url=None,
            timeout=2, llm_ca_bundle=None, llm_key_file=self.key, state_dir=self.root,
            bundle=self.root/'bundle', publisher_key=self.root/'public.pem', fingerprint='a'*64)

    def operation(self):
        opid, directory = p.create_operation(self.root)
        record = {'schema':1, 'operation_id':opid, 'network':'uter-wp-'+opid,
                  'container':'uter-wp-'+opid, 'daemon_id':'DOCKER-1'}
        p.write_journal(directory, record)
        return directory, record

    def test_journal_is_private_and_contains_no_url_or_key(self):
        directory, record = self.operation()
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory/'journal.json').stat().st_mode & 0o777, 0o600)
        text = (directory/'journal.json').read_text()
        self.assertNotIn('fixture-test-key', text)
        self.assertNotIn('litellm.example', text)
        self.assertEqual(p.read_journal(directory)[1], record)

    def test_state_directory_and_journal_tampering_are_rejected(self):
        unsafe = self.root/'unsafe';unsafe.mkdir();unsafe.chmod(0o755)
        with self.assertRaisesRegex(p.ProbeError, 'PRIVATE_STATE'):
            p.create_operation(unsafe)
        directory, record = self.operation()
        record['network'] = 'another-network'
        p.write_journal(directory, record)
        with self.assertRaisesRegex(p.ProbeError, 'JOURNAL_INVALID'):
            p.read_journal(directory)

    def test_private_directory_rejects_writable_and_symlinked_ancestors(self):
        shared=self.root/'shared';shared.mkdir();shared.chmod(0o777)
        nested=shared/'private';nested.mkdir();nested.chmod(0o700)
        with self.assertRaisesRegex(p.ProbeError,'PRIVATE_STATE'):
            p.secure_directory(nested)
        target=self.root/'target';target.mkdir(mode=0o700)
        (target/'private').mkdir(mode=0o700)
        link=self.root/'alias';link.symlink_to(target,target_is_directory=True)
        with self.assertRaisesRegex(p.ProbeError,'PRIVATE_STATE'):
            p.secure_directory(link/'private')
        with self.assertRaisesRegex(p.ProbeError,'PRIVATE_STATE'):
            p.secure_directory(target/'..'/'target'/'private')

    def test_hardlinked_journal_is_rejected(self):
        directory, _ = self.operation()
        journal=directory/'journal.json'
        other=self.root/'hardlink'
        os.link(journal,other)
        with self.assertRaisesRegex(p.ProbeError,'FILE_INVALID'):
            p.read_journal(directory)

    def test_payload_validates_https_health_origin_and_redacts_error(self):
        payload = json.loads(p.prepare_payload(self.args))
        self.assertEqual(payload['key'], 'fixture-test-key')
        self.assertEqual(payload['health'], 'https://litellm.example/health')
        self.args.health_url = 'https://other.example/health'
        with self.assertRaises(p.ProbeError) as error:
            p.prepare_payload(self.args)
        self.assertNotIn('fixture-test-key', str(error.exception))
        self.args.health_url = None
        self.args.llm_url = 'http://litellm.example/v1'
        with self.assertRaises(p.ProbeError):
            p.prepare_payload(self.args)
        self.args.allow_http_llm = True
        self.assertEqual(json.loads(p.prepare_payload(self.args))['base'],self.args.llm_url)
        self.args.llm_url = 'https://user:password@litellm.example/v1'
        with self.assertRaises(p.ProbeError):
            p.prepare_payload(self.args)

    def test_key_rejects_unsafe_parent_symlinks_hardlinks_and_fifo_before_docker(self):
        bad_parent=self.root/'shared';bad_parent.mkdir(mode=0o700);bad_parent.chmod(0o777)
        bad_key=bad_parent/'key';bad_key.write_text('secret');bad_key.chmod(0o600)
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        leaf_link=self.root/'key-link';leaf_link.symlink_to(self.key)
        hardlink=self.root/'hardlink';os.link(self.key,hardlink)
        fifo=self.root/'fifo';os.mkfifo(fifo,0o600)
        for path in (bad_key, alias/'key', leaf_link, hardlink, fifo):
            with self.subTest(path=path), patch.object(p,'run_docker') as docker:
                self.args.llm_key_file=path
                with self.assertRaisesRegex(p.ProbeError,'KEY_FILE_INVALID'):
                    p.probe(self.args)
                docker.assert_not_called()
        hardlink.unlink()
        if os.geteuid() != 0:
            with patch.object(p.os,'geteuid',return_value=987654):
                with self.assertRaisesRegex(p.ProbeError,'KEY_FILE_INVALID'):
                    p.read_trusted_key(self.key)
        self.key.chmod(0o640);self.args.llm_key_file=self.key
        with self.assertRaisesRegex(p.ProbeError,'KEY_FILE_INVALID'):
            p.prepare_payload(self.args)

    def test_ca_validation_rejects_key_material_and_http(self):
        source=self.root/'invalid-ca.pem'
        source.write_text('-----BEGIN PRIVATE KEY-----\nnot-a-ca\n-----END PRIVATE KEY-----\n')
        self.args.llm_ca_bundle=source
        with self.assertRaises(p.ProbeError):p.prepare_payload(self.args)
        self.args.llm_url='http://litellm.example/v1'
        self.args.allow_http_llm=True
        with self.assertRaises(p.ProbeError):p.prepare_payload(self.args)

    def test_ca_uses_trusted_bytes_and_rejects_unsafe_inputs(self):
        ca=self.root/'ca.pem'
        pem=b'-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n'
        ca.write_bytes(pem);ca.chmod(0o644)
        def validate(data):
            ca.write_bytes(b'changed after read')
            self.assertEqual(data,pem)
            return [object()]
        with patch.object(p.install.x509,'load_pem_x509_certificates',side_effect=validate):
            self.assertEqual(p.read_trusted_ca(ca),pem.decode())
        ca.write_bytes(pem)
        unsafe=self.root/'unsafe-ca';unsafe.mkdir();unsafe.chmod(0o777)
        bad=unsafe/'ca';bad.write_bytes(pem)
        alias=self.root/'ca-parent-link';alias.symlink_to(self.root,target_is_directory=True)
        hard=self.root/'ca-hard';os.link(ca,hard)
        fifo=self.root/'ca-fifo';os.mkfifo(fifo)
        for path in (bad,alias/'ca.pem',hard,fifo):
            with self.subTest(path=path),patch.object(p,'run_docker') as docker:
                self.args.llm_ca_bundle=path
                with self.assertRaisesRegex(p.ProbeError,'CA_FILE_INVALID'):
                    p.probe(self.args)
                docker.assert_not_called()
        hard.unlink();ca.chmod(0o666)
        with self.assertRaisesRegex(p.ProbeError,'CA_FILE_INVALID'):
            p.read_trusted_ca(ca)

    def test_signed_image_requires_fingerprint_and_signature(self):
        key=Ed25519PrivateKey.generate()
        private=self.root/'private.pem';public=self.root/'public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        images={name:'registry.example/'+name+'@sha256:'+'a'*64 for name in ('guardrail','agent','redis')}
        config_id='sha256:'+'b'*64
        manifest={'schema':1,'config_schema':1,'status':'released','version':'1.0.0','source_commit':'b'*40,
                  'data_epoch':1,'upgrade_from':[],'images':images,
                  'image_config_ids':{name:config_id for name in images}}
        source=self.root/'manifest.json';source.write_text(json.dumps(manifest));bundle=self.root/'bundle'
        build(source,bundle,private)
        fingerprint=hashlib.sha256(public.read_bytes()).hexdigest()
        self.assertEqual(p.signed_image(bundle,public,fingerprint,self.root),(images['guardrail'],config_id))
        original_verify=p.uterctl.verify
        def verify_after_source_mutation(snapshot, trusted):
            self.assertNotEqual(Path(snapshot), bundle)
            (bundle/'manifest.json').write_text('{"tampered":true}')
            return original_verify(snapshot,trusted)
        with patch.object(p.uterctl,'verify',side_effect=verify_after_source_mutation):
            self.assertEqual(p.signed_image(bundle,public,fingerprint,self.root),(images['guardrail'],config_id))
        with self.assertRaisesRegex(p.ProbeError,'FINGERPRINT_MISMATCH'):
            p.signed_image(bundle,public,'0'*64,self.root)
        (bundle/'compose/compose.yaml').write_text('tampered')
        with self.assertRaisesRegex(p.ProbeError,'SIGNED_BUNDLE_INVALID'):
            p.signed_image(bundle,public,fingerprint,self.root)

    def test_snapshot_isolated_and_rejects_symlink_or_excess_size(self):
        source=self.root/'source';source.mkdir()
        (source/'manifest.json').write_text('original')
        snapshot=self.root/'snapshot';snapshot.mkdir()
        p.snapshot_bundle(source,snapshot)
        (source/'manifest.json').write_text('tampered')
        self.assertEqual((snapshot/'manifest.json').read_text(),'original')
        (source/'link').symlink_to(source/'manifest.json')
        other=self.root/'other';other.mkdir()
        with self.assertRaisesRegex(p.ProbeError,'SIGNED_BUNDLE_INVALID'):
            p.snapshot_bundle(source,other)
        (source/'link').unlink()
        another=self.root/'another';another.mkdir()
        with patch.object(p,'MAX_BUNDLE_BYTES',2):
            with self.assertRaisesRegex(p.ProbeError,'SIGNED_BUNDLE_INVALID'):
                p.snapshot_bundle(source,another)

    def test_docker_binary_requires_trusted_path_and_never_passes_search_path(self):
        path=self.fake_docker('pass\n')
        binary=self.root/'bin'/'docker'
        with patch.dict(os.environ,{'PATH':path}):
            self.assertEqual(p.trusted_docker(),str(binary))
            self.assertEqual(p.docker_environment(self.root)['PATH'],'/usr/bin')
            binary.parent.chmod(0o777)
            with self.assertRaisesRegex(p.ProbeError,'DOCKER_BINARY_UNTRUSTED'):
                p.trusted_docker()

    def test_docker_trusted_symlink_returns_checked_target_and_rejects_unsafe_target(self):
        links=self.root/'links';links.mkdir(mode=0o700)
        targets=self.root/'targets';targets.mkdir(mode=0o700)
        target=targets/'real';target.write_text('#!/bin/sh\n');target.chmod(0o700)
        (links/'docker').symlink_to('../targets/real')
        with patch.dict(os.environ,{'PATH':str(links)}):
            self.assertEqual(p.trusted_docker(),str(target))
            targets.chmod(0o777)
            with self.assertRaisesRegex(p.ProbeError,'DOCKER_BINARY_UNTRUSTED'):
                p.trusted_docker()

    def test_local_image_inspection_requires_exact_digest_and_architecture(self):
        ref='registry.example/guardrail@sha256:'+'a'*64
        config_id='sha256:'+'b'*64
        def inspect(record):
            return subprocess.CompletedProcess([],0,json.dumps([record]).encode(),b'')
        good={'RepoDigests':[ref],'Id':'sha256:'+'b'*64,'Os':'linux','Architecture':'amd64'}
        with patch.object(p,'run_docker',return_value=inspect(good)):
            p.verify_local_image(self.root,ref,config_id)
        descriptor={'RepoDigests':[],'Id':'sha256:'+'a'*64,'Descriptor':{'digest':'sha256:'+'a'*64},
                    'Os':'linux','Architecture':'amd64'}
        with patch.object(p,'run_docker',return_value=inspect(descriptor)):
            p.verify_local_image(self.root,ref,config_id)
        for bad in [dict(good,Architecture='arm64'),dict(good,RepoDigests=['registry.example/other@sha256:'+'a'*64]),
                    dict(descriptor,Descriptor={'digest':'sha256:'+'b'*64}),
                    dict(good,Id='sha256:'+'c'*64)]:
            with self.subTest(bad=bad),patch.object(p,'run_docker',return_value=inspect(bad)):
                with self.assertRaisesRegex(p.ProbeError,'NOT_AVAILABLE_LOCALLY'):
                    p.verify_local_image(self.root,ref,config_id)
        with patch.object(p,'run_docker',return_value=inspect(good)):
            with self.assertRaisesRegex(p.ProbeError,'NOT_AVAILABLE_LOCALLY'):
                p.verify_local_image(self.root,ref,None)
        with patch.object(p,'run_docker',return_value=inspect(descriptor)):
            p.verify_local_image(self.root,ref,None)

    def fake_docker(self, code):
        directory = self.root/'bin';directory.mkdir(exist_ok=True)
        path = directory/'docker'
        path.write_text('#!/usr/bin/env python3\n'+code)
        path.chmod(0o700)
        return str(directory)+os.pathsep+os.environ.get('PATH','')

    def record(self):
        opid='a'*32
        return {'operation_id':opid, 'container':'uter-wp-'+opid, 'network':'uter-wp-'+opid}

    def test_key_is_transmitted_only_via_stdin_and_report_is_bounded(self):
        fake = '''import json,os,sys
if 'fixture-test-key' in repr(sys.argv) or 'fixture-test-key' in repr(dict(os.environ)):
    raise SystemExit(3)
for flag in ('--rm','--read-only','--cap-drop','--pids-limit','--memory','--cpus'):
    if flag not in sys.argv:raise SystemExit(5)
if sys.argv[sys.argv.index('--network')+1] != 'b'*64:raise SystemExit(6)
if sys.argv[sys.argv.index('--pull')+1] != 'never':raise SystemExit(7)
if sys.argv[sys.argv.index('--user')+1] != '10001:10001':raise SystemExit(8)
if sys.argv[sys.argv.index('--cap-drop')+1] != 'ALL':raise SystemExit(9)
payload=json.load(sys.stdin)
if payload.get('key')!='fixture-test-key':raise SystemExit(4)
print(json.dumps({'result':'pass','code':'COMPLETION_RECEIVED'}))
'''
        path = self.fake_docker(fake)
        with patch.dict(os.environ, {'PATH':path,'USER_SECRET':'fixture-test-key','HTTP_PROXY':'fixture-test-key'}):
            result = p.run_container(self.root, self.record(), 'b'*64,
                'registry.example/guardrail@sha256:'+'c'*64,
                p.prepare_payload(self.args), timeout=5, child_timeout=2)
        self.assertEqual(result,{'result':'pass','code':'COMPLETION_RECEIVED'})

    def test_untrusted_output_cannot_exfiltrate_key_through_report(self):
        path = self.fake_docker("import json,sys\nsys.stdin.read()\nprint(json.dumps({'result':'fail','code':'FIXTURE_TEST_KEY'}))\n")
        with patch.dict(os.environ, {'PATH':path}):
            with self.assertRaisesRegex(p.ProbeError, 'WORKLOAD_RESPONSE_INVALID') as error:
                p.run_container(self.root, self.record(), 'b'*64,
                    'registry.example/guardrail@sha256:'+'c'*64,
                    p.prepare_payload(self.args), timeout=5, child_timeout=2)
        self.assertNotIn('FIXTURE_TEST_KEY',str(error.exception))

    def test_output_limit_and_timeout_stop_only_the_fake_subprocess(self):
        for code, expected in [("import sys\nsys.stdin.read()\nsys.stdout.write('X'*10000)\nsys.stdout.flush()\n", 'OUTPUT_TOO_LARGE'),
                               ("import time\ntime.sleep(10)\n", 'WORKLOAD_TIMEOUT')]:
            with self.subTest(expected=expected):
                path = self.fake_docker(code)
                started=time.monotonic()
                with patch.dict(os.environ, {'PATH':path}):
                    with self.assertRaisesRegex(p.ProbeError, expected):
                        p.run_container(self.root, self.record(), 'b'*64,
                            'registry.example/guardrail@sha256:'+'c'*64,
                            p.prepare_payload(self.args), timeout=0.5, child_timeout=1)
                self.assertLess(time.monotonic()-started,5)

    def test_docker_control_output_is_bounded_and_stderr_is_discarded(self):
        path=self.fake_docker("import sys\nsys.stdout.write('X'*(1024*1024+1))\nsys.stdout.flush()\n")
        with patch.dict(os.environ,{'PATH':path}):
            with self.assertRaisesRegex(p.ProbeError,'DOCKER_OUTPUT_TOO_LARGE'):
                p.run_docker(self.root,['info'],timeout=5)
        path=self.fake_docker("import sys\nsys.stderr.write('s'*(1024*1024))\nprint('ok')\n")
        with patch.dict(os.environ,{'PATH':path}):
            result=p.run_docker(self.root,['info'],timeout=5)
        self.assertEqual(result.stdout,b'ok\n')
        self.assertEqual(result.stderr,b'')

    def test_cleanup_deletes_only_exact_labelled_objects(self):
        directory, record = self.operation()
        ids = {'container':'a'*64, 'network':'b'*64}
        alive = dict(ids)
        removed=[]
        def docker(config, args, **kwargs):
            kind, action = args[:2]
            if action=='ls':
                return subprocess.CompletedProcess([],0,(alive.get(kind,'')+'\n').encode(),b'')
            if action=='inspect':
                data={'Name':record[kind], 'Labels':{p.LABEL:record['operation_id']},'Containers':{}}
                if kind=='container':data['Config']={'Labels':data.pop('Labels')}
                return subprocess.CompletedProcess([],0,json.dumps([data]).encode(),b'')
            if action=='rm':
                removed.append((kind,args[-1]));alive.pop(kind)
                return subprocess.CompletedProcess([],0,b'',b'')
            raise AssertionError(args)
        with patch.object(p,'daemon_identity',return_value=record['daemon_id']),patch.object(p,'run_docker',side_effect=docker):
            p.cleanup_operation(directory)
        self.assertEqual(removed,[('container',ids['container']),('network',ids['network'])])
        self.assertFalse(directory.exists())

    def test_cleanup_rejects_modified_docker_config_before_contacting_daemon(self):
        directory, _ = self.operation()
        config = directory/'docker-config'/'config.json'
        config.write_text('{"credsStore":"hostile"}\n')
        with patch.object(p, 'daemon_identity') as daemon, patch.object(p, 'run_docker') as docker:
            with self.assertRaises(p.ProbeError):
                p.cleanup_operation(directory)
            daemon.assert_not_called()
            docker.assert_not_called()
        self.assertTrue((directory/'journal.json').exists())

    def test_cleanup_refuses_mismatched_daemon_or_foreign_network(self):
        directory, record = self.operation()
        with patch.object(p,'daemon_identity',return_value='OTHER'),patch.object(p,'run_docker') as docker:
            with self.assertRaisesRegex(p.ProbeError,'DAEMON_CHANGED'):
                p.cleanup_operation(directory)
            docker.assert_not_called()
        def docker(config,args,**kwargs):
            if args[:2]==['container','ls']:return subprocess.CompletedProcess([],0,b'',b'')
            if args[:2]==['network','ls']:return subprocess.CompletedProcess([],0,(('b'*64)+'\n').encode(),b'')
            if args[:2]==['network','inspect']:
                return subprocess.CompletedProcess([],0,json.dumps([{'Name':record['network'],
                    'Labels':{p.LABEL:record['operation_id']},'Containers':{'foreign':{}}}]).encode(),b'')
            raise AssertionError('unexpected removal')
        with patch.object(p,'daemon_identity',return_value=record['daemon_id']),patch.object(p,'run_docker',side_effect=docker):
            with self.assertRaisesRegex(p.ProbeError,'UNRELATED_ATTACHMENTS'):
                p.cleanup_operation(directory)
        self.assertTrue((directory/'journal.json').exists())

    def test_interruption_cleans_owned_resources_but_keeps_recovery_journal(self):
        token='a'*32
        network='b'*64
        container='c'*64
        alive={'network':network,'container':container}
        removed=[]
        def docker(config,args,**kwargs):
            if args[:2]==['network','create']:
                return subprocess.CompletedProcess([],0,(network+'\n').encode(),b'')
            kind,action=args[:2]
            if action=='ls':return subprocess.CompletedProcess([],0,(alive.get(kind,'')+'\n').encode(),b'')
            if action=='inspect':
                obj={'Name':'uter-wp-'+token,'Labels':{p.LABEL:token},'Containers':{}}
                if kind=='container':obj['Config']={'Labels':obj.pop('Labels')}
                return subprocess.CompletedProcess([],0,json.dumps([obj]).encode(),b'')
            if action=='rm':
                removed.append((kind,args[-1]));alive.pop(kind,None)
                return subprocess.CompletedProcess([],0,b'',b'')
            raise AssertionError(args)
        with patch.object(p.secrets,'token_hex',side_effect=lambda n:'a'*(n*2)), \
             patch.object(p,'signed_image',return_value=('registry.example/g@sha256:'+'d'*64,'sha256:'+'e'*64)), \
             patch.object(p,'daemon_identity',return_value='DOCKER-1'),patch.object(p,'verify_local_image'), \
             patch.object(p,'run_docker',side_effect=docker), \
             patch.object(p,'run_container',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):p.probe(self.args)
            directory=self.root/token
            self.assertTrue((directory/'journal.json').exists())
            journal=(directory/'journal.json').read_text()
            self.assertNotIn('fixture-test-key',journal)
            self.assertEqual(removed,[('container',container),('network',network)])
            p.cleanup_operation(directory)
            self.assertFalse(directory.exists())

    def test_child_program_is_valid_python(self):
        compile(p.CHILD_CODE, '<guardrail-workload-probe>', 'exec')
        self.assertIn('ProxyHandler({})',p.CHILD_CODE)
        self.assertIn('NoRedirect()',p.CHILD_CODE)

    def test_child_runs_health_and_completion_without_echoing_response_or_key(self):
        class Response:
            status=200
            headers={'Content-Encoding':'identity'}
            def __init__(self,body):self.body=body
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps(self.body).encode()
        class Client:
            def __init__(self):self.calls=[]
            def open(self,req,timeout):
                self.calls.append((req.full_url,req.get_header('Authorization')))
                if req.full_url.endswith('/health'):return Response({'healthy_count':1})
                return Response({'choices':[{'message':{'content':'fixture-test-key should remain private'}}]})
        client=Client()
        payload=json.loads(p.prepare_payload(self.args))
        stdin=io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()),encoding='utf-8')
        output=io.StringIO()
        with patch.object(sys,'stdin',stdin),patch.object(sys,'stdout',output),patch.object(sys,'argv',['-c','10']), \
             patch('signal.signal'),patch('signal.alarm'),patch('urllib.request.build_opener',return_value=client):
            exec(compile(p.CHILD_CODE,'<guardrail-workload-probe>','exec'),{})
        self.assertEqual(json.loads(output.getvalue()),{'result':'pass','code':'COMPLETION_RECEIVED'})
        self.assertNotIn('fixture-test-key',output.getvalue())
        self.assertEqual(client.calls,[('https://litellm.example/health','Bearer fixture-test-key'),
                                       ('https://litellm.example/v1/chat/completions','Bearer fixture-test-key')])

    def test_child_rejects_redirect_without_echoing_location_or_key(self):
        from urllib.error import HTTPError
        class Client:
            def open(self,req,timeout):
                raise HTTPError(req.full_url,302,'Found',{'Location':'https://attacker.invalid/fixture-test-key'},io.BytesIO())
        payload=json.loads(p.prepare_payload(self.args))
        stdin=io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()),encoding='utf-8')
        output=io.StringIO()
        with patch.object(sys,'stdin',stdin),patch.object(sys,'stdout',output),patch.object(sys,'argv',['-c','10']), \
             patch('signal.signal'),patch('signal.alarm'),patch('urllib.request.build_opener',return_value=Client()):
            with self.assertRaises(SystemExit):exec(compile(p.CHILD_CODE,'<guardrail-workload-probe>','exec'),{})
        self.assertEqual(json.loads(output.getvalue()),{'result':'fail','code':'REDIRECT_BLOCKED'})
        self.assertNotIn('fixture-test-key',output.getvalue())

    def test_real_sigterm_cleans_only_fake_docker_resources_and_keeps_journal(self):
        key=Ed25519PrivateKey.generate()
        private=self.root/'private.pem';public=self.root/'public.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        images={name:'registry.example/'+name+'@sha256:'+'a'*64 for name in ('guardrail','agent','redis')}
        manifest={'schema':1,'config_schema':1,'status':'released','version':'1.0.0','source_commit':'b'*40,
                  'data_epoch':1,'upgrade_from':[],'images':images}
        source=self.root/'manifest.json';source.write_text(json.dumps(manifest));bundle=self.root/'bundle'
        build(source,bundle,private)
        fingerprint=hashlib.sha256(public.read_bytes()).hexdigest()
        state=self.root/'fake-state';state.mkdir()
        fake = '''import json,sys,time
from pathlib import Path
state=Path(STATE)
args=sys.argv[1:]
cmd=args[args.index('--context')+2:]
net=state/'network.json';container=state/'container.json'
if cmd[:2]==['context','inspect']:
 print(json.dumps([{'Endpoints':{'docker':{'Host':'unix:///tmp/fake.sock'}}}]))
elif cmd[:1]==['info']:
 print('TEST-DAEMON')
elif cmd[:2]==['image','inspect']:
 digest=cmd[-1].split('@')[-1]
 print(json.dumps([{'RepoDigests':[cmd[-1]],'Id':digest,'Descriptor':{'digest':digest},'Os':'linux','Architecture':'amd64'}]))
elif cmd[:2]==['network','create']:
 opid=cmd[cmd.index('--label')+1].split('=',1)[1]
 net.write_text(json.dumps({'Name':cmd[-1],'Labels':{'uter.workload-preflight.id':opid},'Containers':{}}))
 print('b'*64)
elif cmd[0] in ('network','container') and cmd[1]=='ls':
 f=net if cmd[0]=='network' else container
 if f.exists():print(('b' if cmd[0]=='network' else 'c')*64)
elif cmd[0] in ('network','container') and cmd[1]=='inspect':
 f=net if cmd[0]=='network' else container
 print(json.dumps([json.loads(f.read_text())]))
elif cmd[0] in ('network','container') and cmd[1]=='rm':
 f=net if cmd[0]=='network' else container
 f.unlink()
elif cmd[0]=='run':
 opid=cmd[cmd.index('--label')+1].split('=',1)[1]
 payload=json.load(sys.stdin)
 if payload['key']!='fixture-test-key':raise SystemExit(4)
 container.write_text(json.dumps({'Name':cmd[cmd.index('--name')+1],
                    'Config':{'Labels':{'uter.workload-preflight.id':opid}}}))
 (state/'running').write_text('ready')
 time.sleep(30)
else:raise SystemExit(6)
'''
        path=self.fake_docker('STATE = '+repr(str(state))+'\n'+fake)
        script=p.ROOT/'scripts/workload_preflight.py'
        cmd=[sys.executable,str(script),'probe','--bundle',str(bundle),'--publisher-key',str(public),
             '--fingerprint',fingerprint,'--state-dir',str(self.root),'--llm-url',self.args.llm_url,
             '--llm-model',self.args.llm_model,'--llm-key-file',str(self.key),'--timeout','5']
        env={'PATH':path,'HOME':str(self.root),'LANG':'C','PYTHONDONTWRITEBYTECODE':'1'}
        process=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+10
            while not (state/'running').exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(0.05)
            self.assertTrue((state/'running').exists(),'fake Docker workload failed to start')
            process.terminate()
            stdout,stderr=process.communicate(timeout=10)
            self.assertEqual(process.returncode,1)
            self.assertNotIn(b'fixture-test-key',stdout+stderr)
            self.assertFalse((state/'container.json').exists())
            self.assertFalse((state/'network.json').exists())
            journals=list(self.root.glob('*/journal.json'))
            self.assertEqual(len(journals),1)
            self.assertNotIn('fixture-test-key',journals[0].read_text())
        finally:
            if process.poll() is None:
                process.kill();process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
