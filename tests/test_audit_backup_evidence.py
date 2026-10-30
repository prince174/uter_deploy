import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import audit_backup_evidence as audit, backup_store, maintenance_evidence, redis_fence_journal as journal
from scripts import audit_backup_image_ci as image_ci


def tar(files):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w') as archive:
        for name,content in files.items():
            item=tarfile.TarInfo(name);item.size=len(content);archive.addfile(item,io.BytesIO(content))
    return out.getvalue()


def line(seq=1, previous=None, rotation=None):
    obj={'audit_seq':seq,'audit_prev_hash':previous,'audit_hash':'f'*64,'audit_hmac':'e'*64}
    if rotation is not None:obj['audit_rotation_prev_hash']=rotation
    return json.dumps(obj).encode()+b'\n'


@unittest.skipUnless(os.name=='posix','private journal requires POSIX')
class AuditBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir(mode=0o700)
        self.key=b'k'*32;self.op='a'*32;self.plan='b'*64;self.resource='c'*64;self.boot='d'*32
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}
        journal.create(self.home,backend='compose',site=self.site['name'],resource=self.resource,
                       plan_sha256=self.plan,operation=self.op)
        self.locked=True
        self.rec=maintenance_evidence.Recorder(self.home,self.key,operation=self.op,backend='compose',
                                                plan_sha256=self.plan,lock_guard=lambda:self.locked)
        self.receipt={'protocol':1,'boot_id':self.boot,'state':'quiesced','safe_to_stop':True,
                      'active_requests':0,'error':None,'evidence':{'redis_closed':True,'audit':
                        {'last_seq':1,'last_hash':'f'*64,'fsynced':True,'verified':True}}}
        self.rec.intent('guardrail','container',self.boot)
        self.rec.receipt('guardrail','container',self.boot,self.receipt)
        self.product={'version':'1.0.0','images':{'guardrail':'repo/guardrail@sha256:'+'a'*64}}
        self.bundle=self.root/'bundle';self.bundle.mkdir();(self.bundle/'checksums.json').write_bytes(b'fixture')
        self.backup=self.root/'backup'

    def make_backup(self, files=None, key=b'synthetic-audit-key'):
        writer=backup_store.BackupWriter(self.backup,self.key,self.home,self.site,'1.0.0')
        writer.put('runtime',io.BytesIO(tar({'runtime/audit-hmac-key':key})))
        writer.put('redis',io.BytesIO(b'REDIS fixture'))
        writer.put('audit',io.BytesIO(tar(files or {'audit.jsonl':line()})))
        writer.finish()

    def oracle(self, files, key, image):
        self.assertEqual(key,'synthetic-audit-key');self.assertEqual(image,self.product['images']['guardrail'])
        return {'last_seq':1,'last_hash':'f'*64,'files_verified':len(files),'verified_entries':len(files),
                'segments_verified':1,'hmac_enabled':True,'ignored_trailing_entries':0,
                'ignored_orphan_entries':0,'ignored_malformed_entries':0,'legacy_entries_skipped':0}

    def verify(self, oracle=None, **overrides):
        params={'home':self.home,'backup':self.backup,'key':self.key,'bundle':self.bundle,'publisher':'publisher',
                'recorder':self.rec,'site':self.site,'resource':self.resource,'instance':'container','boot':self.boot,
                'strict_auditor':oracle or self.oracle}
        params.update(overrides)
        with patch.object(audit.maintenance_protocol,'verify_capability',return_value=self.product):
            return audit.verify(**params)

    def test_complete_rotations_bind_receipt_and_write_once(self):
        self.make_backup({'audit/audit.jsonl.2':line(),
                          'audit/audit.jsonl.1':line(rotation='1'*64),
                          'audit/audit.jsonl':line(rotation='2'*64)})
        value=self.verify();self.assertFalse(value['safe_to_update']);self.assertEqual(value['record']['audit_files'],3)
        name=audit.save(value,home=self.home,key=self.key,recorder=self.rec,site=self.site['name'],resource=self.resource)
        self.assertEqual(json.loads((self.home/name).read_text()),value)
        with self.assertRaises(audit.AuditEvidenceError):
            audit.save(value,home=self.home,key=self.key,recorder=self.rec,site=self.site['name'],resource=self.resource)

    def test_missing_oldest_rotation_gaps_unknown_files_and_double_genesis_fail(self):
        bad=[{'audit.jsonl.1':line(rotation='1'*64),'audit.jsonl':line(rotation='2'*64)},
             {'audit.jsonl.2':line(),'audit.jsonl':line(rotation='2'*64)},
             {'audit.jsonl':line(),'other':b'x'},
             {'audit.jsonl':line()+line()}]
        for files in bad:
            with self.subTest(files=tuple(files)),self.assertRaises(ValueError):audit._audit_files(files)

    def test_invalid_oracle_receipt_key_and_changed_scope_refused(self):
        self.make_backup()
        for field,value in (('last_seq',2),('last_hash','0'*64),('files_verified',0),('hmac_enabled',False),
                            ('segments_verified',2),('ignored_trailing_entries',1),('last_seq',True),
                            ('segments_verified',True)):
            def wrong(files,key,image):
                return dict(self.oracle(files,key,image),**{field:value})
            with self.subTest(field=field),self.assertRaises(audit.AuditEvidenceError):self.verify(wrong)
        for params in ({'boot':'0'*32},{'resource':'0'*64},{'key':b'z'*32}):
            with self.subTest(params=params),self.assertRaises(audit.AuditEvidenceError):self.verify(**params)
        def unlock(files,key,image):
            value=self.oracle(files,key,image);self.locked=False;return value
        with self.assertRaises(audit.AuditEvidenceError):self.verify(unlock)

    def test_backup_tampering_and_wrong_audit_key_fail_without_evidence(self):
        self.make_backup(key=b'incorrect')
        with self.assertRaises(audit.AuditEvidenceError):self.verify()
        path=self.backup/'audit.enc';raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        with self.assertRaises(audit.AuditEvidenceError):self.verify()
        self.assertFalse(list(self.home.glob('audit-maintenance-match-*')))

    def test_archive_links_duplicate_and_traversal_fail(self):
        for name in ('../bad','/absolute'):
            with self.subTest(name=name),self.assertRaises(ValueError):audit._files(tar({name:b'x'}))
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for _ in range(2):
                entry=tarfile.TarInfo('audit.jsonl');entry.size=1;archive.addfile(entry,io.BytesIO(b'x'))
        with self.assertRaises(ValueError):audit._files(stream.getvalue())
        for link_type in (tarfile.SYMTYPE,tarfile.LNKTYPE):
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as archive:
                entry=tarfile.TarInfo('audit.jsonl');entry.type=link_type;entry.linkname='elsewhere';archive.addfile(entry)
            with self.subTest(link_type=link_type),self.assertRaises(ValueError):audit._files(stream.getvalue())

    def test_home_key_and_bundle_identity_must_stay_bound(self):
        self.make_backup();other=self.root/'other';other.mkdir()
        with self.assertRaises(audit.AuditEvidenceError):self.verify(home=other)
        other_rec=maintenance_evidence.Recorder(self.home,b'z'*32,operation=self.op,backend='compose',
                                               plan_sha256=self.plan,lock_guard=lambda:True)
        with self.assertRaises(audit.AuditEvidenceError):self.verify(recorder=other_rec)
        def replace(files,key,image):
            (self.bundle/'checksums.json').write_bytes(b'replaced')
            return self.oracle(files,key,image)
        with self.assertRaises(audit.AuditEvidenceError):self.verify(replace)

    def test_image_run_uses_immutable_id_and_bounded_stdout(self):
        class Completed: returncode=0
        calls=[]
        def run(args,**kwargs):
            calls.append((args,kwargs));kwargs['stdout'].write(b'{}');return Completed()
        with patch.object(image_ci.subprocess,'run',side_effect=run), \
             patch.object(image_ci.subprocess,'check_output',return_value=b''):
            self.assertEqual(image_ci.call('pass',{},'sha256:'+'a'*64),{})
        self.assertIn('sha256:'+'a'*64,calls[0][0]);self.assertNotIn(image_ci.IMAGE,calls[0][0])
        self.assertTrue(callable(calls[0][1]['preexec_fn']))
        with patch.object(image_ci.subprocess,'run') as process:
            with self.assertRaises(ValueError):image_ci.call('pass',{},image_ci.IMAGE)
            process.assert_not_called()

    def test_evidence_tamper_or_failed_fsync_does_not_report_success(self):
        self.make_backup();value=self.verify()
        damaged=dict(value,record=dict(value['record'],backup_id='f'*32))
        with self.assertRaises(audit.AuditEvidenceError):
            audit.save(damaged,home=self.home,key=self.key,recorder=self.rec,site=self.site['name'],resource=self.resource)
        with patch.object(audit.os,'fsync',side_effect=OSError):
            with self.assertRaises(audit.AuditEvidenceError):
                audit.save(value,home=self.home,key=self.key,recorder=self.rec,site=self.site['name'],resource=self.resource)
        self.assertEqual(len(list(self.home.glob('audit-maintenance-match-*'))),1)

    def test_image_ci_refuses_before_docker_outside_hosted_runner(self):
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted',
                                   'RUNNER_OS':'Linux'},clear=True), \
             patch.object(image_ci.subprocess,'check_output') as docker:
            with self.assertRaises(ValueError):image_ci.main()
        docker.assert_not_called()


if __name__=='__main__':unittest.main()
