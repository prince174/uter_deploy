import copy
import hashlib
import os
import unittest
from unittest.mock import patch

from scripts import audit_backup_evidence as audit, recovery_evidence_experiment as experiment
from tests import test_audit_backup_evidence as fixtures


@unittest.skipUnless(os.name=='posix','fixture journal requires POSIX')
class CombinedRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AuditBackupTests('test_complete_rotations_bind_receipt_and_write_once')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.fixture.make_backup()
        f=self.fixture
        self.args={'home':f.home,'backup':f.backup,'key':f.key,'site':f.site,'resource':f.resource,'recorder':f.rec}
        self.patcher=patch.object(experiment.maintenance_protocol,'verify_capability',return_value=f.product)
        self.patcher.start();self.addCleanup(self.patcher.stop)

    def oracle(self,rdb):
        fp={'schema':1,'digest':'e'*64,'databases':16,'keys':1,'rdb_compared':False,'safe_to_resume':False}
        return {'rdb_sha256':hashlib.sha256(rdb).hexdigest(),'before':fp,'after':dict(fp),'source_again':dict(fp)}

    def capture(self,oracle=None):
        return experiment.capture_redis(**self.args,version='1.0.0',restore_oracle=oracle or self.oracle)

    def audit(self):return self.fixture.verify()

    def combine(self,a=None,r=None,**overrides):
        f=self.fixture
        params={**self.args,'bundle':f.bundle,'publisher':'publisher','instance':'container','boot':f.boot,
                'audit':a or self.audit(),'redis':r or self.capture()}
        params.update(overrides)
        return experiment.combine(**params)

    def resign(self,evidence,purpose):
        evidence['mac']=experiment.sign(self.fixture.key,purpose,evidence['record']);return evidence

    def test_one_authenticated_backup_combines_without_permission(self):
        value=self.combine()
        self.assertIs(value['safe_to_update'],False);self.assertIs(value['safe_to_resume'],False)
        self.assertEqual(value['record']['operation'],self.fixture.op)

    def test_oracle_mismatches_fail_before_evidence(self):
        for field in ('rdb_sha256','before','after','source_again'):
            def wrong(rdb):
                result=self.oracle(rdb)
                if field=='rdb_sha256':result[field]='0'*64
                else:result[field]=dict(result[field],digest='0'*64)
                return result
            with self.subTest(field=field),self.assertRaises(experiment.EvidenceError):self.capture(wrong)

    def test_modified_evidence_or_safe_flag_rejected(self):
        a=self.audit();r=self.capture()
        cases=[(dict(a,mac='0'*64),r),(a,dict(r,mac='0'*64)),
               (dict(a,safe_to_update=True),r),(a,dict(r,safe_to_resume=True)),
               (dict(a,record=dict(a['record'],extra='x')),r)]
        for left,right in cases:
            with self.subTest(left=left,right=right),self.assertRaises(experiment.EvidenceError):self.combine(left,right)

    def test_freshly_authenticated_wrong_identity_or_backup_is_rejected(self):
        a=self.audit();r=self.capture()
        for field in ('operation','backend','site','resource','plan_sha256','backup_id','manifest_sha256',
                      'redis_sha256','redis_plaintext_sha256'):
            changed=copy.deepcopy(r);changed['record'][field]='0'*64
            self.resign(changed,b'redis-recovery-experiment-v1')
            with self.subTest(field=field),self.assertRaises(experiment.EvidenceError):self.combine(a,changed)
        for field in ('boot_id','instance_sha256','audit_sha256','runtime_sha256','bundle_sha256',
                      'guardrail_image','audit_last_hash','audit_last_seq'):
            changed=copy.deepcopy(a);changed['record'][field]='0'*64
            self.resign(changed,b'audit-maintenance-evidence-v1')
            with self.subTest(field=field),self.assertRaises(experiment.EvidenceError):self.combine(changed,r)

    def test_backup_tamper_or_scope_lock_loss_blocks_combination(self):
        a=self.audit();r=self.capture();self.fixture.locked=False
        with self.assertRaises(experiment.EvidenceError):self.combine(a,r)
        self.fixture.locked=True
        path=self.fixture.backup/'audit.enc';raw=bytearray(path.read_bytes());raw[-1]^=1;path.write_bytes(raw)
        with self.assertRaises(experiment.EvidenceError):self.combine(a,r)

    def test_records_from_two_genuine_backups_cannot_be_mixed(self):
        a=self.audit();first=self.fixture.backup
        self.fixture.backup=self.fixture.root/'backup-second';self.fixture.make_backup()
        params=dict(self.args,backup=self.fixture.backup)
        second=experiment.capture_redis(**params,version='1.0.0',restore_oracle=self.oracle)
        self.fixture.backup=first
        with self.assertRaises(experiment.EvidenceError):self.combine(a,second)

    def test_bundle_changed_after_audit_verification_is_rejected(self):
        a=self.audit();r=self.capture()
        (self.fixture.bundle/'checksums.json').write_bytes(b'different fixture')
        with self.assertRaises(experiment.EvidenceError):self.combine(a,r)

    def test_scope_lost_during_redis_oracle_refuses_evidence(self):
        def unlock(rdb):
            result=self.oracle(rdb);self.fixture.locked=False;return result
        with self.assertRaises(experiment.EvidenceError):self.capture(unlock)


if __name__=='__main__':unittest.main()
