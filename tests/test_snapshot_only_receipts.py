import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import snapshot_only_receipts as records


@unittest.skipUnless(os.name=='posix','POSIX exclusive link and fsync required')
class SnapshotOnlyRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.key=b'k'*32
        self.descriptor={'schema':1,'operation':'a'*32,'backend':'compose','site':'uter',
                         'resource':'b'*64,'release_version':'0.1.6','bundle_sha256':'c'*64,
                         'fence_checkpoint_sha256':'d'*64,'identity_sha256':'e'*64,
                         'backup_id':'f'*32,'backup_location_sha256':'1'*64,'executor_sha256':'2'*64}

    def receipt(self,digest):
        return {'schema':1,'operation':self.descriptor['operation'],'descriptor_sha256':digest,
                'backup_id':self.descriptor['backup_id'],'manifest_sha256':'3'*64}

    def prepare(self):
        digest=records.write_descriptor(self.home,self.key,self.descriptor)
        receipt=self.receipt(digest)
        receipt_digest=records.write_receipt(self.home,self.key,receipt)
        return digest,receipt,receipt_digest

    def test_round_trip_release_and_mutation_are_mutually_exclusive(self):
        digest,receipt,receipt_digest=self.prepare()
        self.assertEqual(records.read_descriptor(self.home,self.key),(self.descriptor,digest))
        self.assertEqual(records.read_receipt(self.home,self.key),(receipt,receipt_digest))
        decision_digest=records.write_decision(self.home,self.key,'release')
        decision,observed=records.read_decision(self.home,self.key)
        self.assertEqual(observed,decision_digest);self.assertEqual(decision['action'],'release')
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'mutation')
        self.assertEqual(records.read_decision(self.home,self.key)[0]['action'],'release')

    def test_decision_requires_bound_descriptor_receipt_and_key(self):
        digest=records.write_descriptor(self.home,self.key,self.descriptor)
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'mutation')
        for receipt in ({**self.receipt(digest),'operation':'9'*32},
                        {**self.receipt(digest),'backup_id':'8'*32},
                        {**self.receipt(digest),'descriptor_sha256':'7'*64}):
            with self.subTest(receipt=receipt):
                with self.assertRaisesRegex(records.SnapshotRecordError,'BINDING'):
                    records.write_receipt(self.home,self.key,receipt)
                self.assertFalse((self.home/records.RECEIPT).exists())
        records.write_receipt(self.home,self.key,self.receipt(digest))
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,b'x'*32,'mutation')
        self.assertFalse((self.home/records.DECISION).exists())

    def test_mutation_branch_can_never_be_replaced_by_release(self):
        self.prepare();records.write_decision(self.home,self.key,'mutation')
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'release')
        self.assertEqual(records.read_decision(self.home,self.key)[0]['action'],'mutation')

    def test_tampering_and_record_replay_are_rejected(self):
        self.prepare();records.write_decision(self.home,self.key,'release')
        path=self.home/records.RECEIPT;envelope=json.loads(path.read_text())
        envelope['record']['manifest_sha256']='4'*64;path.write_text(json.dumps(envelope))
        with self.assertRaises(records.SnapshotRecordError):records.read_decision(self.home,self.key)
        # A valid envelope of the wrong type cannot be replayed as a decision.
        path=self.home/records.DECISION
        path.write_bytes((self.home/records.DESCRIPTOR).read_bytes())
        with self.assertRaises(records.SnapshotRecordError):records.read_decision(self.home,self.key)

    def test_symlink_hardlink_permissions_and_duplicate_json_fail_closed(self):
        digest=records.write_descriptor(self.home,self.key,self.descriptor)
        path=self.home/records.RECEIPT
        path.symlink_to(self.home/'absent')
        with self.assertRaises(records.SnapshotRecordError):records.write_receipt(self.home,self.key,self.receipt(digest))
        path.unlink();records.write_receipt(self.home,self.key,self.receipt(digest))
        os.link(path,self.home/'other')
        with self.assertRaises(records.SnapshotRecordError):records.read_receipt(self.home,self.key)
        (self.home/'other').unlink();path.chmod(0o644)
        with self.assertRaises(records.SnapshotRecordError):records.read_receipt(self.home,self.key)
        path.chmod(0o600);path.write_text('{"kind":"receipt","kind":"receipt"}')
        with self.assertRaises(records.SnapshotRecordError):records.read_receipt(self.home,self.key)

    def test_failure_after_decision_link_is_uncertain_and_never_overwritten(self):
        self.prepare();real_fsync=records.os.fsync;calls=[]
        def fail_directory(fd):
            calls.append(fd)
            if len(calls)==2:raise OSError('synthetic fsync failure')
            return real_fsync(fd)
        with mock.patch.object(records.os,'fsync',side_effect=fail_directory):
            with self.assertRaisesRegex(records.SnapshotRecordError,'WRITE_UNCERTAIN'):
                records.write_decision(self.home,self.key,'release')
        self.assertTrue((self.home/records.DECISION).exists())
        # The orphaned temporary hard link makes the record unreadable: no
        # operation is authorized until a human resolves the uncertain state.
        with self.assertRaises(records.SnapshotRecordError):records.read_decision(self.home,self.key)
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'mutation')

    def test_failure_before_link_does_not_create_final_name(self):
        with mock.patch.object(records.os,'link',side_effect=OSError('simulated')):
            with self.assertRaisesRegex(records.SnapshotRecordError,'WRITE_UNCERTAIN'):
                records.write_descriptor(self.home,self.key,self.descriptor)
        self.assertFalse((self.home/records.DESCRIPTOR).exists())
        self.assertTrue(any(p.name.startswith('.snapshot-record-') for p in self.home.iterdir()))

    def test_failure_after_unlink_keeps_committed_decision_and_refuses_other_branch(self):
        self.prepare();real_fsync=records.os.fsync;calls=[]
        def fail_last_sync(fd):
            calls.append(fd)
            if len(calls)==3:raise OSError('synthetic fsync failure')
            return real_fsync(fd)
        with mock.patch.object(records.os,'fsync',side_effect=fail_last_sync):
            with self.assertRaisesRegex(records.SnapshotRecordError,'WRITE_UNCERTAIN'):
                records.write_decision(self.home,self.key,'mutation')
        self.assertEqual(records.read_decision(self.home,self.key)[0]['action'],'mutation')
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'release')

    def test_invalid_kind_invalid_action_and_untrusted_directory(self):
        with self.assertRaises(records.SnapshotRecordError):
            records.write_descriptor(self.home,self.key,{**self.descriptor,'backend':'other'})
        self.prepare()
        with self.assertRaises(records.SnapshotRecordError):records.write_decision(self.home,self.key,'other')
        self.assertFalse((self.home/records.DECISION).exists())
        self.home.chmod(0o755)
        with self.assertRaises(records.SnapshotRecordError):records.read_receipt(self.home,self.key)

    def test_competing_decisions_never_both_win(self):
        self.prepare()
        def attempt(action):
            try:records.write_decision(self.home,self.key,action);return action
            except records.SnapshotRecordError:return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(attempt,('release','mutation')))
        winners=[item for item in results if item is not None]
        self.assertEqual(len(winners),1)
        self.assertEqual(records.read_decision(self.home,self.key)[0]['action'],winners[0])


if __name__=='__main__':unittest.main()
