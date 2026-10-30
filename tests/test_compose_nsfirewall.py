import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import compose_nsfirewall_adapter as ns, compose_nsfirewall_protocol as protocol
from scripts import redis_fence_journal as journal


@unittest.skipUnless(os.name=='posix','POSIX namespace and journal required')
class NamespaceFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        self.operation=self.record['operation']
        self.adapter=ns.Adapter(self.home,self.home/'bundle',self.home/'key',b'k'*32)
        self.adapter.operation=self.operation

    def test_rule_identifier_cannot_be_injected(self):
        self.assertEqual(self.adapter._rule()[-2:],['-j','DROP'])
        self.adapter.operation='a'*32+';iptables'
        with self.assertRaisesRegex(ns.NamespaceFenceError,'OPERATION_INVALID'):self.adapter._rule()

    def test_first_exact_rule_and_full_baseline_are_required(self):
        import hashlib
        token='uter-fence-'+self.operation
        policy='-P INPUT ACCEPT\n';other='-A INPUT -j ACCEPT\n'
        expected=policy+other
        self.adapter.initial_hash=hashlib.sha256(expected.encode()).hexdigest()
        own='-A INPUT -p tcp --dport 6379 ! -i lo -m comment --comment '+token+' -j DROP\n'
        def run(args):
            if args[:2]==['-S','INPUT']:return (policy+own+other).encode()
            if args[:2]==['-C','INPUT']:return b''
            raise AssertionError(args)
        with mock.patch.object(self.adapter,'_cmd',side_effect=run):
            self.adapter._check_firewall(installed=True)
        for raw in (policy+other+own,policy+own+own+other,policy+own):
            with self.subTest(raw=raw),mock.patch.object(self.adapter,'_cmd',return_value=raw.encode()):
                with self.assertRaises(ns.NamespaceFenceError):self.adapter._check_firewall(installed=True)

    def test_no_rule_without_a_nonhost_pinned_fd(self):
        with mock.patch.object(self.adapter,'_fd_nonhost',side_effect=ns.NamespaceFenceError('host')), \
             mock.patch.object(ns.subprocess,'Popen') as popen:
            with self.assertRaises(ns.NamespaceFenceError):self.adapter._cmd(['-S','INPUT'])
        popen.assert_not_called()

    def test_protocol_never_removes_rule_after_any_uncertain_mutation(self):
        for failing in ('disable_restart','install_rule','close_clients','verify_fenced'):
            with self.subTest(failing=failing),tempfile.TemporaryDirectory() as folder:
                record=journal.create(folder,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
                adapter=mock.Mock();adapter.prepare.return_value=True;adapter.verify_fenced.return_value=True
                getattr(adapter,failing).side_effect=RuntimeError('sensitive')
                with self.assertRaisesRegex(protocol.NamespaceProtocolError,'ISOLATION_INCOMPLETE'):
                    protocol.isolate(folder,record['operation'],adapter)
                self.assertEqual(journal.read(folder)['phase'],'isolating')
                adapter.release_before_capture.assert_not_called()

    def test_release_authorization_is_single_direct_transition_before_capture(self):
        journal.advance(self.home,operation=self.operation,expected='prepared',next_phase='isolating')
        journal.advance(self.home,operation=self.operation,expected='isolating',next_phase='isolated')
        record=journal.read(self.home);self.adapter.installed=True
        with mock.patch.object(self.adapter,'verify_fenced',return_value=True):
            self.assertIs(self.adapter.authorize_release_before_capture(record),True)
        self.assertEqual(journal.read(self.home)['phase'],'aborting')
        with self.assertRaises(journal.FenceJournalError):
            journal.advance(self.home,operation=self.operation,expected='isolated',next_phase='capturing')

    def test_after_capture_no_release_permit(self):
        for old,new in (('prepared','isolating'),('isolating','isolated'),('isolated','capturing'),('capturing','captured')):
            journal.advance(self.home,operation=self.operation,expected=old,next_phase=new)
        self.adapter.installed=True
        stale=dict(self.record,phase='isolated')
        with self.assertRaisesRegex(ns.NamespaceFenceError,'JOURNAL_MISMATCH'):
            self.adapter.authorize_release_before_capture(stale)
        self.assertIsNone(self.adapter.release_permit)

    def test_release_uncertainty_keeps_abort_journal(self):
        for old,new in (('prepared','isolating'),('isolating','isolated')):
            journal.advance(self.home,operation=self.operation,expected=old,next_phase=new)
        adapter=mock.Mock()
        def authorize(record):
            journal.advance(self.home,operation=self.operation,expected='isolated',next_phase='aborting');return True
        adapter.authorize_release_before_capture.side_effect=authorize
        adapter.release_before_capture.side_effect=RuntimeError('private')
        with self.assertRaisesRegex(protocol.NamespaceProtocolError,'RELEASE_INCOMPLETE'):
            protocol.release_without_capture(self.home,self.operation,adapter)
        self.assertEqual(journal.read(self.home)['phase'],'aborting')


if __name__=='__main__':unittest.main()
