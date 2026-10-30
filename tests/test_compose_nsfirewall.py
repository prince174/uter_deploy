import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
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

    def test_rejects_every_host_or_daemon_namespace_and_changed_daemon(self):
        self.adapter.fd=40;self.adapter.daemon_fd=41;self.adapter.daemon_pidfd=42;self.adapter.daemon_pid=99
        def entry(ino):return SimpleNamespace(st_dev=1,st_ino=ino)
        for conflict in ('self','init','daemon'):
            with self.subTest(conflict=conflict):
                def stat(path):
                    return entry(7 if ((conflict=='self' and str(path)=='/proc/self/ns/net') or
                                       (conflict=='init' and str(path)=='/proc/1/ns/net')) else 2)
                def fstat(fd):return entry(7 if fd==40 or conflict=='daemon' else 2)
                with mock.patch.object(self.adapter,'_daemon_identity',return_value=99),mock.patch.object(ns.select,'select',return_value=([],[],[])), \
                     mock.patch.object(ns.os,'stat',side_effect=stat),mock.patch.object(ns.os,'fstat',side_effect=fstat):
                    with self.assertRaisesRegex(ns.NamespaceFenceError,'HOST_NAMESPACE_REJECTED'):self.adapter._fd_nonhost()
        with mock.patch.object(self.adapter,'_daemon_identity',return_value=100),mock.patch.object(ns.select,'select',return_value=([],[],[])):
            with self.assertRaisesRegex(ns.NamespaceFenceError,'DAEMON_UNVERIFIED'):self.adapter._fd_nonhost()
        with mock.patch.object(ns.select,'select',return_value=([42],[],[])):
            with self.assertRaisesRegex(ns.NamespaceFenceError,'DAEMON_UNVERIFIED'):self.adapter._fd_nonhost()

    def test_daemon_socket_is_retained_and_dead_or_noisy_peer_is_rejected(self):
        peer=mock.Mock();peer.getsockopt.return_value=struct.pack('3i',99,0,0)
        self.adapter.daemon_socket=peer
        with mock.patch.object(ns.Path,'read_text',return_value='dockerd\n'), \
             mock.patch.object(ns.os,'stat',return_value=SimpleNamespace(st_dev=1,st_ino=4)), \
             mock.patch.object(ns.select,'select',return_value=([],[],[])):
            self.assertEqual(self.adapter._daemon_identity(),99)
            peer.close.assert_not_called()
        for content in (b'',b'unexpected'):
            peer.recv.return_value=content
            with self.subTest(content=content),mock.patch.object(ns.select,'select',return_value=([peer],[],[])):
                with self.assertRaisesRegex(ns.NamespaceFenceError,'DAEMON_UNVERIFIED'):self.adapter._daemon_identity()
        self.adapter.close();peer.close.assert_called_once()

    def test_extra_loopback_process_wrong_child_namespace_and_capabilities_are_rejected(self):
        self.adapter.net_identity=(1,7);self.adapter.redis_pid=42
        rows='PID PPID COMMAND\n42 1 docker-init\n43 42 redis-server\n'
        plan={'container_id':'a'*64}
        clear=''.join(name+':\t0000000000000000\n' for name in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd'))+'NoNewPrivs:\t1\n'
        def run(top, namespace=7, status=clear):
            with mock.patch.object(self.adapter,'_lock'),mock.patch.object(self.adapter,'_fd_nonhost',return_value=(1,7)), \
                 mock.patch.object(self.adapter,'_state',return_value={'pid':42}),mock.patch.object(self.adapter,'_run',return_value=top), \
                 mock.patch.object(ns.os,'stat',side_effect=lambda p:SimpleNamespace(st_dev=1,st_ino=namespace if str(p)=='/proc/43/ns/net' else 7)), \
                 mock.patch.object(ns.Path,'read_text',return_value=status),mock.patch.object(self.adapter,'_exclusive_namespace'):
                self.adapter._live_namespace(plan)
        run(rows)
        for top,namespace,status in ((rows+'44 42 helper\n',7,None),(rows,8,None),
                                     (rows,7,clear.replace('CapPrm:\t0000000000000000','CapPrm:\t0000000000001000')),
                                     (rows,7,clear.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'))):
            with self.subTest(top=top,namespace=namespace,status=status):
                with self.assertRaises(ns.NamespaceFenceError):
                    run(top,namespace,status or clear)

    def test_rejects_foreign_thread_in_namespace_and_unreadable_proc(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'namespace';source.write_text('')
            identity=source.stat();expected=(identity.st_dev,identity.st_ino)
            for pid in ('42','43','44'):
                namespace=root/pid/'task'/pid/'ns/net';namespace.parent.mkdir(parents=True)
                os.link(source,namespace)
            with mock.patch.object(ns,'PROC_ROOT',root):
                with self.assertRaisesRegex(ns.NamespaceFenceError,'NAMESPACE_PEER'):
                    self.adapter._exclusive_namespace(expected,{42,43})
                self.adapter._exclusive_namespace(expected,{42,43,44})
                with mock.patch.object(ns.Path,'iterdir',side_effect=PermissionError):
                    with self.assertRaisesRegex(ns.NamespaceFenceError,'PROC_UNVERIFIED'):
                        self.adapter._exclusive_namespace(expected,{42,43,44})

    def test_successful_release_marks_redis_only(self):
        for old,new in (('prepared','isolating'),('isolating','isolated')):
            journal.advance(self.home,operation=self.operation,expected=old,next_phase=new)
        adapter=mock.Mock()
        def authorize(record):
            journal.advance(self.home,operation=self.operation,expected='isolated',next_phase='aborting');return True
        adapter.authorize_release_before_capture.side_effect=authorize
        protocol.release_without_capture(self.home,self.operation,adapter)
        self.assertEqual(journal.read(self.home)['phase'],'redis_released')

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
