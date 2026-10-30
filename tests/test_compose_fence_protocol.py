import os
import tempfile
from pathlib import Path
import unittest
from unittest import mock
from scripts import compose_fence_protocol as protocol
from scripts import redis_fence_journal as journal


@unittest.skipUnless(os.name == 'posix', 'journal requires POSIX fsync and dirfds')
class ComposeFenceProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.record=journal.create(self.home,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
        self.op=self.record['operation']
        self.adapter=mock.Mock()
        self.adapter.verify_preconditions.return_value=True
        self.adapter.verify_isolated.return_value=True
        self.adapter.verify_old_restoration_safe.return_value=True
        self.adapter.verify_old_restored.return_value=True

    def test_isolate_order_and_verified_capture(self):
        protocol.isolate(self.home,self.op,self.adapter)
        self.assertEqual([c[0] for c in self.adapter.method_calls],['verify_preconditions','disable_restart',
                         'disconnect_network','close_external_clients','verify_isolated'])
        self.assertEqual(journal.read(self.home)['phase'],'isolated')
        self.adapter.reset_mock()
        captures=[]
        protocol.capture(self.home,self.op,self.adapter,lambda: captures.append('synthetic'))
        self.assertEqual(captures,['synthetic'])
        self.assertEqual([c[0] for c in self.adapter.method_calls],['verify_isolated','verify_isolated'])
        self.assertEqual(journal.read(self.home)['phase'],'captured')

    def test_failures_after_first_mutation_never_auto_reconnect(self):
        for method in ('disable_restart','disconnect_network','close_external_clients','verify_isolated'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as temp:
                rec=journal.create(temp,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
                adapter=mock.Mock();adapter.verify_preconditions.return_value=True
                adapter.verify_isolated.return_value=True
                getattr(adapter,method).side_effect=RuntimeError('private details')
                with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_ISOLATION_INCOMPLETE$'):
                    protocol.isolate(temp,rec['operation'],adapter)
                self.assertEqual(journal.read(temp)['phase'],'isolating')
                adapter.restore_old_configuration.assert_not_called()

    def test_precondition_failure_writes_no_mutation_phase(self):
        self.adapter.verify_preconditions.side_effect=RuntimeError('private detail')
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_PRECONDITION_FAILED$'):
            protocol.isolate(self.home,self.op,self.adapter)
        self.assertEqual(journal.read(self.home)['phase'],'prepared')
        self.adapter.disable_restart.assert_not_called()

    def test_capture_failure_keeps_journal_and_never_restores(self):
        protocol.isolate(self.home,self.op,self.adapter)
        def broken(): raise ValueError('sensitive detail')
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_CAPTURE_INCOMPLETE$'):
            protocol.capture(self.home,self.op,self.adapter,broken)
        self.assertEqual(journal.read(self.home)['phase'],'capturing')
        self.adapter.restore_old_configuration.assert_not_called()

    def test_capture_rechecks_fence_and_does_not_certify_failed_result(self):
        protocol.isolate(self.home,self.op,self.adapter)
        self.adapter.verify_isolated.side_effect=[True,False]
        performed=mock.Mock()
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_CAPTURE_INCOMPLETE$'):
            protocol.capture(self.home,self.op,self.adapter,performed)
        performed.assert_called_once()
        self.assertEqual(journal.read(self.home)['phase'],'capturing')

    def test_lost_fence_prevents_snapshot(self):
        protocol.isolate(self.home,self.op,self.adapter)
        self.adapter.verify_isolated.side_effect=RuntimeError('lost')
        capture=mock.Mock()
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_LOST$'):
            protocol.capture(self.home,self.op,self.adapter,capture)
        self.assertEqual(journal.read(self.home)['phase'],'isolated')
        capture.assert_not_called()

    def test_restore_requires_proof_and_journal_then_rechecks(self):
        protocol.isolate(self.home,self.op,self.adapter)
        self.adapter.verify_old_restoration_safe.side_effect=RuntimeError('no proof')
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_RESTORE_UNSAFE$'):
            protocol.abort_to_old(self.home,self.op,self.adapter)
        self.assertEqual(journal.read(self.home)['phase'],'isolated')
        self.adapter.restore_old_configuration.assert_not_called()
        self.adapter.verify_old_restoration_safe.side_effect=None
        self.adapter.verify_old_restored.side_effect=RuntimeError('not restored')
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_RESTORE_INCOMPLETE$'):
            protocol.abort_to_old(self.home,self.op,self.adapter)
        self.assertEqual(journal.read(self.home)['phase'],'aborting')

    def test_checks_only_accept_literal_true(self):
        for method, state, call in (
                ('verify_preconditions', 'prepared', 'isolate'),
                ('verify_isolated', 'isolated', 'capture'),
                ('verify_old_restoration_safe', 'isolated', 'restore'),
                ('verify_old_restored', 'aborting', 'restore')):
            for bad in (None, False, 1, 'true'):
                with self.subTest(method=method,bad=bad), tempfile.TemporaryDirectory() as temp:
                    rec=journal.create(temp,backend='compose',site='test',resource='a'*64,plan_sha256='b'*64)
                    adapter=mock.Mock()
                    for name in ('verify_preconditions','verify_isolated','verify_old_restoration_safe','verify_old_restored'):
                        getattr(adapter,name).return_value=True
                    if call!='isolate': protocol.isolate(temp,rec['operation'],adapter)
                    getattr(adapter,method).return_value=bad
                    with self.assertRaises(protocol.ComposeFenceProtocolError):
                        if call=='isolate': protocol.isolate(temp,rec['operation'],adapter)
                        elif call=='capture': protocol.capture(temp,rec['operation'],adapter,lambda:None)
                        else: protocol.abort_to_old(temp,rec['operation'],adapter)
                    self.assertEqual(journal.read(temp)['phase'],state)
                    if method=='verify_old_restoration_safe':adapter.restore_old_configuration.assert_not_called()

    def test_no_cross_operation_or_backend(self):
        with self.assertRaisesRegex(protocol.ComposeFenceProtocolError,'^COMPOSE_FENCE_STATE_INVALID$'):
            protocol.isolate(self.home,'0'*32,self.adapter)
        self.assertEqual(journal.read(self.home)['phase'],'prepared')
        self.adapter.verify_preconditions.assert_not_called()


if __name__=='__main__': unittest.main()
