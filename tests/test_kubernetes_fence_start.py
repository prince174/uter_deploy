import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import kubernetes_fence_start as start


class StartSequenceTests(unittest.TestCase):
    def setUp(self):
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2},_key_path='key',home='home',
            writer_uids={'guardrail':'a','agent':'b'},api=object(),reverify=lambda:None)
        self.operation='a'*32

    def test_happy_sequence_never_authorizes_backup_or_update(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(start.backup_installation,'safe_file',return_value=b'k'*32))
            stack.enter_context(patch.object(start.finalizer,'read_plan',return_value={}))
            stack.enter_context(patch.object(start.finalizer,'_check_journal'))
            operations=((start.writers,'prepare'),(start.writer_finalizer,'prepare'),(start.recovery,'seal_before_mutation'),
                (start.audit_plan,'prepare'),(start.writer_finalizer,'hold'),(start.writers,'stop'),
                (start.writer_finalizer,'observe'),(start.writer_finalizer,'release'),(start.writers,'observe_stopped'),
                (start.finalizer,'hold'),(start.loopback,'prepare'),(start.loopback,'request'),
                (start.shutdown,'observe'),(start.redis_release,'release'))
            mocks=[stack.enter_context(patch.object(module,name)) for module,name in operations]
            result=start.start(self.session,self.operation,timeout=1)
            self.assertEqual(result,{'redis_finalizer_release_requested':True,'complete_backup':False,
                'redis_isolated':False,'safe_to_backup':False,'safe_to_update':False})
            self.assertEqual(mocks[5].call_count,2)
            self.assertEqual(mocks[-1].call_count,1)

    def test_missing_trusted_profile_does_not_mutate(self):
        self.session._record['schema']=1
        with patch.object(start.writers,'stop') as stop:
            with self.assertRaises(start.StartError):start.start(self.session,self.operation)
            stop.assert_not_called()

    def test_uncertain_stop_is_not_retried(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(patch.object(start.backup_installation,'safe_file',return_value=b'k'*32))
            stack.enter_context(patch.object(start.finalizer,'read_plan',return_value={}))
            stack.enter_context(patch.object(start.finalizer,'_check_journal'))
            for module,name in ((start.writers,'prepare'),(start.writer_finalizer,'prepare'),
                (start.recovery,'seal_before_mutation'),(start.audit_plan,'prepare'),(start.writer_finalizer,'hold')):
                stack.enter_context(patch.object(module,name))
            stop=stack.enter_context(patch.object(start.writers,'stop',side_effect=TimeoutError))
            with self.assertRaises(start.StartError):start.start(self.session,self.operation,timeout=1)
            self.assertEqual(stop.call_count,1)
