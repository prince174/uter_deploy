from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import kubernetes_redis_reverse as reverse


class RedisReverseTests(unittest.TestCase):
    def setUp(self):
        self.session=SimpleNamespace(_executor=('signed',),_record={'schema':2},_key_path='key',home='home',api=object())
        self.record={'pod':'pod','uid':'uid'}

    def run_case(self,fail=False):
        with ExitStack() as stack:
            stack.enter_context(patch.object(reverse.network_guard,'assert_external_exclusion'))
            stack.enter_context(patch.object(reverse.backup_installation,'safe_file',return_value=b'k'*32))
            stack.enter_context(patch.object(reverse.pod,'_record',return_value=self.record))
            stack.enter_context(patch.object(reverse.backup,'verify_receipt'))
            stack.enter_context(patch.object(reverse.pod,'hold'))
            stack.enter_context(patch.object(reverse.original,'read_plan',return_value={}))
            stack.enter_context(patch.object(reverse.reverse,'prepare'))
            stack.enter_context(patch.object(reverse.auth,'seal'))
            submit=stack.enter_context(patch.object(reverse.reverse,'request',side_effect=TimeoutError if fail else None))
            stack.enter_context(patch.object(reverse.pod,'observe',return_value={'termination_observed':True}))
            release=stack.enter_context(patch.object(reverse.pod,'release'))
            if fail:
                with self.assertRaises(reverse.RedisReverseError):reverse.request(self.session,'a'*32,'destination',timeout=1)
                self.assertEqual(submit.call_count,1);release.assert_not_called()
            else:
                self.assertEqual(reverse.request(self.session,'a'*32,'destination',timeout=1),
                    {'original_spec_observed':True,'loopback_pod_finalizer_release_requested':True,
                     'writes_may_have_started':True,'data_verified':False,'safe_to_resume':False})
                self.assertEqual(submit.call_count,1);self.assertEqual(release.call_count,1)

    def test_reverse_sequence_does_not_authorize_resume(self):self.run_case()
    def test_unknown_mutation_is_not_retried(self):self.run_case(fail=True)
    def test_unproven_external_exclusion_fails_before_any_mutation(self):
        with patch.object(reverse.pod,'hold') as hold:
            with self.assertRaises(reverse.RedisReverseError):reverse.request(self.session,'a'*32,'destination',timeout=1)
            hold.assert_not_called()
