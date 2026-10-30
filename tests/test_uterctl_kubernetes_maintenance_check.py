from contextlib import nullcontext, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import uterctl
from scripts import (backup_installation, kubernetes_fence_coordinator as coordinator,
                     kubernetes_maintenance_preflight as preflight, maintenance_transport,
                     redis_fence_journal as journal)
from tests import test_kubernetes_maintenance_preflight as fixtures


class KubernetesMaintenanceCheckTests(unittest.TestCase):
    def setUp(self):
        self.argv=['maintenance-check-kubernetes','--home','/home','--bundle','/bundle',
                   '--key','/publisher','--executor-key','/executor','--backup-key','/backup',
                   '--kubeconfig','/kubeconfig','--operator-profile','/profile','--kubectl','/kubectl']
        self.snapshot={'writers':{'agent':{'private':'secret-canary'},'guardrail':{}},
                       'ingress_fenced':False,'restart_fenced':False,'redis_isolated':False,
                       'safe_to_start':False,'safe_to_update':False}

    def test_rejects_missing_or_relative_paths_before_executor_or_api(self):
        with patch.object(uterctl,'_load_signed_fence_executor') as load, \
             patch.object(coordinator,'checked_session') as session:
            with self.assertRaisesRegex(ValueError,'ARGUMENTS_REQUIRED'):
                uterctl.main(self.argv[:-2])
            altered=self.argv.copy();altered[altered.index('--kubeconfig')+1]='relative'
            with self.assertRaisesRegex(ValueError,'PATH_NOT_ABSOLUTE'):
                uterctl.main(altered)
        load.assert_not_called();session.assert_not_called()

    def test_uses_signed_session_and_outputs_only_fixed_non_authorizing_result(self):
        output=io.StringIO();fixture=object()
        with patch.object(uterctl,'_load_signed_fence_executor') as load, \
             patch.object(backup_installation,'private_directory',return_value=Path('/home')), \
             patch.object(uterctl,'locked',return_value=nullcontext()) as lock, \
             patch.object(journal,'blocks_mutation',return_value=False), \
             patch.object(coordinator,'checked_session',return_value=nullcontext(fixture)) as session, \
             patch.object(preflight,'observe',return_value=self.snapshot) as observe, \
             patch.object(maintenance_transport,'request') as transport, \
             patch.object(journal,'create') as create,redirect_stdout(output):
            uterctl.main(self.argv)
        load.assert_called_once();lock.assert_called_once_with(Path('/home'))
        session.assert_called_once();self.assertEqual(observe.call_count,2)
        self.assertEqual(observe.call_args.args,(fixture,))
        transport.assert_not_called();create.assert_not_called()
        self.assertIn('"safe_to_update": false',output.getvalue())
        self.assertIn('"application_endpoint_checked": false',output.getvalue())
        self.assertNotIn('secret-canary',output.getvalue())

    def test_active_journal_refuses_before_kubernetes_session(self):
        with patch.object(uterctl,'_load_signed_fence_executor'), \
             patch.object(backup_installation,'private_directory',return_value=Path('/home')), \
             patch.object(uterctl,'locked',return_value=nullcontext()), \
             patch.object(journal,'blocks_mutation',return_value=True), \
             patch.object(coordinator,'checked_session') as session:
            with self.assertRaisesRegex(ValueError,'REDIS_FENCE_REQUIRES_INSPECTION'):
                uterctl.main(self.argv)
        session.assert_not_called()

    def test_inconsistent_snapshot_does_not_print_success(self):
        output=io.StringIO();snapshot=dict(self.snapshot,safe_to_update=True)
        with patch.object(uterctl,'_load_signed_fence_executor'), \
             patch.object(backup_installation,'private_directory',return_value=Path('/home')), \
             patch.object(uterctl,'locked',return_value=nullcontext()), \
             patch.object(journal,'blocks_mutation',return_value=False), \
             patch.object(coordinator,'checked_session',return_value=nullcontext(object())), \
             patch.object(preflight,'observe',return_value=snapshot),redirect_stdout(output):
            with self.assertRaisesRegex(ValueError,'RESULT_UNVERIFIED'):
                uterctl.main(self.argv)
        self.assertEqual(output.getvalue(),'')

    def test_identity_change_between_observations_does_not_print_success(self):
        output=io.StringIO();changed=dict(self.snapshot,writers={'agent':{},'guardrail':{}})
        with patch.object(uterctl,'_load_signed_fence_executor'), \
             patch.object(backup_installation,'private_directory',return_value=Path('/home')), \
             patch.object(uterctl,'locked',return_value=nullcontext()), \
             patch.object(journal,'blocks_mutation',return_value=False), \
             patch.object(coordinator,'checked_session',return_value=nullcontext(object())), \
             patch.object(preflight,'observe',side_effect=(self.snapshot,changed)),redirect_stdout(output):
            with self.assertRaisesRegex(ValueError,'IDENTITY_CHANGED'):
                uterctl.main(self.argv)
        self.assertEqual(output.getvalue(),'')

    def test_real_preflight_only_reads_kubernetes_and_never_calls_maintenance(self):
        fixture=fixtures.KubernetesPreflightTests();fixture.setUp()
        queries=[];original=fixture.session._query
        def query(args):
            queries.append(args)
            self.assertEqual(args[0],'get')
            return original(args)
        fixture.session._query=query
        with patch.object(uterctl,'_load_signed_fence_executor'), \
             patch.object(backup_installation,'private_directory',return_value=Path('/home')), \
             patch.object(uterctl,'locked',return_value=nullcontext()), \
             patch.object(journal,'blocks_mutation',return_value=False), \
             patch.object(coordinator,'checked_session',return_value=nullcontext(fixture.session)), \
             patch.object(preflight.maintenance_protocol,'verify_capability',return_value=fixture.manifest), \
             patch.object(preflight.writers,'_deployment',side_effect=lambda s,service,uid:({'uid':uid},{'replicas':1})), \
             patch.object(maintenance_transport,'request') as request, \
             patch.object(journal,'create') as create,redirect_stdout(io.StringIO()):
            uterctl.main(self.argv)
        self.assertTrue(queries);self.assertTrue(all(q[0]=='get' for q in queries))
        request.assert_not_called();create.assert_not_called()


if __name__=='__main__':unittest.main()
