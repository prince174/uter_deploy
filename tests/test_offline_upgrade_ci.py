import tempfile
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from scripts import offline_upgrade_ci as ci


class OfflineUpgradeCITests(unittest.TestCase):
    def test_guardrail_smoke_exception_targets_one_private_address_and_port(self):
        with patch.object(ci.ci.Firewall,'command') as command:
            firewall=ci.ci.Firewall('UDOFF123456ABCDEF')
            ci.allow_guardrail_smoke(firewall,'172.19.0.2')
            command.assert_called_once_with('iptables','-I','UDOFF123456ABCDEF','1',
                '-d','172.19.0.2/32','-p','tcp','--dport','8000','-j','RETURN')
            for invalid in ('8.8.8.8','172.19.0.0/16','::1'):
                command.reset_mock()
                with self.subTest(invalid=invalid),self.assertRaises((ValueError,ci.ci.StageError)):
                    ci.allow_guardrail_smoke(firewall,invalid)
                command.assert_not_called()

    def test_smoke_counters_only_count_without_allowing_packets(self):
        with patch.object(ci.ci.Firewall,'command') as command:
            firewall=ci.ci.Firewall('UDOFF123456ABCDEF')
            ci.add_smoke_counters(firewall,{'backend':'172.18.0.2','outbound':'172.19.0.2'})
            self.assertEqual(command.call_count,2)
            for invocation in command.call_args_list:
                self.assertNotIn('-j',invocation.args)
                self.assertIn('--dport',invocation.args)
                self.assertIn('8000',invocation.args)
            command.reset_mock()
            command.return_value=SimpleNamespace(stdout=b' 17 1020    all -- * * 0.0.0.0/0 172.18.0.2 /* uter-smoke-backend */\n 0 0 all -- * * 0.0.0.0/0 172.19.0.2 /* uter-smoke-outbound */\n')
            self.assertEqual(ci.smoke_counter_values(firewall),{'backend':17,'outbound':0})
            command.return_value=SimpleNamespace(stdout=b'')
            with self.assertRaises(ci.ci.StageError):
                ci.smoke_counter_values(firewall)

    def test_guardrail_addresses_require_matching_project_labels(self):
        project='uter-offline-ci-123456abcdef'
        identity='a'*64
        network={'Name':project+'_backend','Driver':'bridge',
                 'Labels':{'com.docker.compose.project':project,'com.docker.compose.network':'backend'},
                 'IPAM':{'Config':[{'Subnet':'172.18.0.0/16'}]},
                 'Containers':{identity:{'Name':project+'-guardrail-1','IPv4Address':'172.18.0.2/16'}}}
        def execute(args, category, **kwargs):
            if 'network' in args:
                side=args[-1].split('_')[-1]
                selected=json.loads(json.dumps(network))
                selected['Name']=project+'_'+side
                selected['Labels']['com.docker.compose.network']=side
                return SimpleNamespace(stdout=json.dumps(selected).encode())
            return SimpleNamespace(stdout=json.dumps({'com.docker.compose.project':project,
                'com.docker.compose.service':'guardrail'}).encode())
        with patch.object(ci.ci,'run',side_effect=execute):
            self.assertEqual(ci.guardrail_addresses('/docker',project,{}),
                             {'backend':'172.18.0.2','outbound':'172.18.0.2'})
            network['Labels']['com.docker.compose.project']='foreign'
            with self.assertRaises(ci.ci.StageError):
                ci.guardrail_addresses('/docker',project,{})

    def test_failure_diagnostics_report_only_safe_categories(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); trace=root/'trace'
            trace.write_text('OTHER\nUP_PULL_NEVER\nsecret-canary\n')
            (root/'state.json').write_text(json.dumps({'pending':{'credential':'secret-canary'}}))
            (root/'backup-operation.json').write_text(json.dumps({'phase':'quiesced','credential':'secret-canary'}))
            result=ci.failure_categories(b'Update incomplete. State retained; uter_managed_smoke.py secret-canary',root,trace)
            self.assertTrue(result['apply_or_smoke_failed'])
            self.assertTrue(result['managed_smoke_error'])
            self.assertTrue(result['compose_up_observed'])
            self.assertEqual(result['state'],'pending')
            self.assertEqual(result['backup_journal'],'quiesced')
            self.assertNotIn('secret-canary',json.dumps(result))
            (root/'state.json').unlink()
            (root/'backup-operation.json').write_text('{bad')
            result=ci.failure_categories(b'Pre-adoption smoke failed',root,trace)
            self.assertEqual(result['state'],'not_adopted')
            self.assertEqual(result['backup_journal'],'unreadable')
            self.assertTrue(result['adoption_smoke_failed'])
    def test_fixture_allowlist_requires_owned_network_and_containers(self):
        project='uter-offline-ci-123456abcdef'
        ids={'guardrail':'a'*64,'agent':'b'*64}
        network={'Id':'c'*64,'Name':project+'_outbound','Driver':'bridge','Internal':False,
                 'Labels':{'com.docker.compose.project':project,'com.docker.compose.network':'outbound'},
                 'IPAM':{'Config':[{'Subnet':'172.20.0.0/16','Gateway':'172.20.0.1'}]},
                 'Containers':{identity:{'Name':project+'-'+role+'-1','IPv4Address':'172.20.0.'+str(index)+'/16'}
                               for index,(role,identity) in enumerate(ids.items(),2)}}
        def execute(args, category, **kwargs):
            if 'network' in args:
                return SimpleNamespace(stdout=json.dumps(network).encode())
            identity=args[-1]
            role=next(role for role,value in ids.items() if value==identity)
            labels={'com.docker.compose.project':project,'com.docker.compose.service':role}
            return SimpleNamespace(stdout=(' '.join(map(json.dumps,[identity,'/'+project+'-'+role+'-1',labels]))).encode())
        with patch.object(ci.ci,'run',side_effect=execute):
            self.assertEqual(ci.verified_outbound_subnet('/docker',project,{}),('172.20.0.0/16','c'*64))
            network['Labels']['com.docker.compose.project']='foreign'
            with self.assertRaises(ci.ci.StageError):
                ci.verified_outbound_subnet('/docker',project,{})
            network['Labels']['com.docker.compose.project']=project
            for field, bad in [('Name','foreign'), ('Driver','overlay'), ('Internal',True), ('Id','bad')]:
                previous=network[field]; network[field]=bad
                with self.subTest(field=field),self.assertRaises(ci.ci.StageError):
                    ci.verified_outbound_subnet('/docker',project,{})
                network[field]=previous
            for subnet in ('172.16.0.0/12','0.0.0.0/0','8.8.8.0/24','172.20.0.1/16'):
                network['IPAM']['Config'][0]['Subnet']=subnet
                with self.subTest(subnet=subnet),self.assertRaises(ci.ci.StageError):
                    ci.verified_outbound_subnet('/docker',project,{})
            network['IPAM']['Config'][0]['Subnet']='172.20.0.0/16'
            network['Containers'][ids['guardrail']]['IPv4Address']='10.0.0.2/16'
            with self.assertRaises(ci.ci.StageError):
                ci.verified_outbound_subnet('/docker',project,{})
            network['Containers'][ids['guardrail']]['IPv4Address']='172.20.0.2/16'
            network['Containers']['c'*64]={'Name':'foreign','IPv4Address':'172.20.0.8/16'}
            with self.assertRaises(ci.ci.StageError):
                ci.verified_outbound_subnet('/docker',project,{})

    def test_fixture_firewall_exception_is_only_established_replies(self):
        with patch.object(ci.ci.Firewall,'command') as command:
            firewall=ci.ci.Firewall('UDOFF123456ABCDEF')
            ci.allow_fixture_responses(firewall,'172.17.0.1','172.20.0.0/16',43210)
        command.assert_called_once_with('iptables','-I','UDOFF123456ABCDEF','1',
            '-s','172.17.0.1/32','-d','172.20.0.0/16','-p','tcp','--sport','43210',
            '-m','conntrack','--ctstate','ESTABLISHED','-j','RETURN')
    def test_signed_target_updater_receives_offline_and_current_bundle(self):
        paths = [Path('/fixture')/name for name in ('old', 'new', 'public', 'home', 'backups', 'key')]
        command = ci.update_command('/python', *paths)
        self.assertEqual(command[1], paths[1]/'scripts/update_installation.py')
        self.assertEqual(command[command.index('--current-bundle')+1], paths[0])
        self.assertEqual(command[command.index('--bundle')+1], paths[1])
        self.assertIn('--offline', command)
        self.assertIn('--create-backup-key', command)

    def test_fingerprint_detects_changes_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'state').write_text('old')
            first = ci.digest_tree(root)
            (root/'state').write_text('new')
            self.assertNotEqual(first, ci.digest_tree(root))
            (root/'link').symlink_to(root/'state')
            with self.assertRaises(ci.ci.StageError):
                ci.digest_tree(root)

    def test_workflow_uses_published_pair_and_enforces_runner_guard(self):
        workflow = (Path(__file__).resolve().parents[1]/'.github/workflows/offline-upgrade.yml').read_text()
        self.assertIn('--old-version 0.1.4 --new-version 0.1.5', workflow)
        self.assertIn('release_upgrade_preflight_ci.py', workflow)
        self.assertIn('RUNNER_ENVIRONMENT', workflow)
        self.assertIn('scripts/offline_upgrade_ci.py', workflow)
        self.assertIn("--proto '=https' --proto-redir '=https'", workflow)


if __name__ == '__main__':
    unittest.main()
