import tempfile
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from scripts import offline_upgrade_ci as ci


class OfflineUpgradeCITests(unittest.TestCase):
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
