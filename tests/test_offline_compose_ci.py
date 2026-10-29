import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import offline_compose_ci as ci


class OfflineComposeCITests(unittest.TestCase):
    def test_refuses_non_github_or_self_hosted_environment(self):
        good = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_RUN_ID': '123',
                'GITHUB_REPOSITORY': 'prince174/uter_deploy'}
        with patch.object(ci.os, 'geteuid', return_value=0), patch.dict(os.environ, good, clear=True):
            ci.ci_only()
            for key, value in [('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                               ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_RUN_ID', 'abc'),
                               ('GITHUB_REPOSITORY', 'another/repository'), ('DOCKER_HOST', 'tcp://remote')]:
                with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                    with self.assertRaisesRegex(ci.StageError, 'DISPOSABLE'):
                        ci.ci_only()

    def test_firewall_uses_only_its_own_chains_and_cleans_on_exception(self):
        calls = []
        def fake(args, category, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        chain = 'UDOFF' + 'A'*12
        with patch.object(ci, 'run', side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, 'test'):
                with ci.Firewall(chain):
                    raise RuntimeError('test')
        for tool in ('iptables', 'ip6tables'):
            matching = [x for x in calls if x[0] == tool]
            self.assertTrue(any(x[2:] == ['-N', chain] for x in matching))
            self.assertTrue(any(x[2:] == ['-D', 'OUTPUT', '-m', 'owner', '--uid-owner', '0', '-j', chain] for x in matching))
            self.assertTrue(any(x[2:] == ['-F', chain] for x in matching))
            self.assertTrue(any(x[2:] == ['-X', chain] for x in matching))
            self.assertFalse(any(x[2:] in (['-F'], ['-X']) for x in matching))

    def test_partial_firewall_setup_cleans_created_chains(self):
        calls = []
        def fake(args, category, **kwargs):
            calls.append(args)
            if args[0] == 'ip6tables' and args[2] == '-A':
                raise ci.StageError('FIREWALL_COMMAND_FAILED')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        chain = 'UDOFF' + 'B'*12
        with patch.object(ci, 'run', side_effect=fake):
            with self.assertRaisesRegex(ci.StageError, 'FIREWALL_COMMAND_FAILED'):
                with ci.Firewall(chain):
                    pass
        self.assertIn(['iptables','-w','-D','OUTPUT','-m','owner','--uid-owner','0','-j',chain],calls)
        self.assertIn(['iptables','-w','-X',chain],calls)
        self.assertIn(['ip6tables','-w','-X',chain],calls)
        self.assertNotIn(['ip6tables','-w','-D','OUTPUT','-m','owner','--uid-owner','0','-j',chain],calls)

    def test_firewall_cleanup_attempts_all_rules_even_after_failure(self):
        calls=[]
        def fake(args, category, **kwargs):
            calls.append(args)
            if args[0]=='ip6tables' and args[2]=='-D':
                raise ci.StageError('FIREWALL_COMMAND_FAILED')
            return subprocess.CompletedProcess(args,0,b'',b'')
        chain='UDOFF'+'D'*12
        with patch.object(ci,'run',side_effect=fake):
            with self.assertRaisesRegex(ci.StageError,'FIREWALL_CLEANUP_FAILED'):
                with ci.Firewall(chain):
                    pass
        self.assertIn(['iptables','-w','-D','OUTPUT','-m','owner','--uid-owner','0','-j',chain],calls)
        self.assertIn(['iptables','-w','-X',chain],calls)
        self.assertIn(['ip6tables','-w','-X',chain],calls)

    def test_reject_count_must_be_unambiguous(self):
        fw=ci.Firewall('UDOFF'+'C'*12)
        table=b'Chain UDOFF (1 references)\n pkts bytes target prot opt in out source destination\n 3 180 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0\n'
        with patch.object(fw, 'command', return_value=subprocess.CompletedProcess([],0,table,b'')):
            self.assertEqual(fw.reject_count(),3)
        with patch.object(fw, 'command', return_value=subprocess.CompletedProcess([],0,b'unknown',b'')):
            with self.assertRaisesRegex(ci.StageError,'COUNTER_UNAVAILABLE'):
                fw.reject_count()

    def test_registry_private_or_mixed_addresses_fail_closed(self):
        public=[(2,1,6,'',('140.82.112.33',443))]
        mixed=public+[(2,1,6,'',('10.0.0.1',443))]
        with patch.object(ci.socket,'getaddrinfo',return_value=public):
            self.assertEqual(ci.public_registry_ipv4(),['140.82.112.33'])
        with patch.object(ci.socket,'getaddrinfo',return_value=mixed):
            with self.assertRaisesRegex(ci.StageError,'ADDRESS_UNVERIFIED'):
                ci.public_registry_ipv4()

    def test_docker_wrapper_records_only_categories_and_blocks_unsafe_up(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)
            real=path/'fake-docker'
            real.write_text('#!/bin/sh\nexit 0\n')
            real.chmod(0o700)
            trace=path/'trace'
            ci.make_wrapper(path,real,trace)
            wrapper=path/'docker'
            env=os.environ.copy();env['UTER_CI_FORBID_UP']='1'
            result=subprocess.run([str(wrapper),'compose','up','--pull','never'],env=env,capture_output=True)
            self.assertEqual(result.returncode,98)
            env['UTER_CI_FORBID_UP']='0'
            result=subprocess.run([str(wrapper),'compose','up','--pull','never','fake-sensitive-argument'],env=env,capture_output=True)
            self.assertEqual(result.returncode,0)
            self.assertNotIn('fake-sensitive-argument',trace.read_text())
            ci.check_trace(trace)
            subprocess.run([str(wrapper),'compose','pull'],env=env,check=True)
            with self.assertRaisesRegex(ci.StageError,'UNEXPECTED_DOCKER_COMMAND'):
                ci.check_trace(trace)

    def test_volume_probe_cannot_use_network_or_pull(self):
        with patch.object(ci,'run') as run:
            ci.volume_probe('/docker','fixture@sha256:'+'a'*64,'test-redis',create=True,env={})
        command=run.call_args.args[0]
        self.assertEqual(command[command.index('--network')+1],'none')
        self.assertEqual(command[command.index('--pull')+1],'never')
        self.assertIn('type=volume,source=test-redis,target=/data',command)

    def test_stopped_containers_are_included_in_owned_cleanup(self):
        commands=[]
        def fake(args, category, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args,0,b'',b'')
        with patch.object(ci,'run',side_effect=fake):
            ci.owned_resources('/docker','uter-offline-ci-a'*1,{})
        container=next(cmd for cmd in commands if 'container' in cmd)
        self.assertIn('-a',container)

    def test_cleanup_rejects_unexpected_resource_before_removing_anything(self):
        project='uter-offline-ci-'+'a'*12
        calls=[]
        def fake(args, category, **kwargs):
            calls.append(args)
            payload=json.dumps([{'Name':'someone-else', 'Labels':{'com.docker.compose.project':project}}]).encode()
            return subprocess.CompletedProcess(args,0,payload,b'')
        with patch.object(ci,'owned_resources',return_value={'container':[],'network':[],'volume':['x']}), \
             patch.object(ci,'run',side_effect=fake):
            with self.assertRaisesRegex(ci.StageError,'OWNERSHIP_INVALID'):
                ci.cleanup('/docker',project,{})
        self.assertFalse(any('rm' in command for command in calls))


if __name__=='__main__':
    unittest.main()
