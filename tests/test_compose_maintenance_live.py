import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from contextlib import nullcontext
import uterctl

from scripts import compose_maintenance_live as subject
from scripts import compose_maintenance_template_ci as ci


class ComposeLiveDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.home=Path('/fixture/private')
        self.cfg={'backend':'compose','maintenance_enabled':True}
        self.key=b'K'*64
        self.writers={name:{'id':character*64,'started':'2026-01-01T00:00:00Z',
                            'restart_count':0,'image_id':'sha256:'+character*64,
                            'image_ref':'example/'+name+'@sha256:'+character*64}
                      for name,character in [('agent','a'),('guardrail','b')]}
        self.plan={'operation':'c'*32,'site':'uter-test'}
        self.states={name:self.state(writer) for name,writer in self.writers.items()}
        self.image={'entrypoint':['python'],'cmd':['service.py']}

    def state(self,expected):
        return {'id':expected['id'],'running':True,'pid':123,'started':expected['started'],
                'restart_count':expected['restart_count'],'restart':'unless-stopped',
                'image_ref':expected['image_ref'],'image_id':expected['image_id'],'user':'10001:10001',
                'entrypoint':['python'],'cmd':['service.py'],'privileged':False,'pid_mode':'',
                'readonly_root':True,'mounts':[{'Type':'bind','RW':False,
                  'Source':str(self.home/'runtime/maintenance-key'),'Destination':'/run/uter-maintenance/key'}],
                'selected_env':sorted(subject._EXPECTED_ENV)+['__end__']}

    def query(self,command,*_args):
        if command[3:5]==['image','inspect']:return dict(self.image)
        ident=command[-1]
        return next(state for name,state in self.states.items() if self.writers[name]['id']==ident)

    def context(self):
        from contextlib import ExitStack
        stack=ExitStack();self.addCleanup(stack.close)
        adapter=Mock();stack.enter_context(patch.object(subject.compose_nsfirewall_adapter,'Adapter',return_value=adapter))
        stack.enter_context(patch.object(subject.backup_snapshot,'_require_fenced_operation_lock'))
        stack.enter_context(patch.object(subject.redis_fence_journal,'blocks_mutation',return_value=False))
        stack.enter_context(patch.object(subject.workload_preflight,'read_trusted_file',return_value=json.dumps(self.cfg).encode()))
        stack.enter_context(patch.object(subject.compose_maintenance_profile,'verify'))
        stack.enter_context(patch.object(subject.compose_maintenance_secret,'read_key',return_value=self.key))
        stack.enter_context(patch.object(subject.compose_fence_start,'_observe',return_value=(self.plan,self.writers,'f'*64)))
        stack.enter_context(patch.object(subject.docker,'_json',side_effect=self.query))
        return adapter

    def run_check(self):
        return subject.check(self.home,'/bundle','/publisher',b'b'*32)

    def test_success_reports_only_bounded_flags_and_no_safety_authorization(self):
        adapter=self.context(); result=self.run_check()
        self.assertEqual(result['writers_observed'],2)
        self.assertTrue(result['profile_snapshots_match'])
        for key in ('application_endpoint_checked','single_worker_verified','key_mount_identity_verified','ingress_fenced','restart_fenced',
                    'redis_isolated','safe_to_backup','safe_to_update'):
            self.assertFalse(result[key])
        self.assertNotIn('example/',repr(result));self.assertNotIn('K'*32,repr(result))
        adapter.close.assert_called_once()

    def test_close_failure_is_fixed_error_without_leak(self):
        adapter=self.context();adapter.close.side_effect=OSError('secret-canary')
        with self.assertRaisesRegex(subject.LiveProfileError,'^COMPOSE_MAINTENANCE_LIVE_UNVERIFIED$') as error:
            self.run_check()
        self.assertNotIn('secret-canary',str(error.exception))

    def test_unexpected_runtime_or_mount_rejected_with_fixed_error(self):
        self.context()
        original=self.states['agent']
        mutations=[{'user':'0:0'},{'restart':'always'},{'pid_mode':'host'},
                   {'cmd':['--workers','8']},{'readonly_root':False},
                   {'selected_env':list(subject._EXPECTED_ENV)+['WEB_CONCURRENCY=8','__end__']},
                   {'mounts':[{'Type':'bind','RW':True,'Source':'secret-canary',
                               'Destination':'/run/uter-maintenance/key'}]},
                   {'mounts':original['mounts']+[{'Destination':'/run/uter-maintenance'}]}]
        for change in mutations:
            with self.subTest(change=list(change)):
                self.states['agent']=dict(original,**change)
                with self.assertRaisesRegex(subject.LiveProfileError,'^COMPOSE_MAINTENANCE_LIVE_UNVERIFIED$') as error:
                    self.run_check()
                self.assertNotIn('secret-canary',str(error.exception))
        self.states['agent']=original

    def test_container_restart_between_observations_cannot_succeed(self):
        self.context()
        first=self.states['agent'];calls=0
        def query(command,*args):
            nonlocal calls
            result=self.query(command,*args)
            if command[-1]==self.writers['agent']['id']:
                calls+=1
                if calls==2:return dict(first,pid=999)
            return result
        with patch.object(subject.docker,'_json',side_effect=query):
            with self.assertRaisesRegex(subject.LiveProfileError,'LIVE_UNVERIFIED'):
                self.run_check()

    def test_only_selected_env_values_are_requested_and_no_exec_is_used(self):
        self.assertNotIn('{{json .Config.Env}}',subject._CONTAINER_FORMAT)
        self.assertIn('split . "="',subject._CONTAINER_FORMAT)
        self.assertEqual(set(subject._EXPECTED_ENV),{'UTER_MAINTENANCE_ENABLED=true',
            'UTER_MAINTENANCE_KEY_FILE=/run/uter-maintenance/key','WEB_CONCURRENCY=1'})

    def test_cli_requires_signed_absolute_inputs_before_executor_load(self):
        with patch.object(uterctl,'_load_signed_fence_executor') as load:
            with self.assertRaisesRegex(ValueError,'MAINTENANCE_CHECK_PATH_NOT_ABSOLUTE'):
                uterctl.main(['maintenance-profile-check-compose','--home','relative','--bundle','/bundle',
                              '--key','/publisher','--executor-key','/executor'])
        load.assert_not_called()

    def test_cli_uses_signed_executor_and_serializing_lock(self):
        result={'backend':'compose','safe_to_update':False,'key_mount_identity_verified':False}
        with patch.object(uterctl,'_load_signed_fence_executor') as load, \
             patch.object(uterctl,'_fence_secret_inputs',return_value=('/home','/backup-key',b'k'*32)), \
             patch.object(uterctl,'fenced_locked',return_value=nullcontext()) as lock, \
             patch.object(subject,'check',return_value=result) as check, patch('builtins.print') as output:
            uterctl.main(['maintenance-profile-check-compose','--home','/home','--bundle','/bundle',
                          '--key','/publisher','--executor-key','/executor','--backup-key','/backup-key'])
        load.assert_called_once();lock.assert_called_once_with('/home');check.assert_called_once()
        self.assertIn('"safe_to_update": false',output.call_args.args[0])

    def test_fixture_refuses_non_hosted_context_before_docker(self):
        with patch.dict('os.environ',{},clear=True), patch.object(ci.install_recovery,'run_readonly') as run:
            with self.assertRaisesRegex(ValueError,'TEMPLATE_FIXTURE_ENVIRONMENT_UNVERIFIED'):
                ci.main()
            run.assert_not_called()

    def test_fixture_bad_create_id_uses_exact_name_and_checked_id_for_cleanup(self):
        calls=[];state={'list':0}; valid='a'*64
        def fake(*args,env):
            calls.append(args)
            if args[:2]==('context','inspect'):return '"unix:///var/run/docker.sock"'
            if args[0]=='ps':
                state['list']+=1
                return valid if state['list']==2 else ''
            if args[0]=='pull':return ''
            if args[0]=='create':
                state['name']=args[args.index('--name')+1]
                state['nonce']=state['name'].removeprefix('uter-template-fixture-')
                return 'invalid-id'
            if args[0]=='inspect':return state['nonce'] if 'Labels' in args[2] else '/'+state['name']
            if args[0]=='rm':return ''
            raise AssertionError
        settings={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                  'UTER_CI_TEMPLATE':'true'}
        with patch.dict('os.environ',settings,clear=True),patch.object(ci.sys,'platform','linux'), \
             patch.object(ci,'run',side_effect=fake):
            with self.assertRaises(ValueError):ci.main()
        self.assertTrue(any(call[0]=='rm' and valid in call for call in calls))
        self.assertFalse(any(call[0] in ('inspect','rm') and 'invalid-id' in call for call in calls))
