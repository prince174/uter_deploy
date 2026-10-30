import unittest
import subprocess
from unittest.mock import patch
from scripts import redis_acl_experiment as experiment
from scripts import redis_acl_experiment_ci


class RedisACLExperimentTests(unittest.TestCase):
    def setUp(self):
        self.run_id='a'*40; self.client='7'; self.admin='uter-maint-test'
        self.users=['default',self.admin]; self.role='master'; self.replicas='0'
        self.clients=['id=7 addr=local user='+self.admin,'id=8 addr=local user=default']
        self.off=False; self.intents=[]; self.commands=[]; self.failure=None
        self.modules=[]; self.functions=[]; self.loading='0'; self.aof='1'
        self.default_commands='-@all +get +set +ping'

    def call(self,*args):
        self.commands.append(args)
        if self.failure == args: raise TimeoutError
        if args == ('INFO','SERVER'): return 'run_id:'+self.run_id+'\r\n'
        if args == ('INFO','REPLICATION'): return 'role:'+self.role+'\r\nconnected_slaves:'+self.replicas+'\r\n'
        if args == ('INFO','PERSISTENCE'): return ('loading:'+self.loading+'\r\naof_enabled:'+self.aof+
            '\r\naof_rewrite_in_progress:0\r\nrdb_bgsave_in_progress:0\r\naof_last_write_status:ok\r\n')
        if args == ('MODULE','LIST'): return self.modules
        if args == ('FUNCTION','LIST'): return self.functions
        if args == ('CLIENT','ID'): return int(self.client)
        if args == ('ACL','USERS'): return self.users
        if args == ('CLIENT','LIST'): return '\n'.join(self.clients)+'\n'
        if args == ('ACL','SETUSER','default','off'): self.off=True; return 'OK'
        if args == ('CLIENT','KILL','USER','default','SKIPME','yes'):
            count=len(self.clients)-1; self.clients=self.clients[:1]; return count
        if args == ('ACL','GETUSER','default'): return {'flags':['off'] if self.off else ['on'],
            'passwords':['a'*64], 'commands':self.default_commands, 'selectors':[]}
        raise AssertionError(args)

    def intent(self,stage):
        if stage in self.intents: return False
        self.intents.append(stage); return True

    def run_it(self):
        return experiment.run(self.call, admin_user=self.admin, expected_run_id='a'*40,
                              expected_client_id='7', record_intent=self.intent)

    def test_kills_existing_clients_but_never_authorizes_backup(self):
        result=self.run_it()
        self.assertTrue(result['observed_only_admin'])
        self.assertFalse(result['safe_to_backup'])
        self.assertEqual(self.intents,['disable-default','kill-default'])
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()

    def test_unknown_acl_user_or_admin_connection_is_rejected_before_mutation(self):
        self.users.append('other')
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,[])
        self.users.pop(); self.clients.append('id=9 addr=local user='+self.admin)
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,[])

    def test_replicas_and_changed_process_rejected(self):
        self.replicas='1'
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.replicas='0'; self.run_id='b'*40
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,[])

    def test_modules_functions_and_unready_persistence_rejected(self):
        self.modules=['unknown']
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.modules=[]; self.functions=['unknown']
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.functions=[]; self.aof='0'
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,[])

    def test_privileged_default_is_rejected_before_any_mutation(self):
        self.default_commands='+@all'
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,[])

    def test_timeout_is_uncertain_and_never_retried(self):
        self.failure=('CLIENT','KILL','USER','default','SKIPME','yes')
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.intents,['disable-default','kill-default'])
        with self.assertRaises(experiment.ACLExperimentError): self.run_it()
        self.assertEqual(self.commands.count(self.failure),1)

    def test_ci_probe_refuses_non_hosted_runner_before_docker(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted',
                                      'RUNNER_OS':'Linux'}, clear=True), \
             patch.object(redis_acl_experiment_ci,'docker') as docker:
            with self.assertRaises(ValueError): redis_acl_experiment_ci.main()
            docker.assert_not_called()

    def test_ci_cleanup_rejects_ambiguous_confirmed_container(self):
        error=subprocess.CalledProcessError(1,['docker'])
        with patch.object(redis_acl_experiment_ci,'docker',side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                redis_acl_experiment_ci.cleanup_container('fixture','nonce','a'*64)
        with patch.object(redis_acl_experiment_ci,'docker',return_value='different') as docker:
            with self.assertRaises(ValueError):
                redis_acl_experiment_ci.cleanup_container('fixture','nonce','a'*64)
            self.assertEqual(docker.call_count,1)


if __name__ == '__main__': unittest.main()
