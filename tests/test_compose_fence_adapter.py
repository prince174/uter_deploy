import os
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts import compose_fence_adapter as fence


@unittest.skipUnless(os.name == 'posix', 'Compose fence requires a POSIX controller lock')
class ComposeFenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.adapter = fence.Adapter(self.home, self.home/'bundle', self.home/'key', b'k'*32)
        self.plan = {'site':'uter-test', 'container_id':'a'*64, 'network_id':'b'*64,
                     'network_name':'uter-test_backend', 'volume_name':'uter-test_redis-data',
                     'started_at':'2026-10-30T00:00:00Z', 'restart_count':0,
                     'image_ref':'ghcr.io/test/redis@sha256:'+'c'*64, 'image_config_id':'sha256:'+'d'*64,
                     'endpoint_ipv4':'172.30.0.5', 'endpoint_mac':'02:42:ac:1e:00:05',
                     'endpoint_aliases':['redis','uter-test-redis-1'], 'network_subnet':'172.30.0.0/16',
                     'network_gateway':'172.30.0.1'}
        runtime=self.home/'runtime';runtime.mkdir()
        for name in ('redis.conf','redis-password'):
            (runtime/name).write_text('synthetic');(runtime/name).chmod(0o600)
        self.state = {'id':'a'*64, 'running':True, 'pid':23, 'started':self.plan['started_at'], 'restart_count':0,
                      'image':self.plan['image_ref'], 'image_id':self.plan['image_config_id'], 'restart':'no',
                      'network_mode':'uter-test_backend', 'ports':None, 'publish_all':False, 'runtime_ports':{},
                      'privileged':False, 'pid_mode':'', 'cap_add':None, 'readonly':True,'init':True,'user':'999:1000',
                      'tmpfs':{'/tmp':'size=128m,mode=1777'},'command':['redis-server','/usr/local/etc/redis/redis.conf'],
                      'entrypoint':['docker-entrypoint.sh'],
                      'mounts':[{'Type':'volume','Name':self.plan['volume_name'],'Destination':'/data','RW':True},
                                {'Type':'bind','Source':str(runtime/'redis.conf'),'Destination':'/usr/local/etc/redis/redis.conf','RW':False},
                                {'Type':'bind','Source':str(runtime/'redis-password'),'Destination':'/run/secrets/redis_password','RW':False}],
                      'networks':{}}
        self.record = {'operation':'1'*32,'site':'uter-test','resource':'a'*64,'plan_sha256':'b'*64}

    def test_controller_lock_is_owned_by_current_process_and_private(self):
        path = self.home/'operation.lock'
        path.write_text(str(os.getpid())); path.chmod(0o600)
        self.adapter._lock()
        path.write_text(str(os.getpid()+1))
        with self.assertRaisesRegex(fence.ComposeFenceAdapterError, 'LOCK_INVALID'): self.adapter._lock()
        path.write_text(str(os.getpid()));path.chmod(0o644)
        with self.assertRaisesRegex(fence.ComposeFenceAdapterError, 'LOCK_INVALID'): self.adapter._lock()
        path.unlink();path.symlink_to(self.home/'untrusted')
        with self.assertRaisesRegex(fence.ComposeFenceAdapterError, 'LOCK_INVALID'): self.adapter._lock()

    def test_only_exact_signed_config_is_allowed_and_errors_never_expose_secrets(self):
        install=self.home/'signed';(install/'compose').mkdir(parents=True);(install/'examples').mkdir()
        (install/'compose/compose.yaml').write_text('services:\n  redis:\n    command: [redis-server, /usr/local/etc/redis/redis.conf]\n')
        template=b'bind 0.0.0.0\nappendonly yes\nrequirepass REPLACE\n'
        (install/'examples/redis.conf.example').write_bytes(template)
        password=b'a'*64
        (self.home/'runtime/redis-password').write_bytes(password)
        config=self.home/'runtime/redis.conf';config.write_bytes(template.replace(b'REPLACE',password))
        self.adapter._config(install)
        for changed in (template.replace(b'REPLACE',password)+b'loadmodule /tmp/unsafe.so\n',
                        template.replace(b'REPLACE',password)+b'unixsocket /data/socket\n'):
            config.write_bytes(changed)
            with self.assertRaisesRegex(fence.ComposeFenceAdapterError,'^COMPOSE_FENCE_CONFIG_UNSUPPORTED$') as error:
                self.adapter._config(install)
            self.assertNotIn(password.decode(),str(error.exception))
        config.write_bytes(template.replace(b'REPLACE',password))
        (install/'compose/compose.yaml').write_text('services:\n  redis:\n    command: [sh, -c, unsafe]\n')
        with self.assertRaises(fence.ComposeFenceAdapterError):self.adapter._config(install)

    def test_detached_state_requires_same_process_image_volume_and_no_network(self):
        with mock.patch.object(self.adapter,'_verify_process'), mock.patch.object(self.adapter,'_json',return_value=['docker-entrypoint.sh']), \
             mock.patch.object(self.adapter, '_inspect_redis', return_value=self.state):
            self.assertEqual(self.adapter._state(self.plan,detached=True,restart='no'),self.state)
        for change in ({'restart':'unless-stopped'}, {'started':'different'}, {'restart_count':1},
                       {'networks':{'rogue':{}}}, {'ports':{'6379/tcp':[{}]}}, {'publish_all':True},
                       {'image_id':'sha256:'+'f'*64}, {'privileged':True}, {'network_mode':'host'},
                       {'runtime_ports':{'6379/tcp':[{'HostPort':'6379'}]}}, {'readonly':False},
                       {'user':'0:0'}, {'init':False}, {'command':['/bin/sh']}, {'tmpfs':{'/tmp':'rw','/bin':'rw'}},
                       {'mounts':self.state['mounts']+[{'Type':'bind','Destination':'/usr/local/bin/redis-cli','RW':True}]}):
            with self.subTest(change=change), mock.patch.object(self.adapter,'_verify_process'), \
                 mock.patch.object(self.adapter,'_json',return_value=['docker-entrypoint.sh']), \
                 mock.patch.object(self.adapter, '_inspect_redis', return_value=dict(self.state,**change)):
                with self.assertRaises(fence.ComposeFenceAdapterError): self.adapter._state(self.plan,detached=True,restart='no')

    def test_host_process_identity_checks_init_parent_executable_uid_and_container_cgroup(self):
        proc=self.home/'proc';proc.mkdir();target=proc/'246';target.mkdir()
        (target/'stat').write_text('246 (redis-server) '+ ' '.join(['S']+['0']*18+['1234']+['0']*5))
        (target/'status').write_text('Name:\tredis-server\nPid:\t246\nPPid:\t23\nUid:\t999\t999\t999\t999\n')
        (target/'cgroup').write_text('0::/docker/'+self.plan['container_id']+'\n')
        (target/'exe').symlink_to('/usr/local/bin/redis-server')
        with mock.patch.object(fence,'PROC_ROOT',proc), mock.patch.object(fence.os,'geteuid',return_value=0), \
             mock.patch.object(self.adapter,'_run',return_value='PID PPID COMMAND\n246 23 redis-server') as run:
            self.adapter._verify_process(self.plan,23)
            self.assertEqual(run.call_args.args,('top',self.plan['container_id'],'-eo','pid,ppid,comm'))
            (target/'cgroup').write_text('0::/docker/'+'f'*64+'\n')
            with self.assertRaisesRegex(fence.ComposeFenceAdapterError,'EXECUTABLE_UNVERIFIED'):
                self.adapter._verify_process(self.plan,23)
            (target/'cgroup').write_text('0::/docker/'+self.plan['container_id']+'\n')
            (target/'status').write_text('Name:\tredis-server\nPid:\t246\nPPid:\t23\nUid:\t0\t0\t0\t0\n')
            with self.assertRaisesRegex(fence.ComposeFenceAdapterError,'EXECUTABLE_UNVERIFIED'):
                self.adapter._verify_process(self.plan,23)
        with mock.patch.object(fence.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(fence.ComposeFenceAdapterError,'EXECUTABLE_UNVERIFIED'):
                self.adapter._verify_process(self.plan,23)

    def test_peer_network_namespace_and_volume_are_rejected(self):
        peer='f'*64
        for mode, mounts, target in (('container:'+self.plan['container_id'],[],self.plan['container_id']),
                                      ('bridge',[{'Type':'volume','Name':self.plan['volume_name']}],None)):
            with self.subTest(mode=mode), mock.patch.object(self.adapter,'_run',return_value=peer), \
                 mock.patch.object(self.adapter,'_json',side_effect=[{'mode':mode,'mounts':mounts},target]):
                with self.assertRaises(fence.ComposeFenceAdapterError): self.adapter._peers(self.plan)

    def test_close_requires_all_client_types_and_single_remaining_cli(self):
        with mock.patch.object(self.adapter,'_plan',return_value=self.plan), mock.patch.object(self.adapter,'_lock'), \
             mock.patch.object(self.adapter,'_state'), mock.patch.object(self.adapter,'_peers'), \
             mock.patch.object(self.adapter,'_redis',side_effect=['1','0','0','0','id=4 flags=N cmd=client|list']) as redis:
            self.adapter.close_external_clients(self.record)
        self.assertEqual([c.args[1:] for c in redis.call_args_list[:4]],
                         [('CLIENT','KILL','TYPE',k,'SKIPME','yes') for k in ('normal','pubsub','replica','master')])

    def test_client_kill_error_or_remaining_client_is_failure(self):
        for replies in (['ERR unsupported'], ['0','0','0','0','id=1 flags=N\nid=2 flags=N'],
                        ['0','0','0','0',''], ['0','0','0','0','id=1 flags=S']):
            with self.subTest(replies=replies), mock.patch.object(self.adapter,'_plan',return_value=self.plan), \
                 mock.patch.object(self.adapter,'_lock'), mock.patch.object(self.adapter,'_state'), \
                 mock.patch.object(self.adapter,'_peers'), mock.patch.object(self.adapter,'_redis',side_effect=replies):
                with self.assertRaises(fence.ComposeFenceAdapterError): self.adapter.close_external_clients(self.record)

    def test_redis_requires_no_unix_socket_master_without_replicas_and_healthy_aof(self):
        good = ['unixsocket', 'role:master\nconnected_slaves:0', 'aof_enabled:1\naof_last_write_status:ok', '']
        with mock.patch.object(self.adapter,'_redis',side_effect=good): self.adapter._redis_config(self.plan)
        for replies in (['unixsocket\n/run/redis.sock'], ['unixsocket','role:slave\nconnected_slaves:0'],
                        ['unixsocket','role:master\nconnected_slaves:1'],
                        ['unixsocket','role:master\nconnected_slaves:0','aof_enabled:0'],
                        ['unixsocket','role:master\nconnected_slaves:0','aof_enabled:1\naof_last_write_status:err'],
                        ['unixsocket','role:master\nconnected_slaves:0','aof_enabled:1\naof_last_write_status:ok','name=malicious']):
            with self.subTest(replies=replies), mock.patch.object(self.adapter,'_redis',side_effect=replies):
                with self.assertRaises(fence.ComposeFenceAdapterError): self.adapter._redis_config(self.plan)

    def test_network_and_volume_must_match_recorded_local_topology(self):
        network={'id':self.plan['network_id'],'name':self.plan['network_name'],'driver':'bridge',
                 'scope':'local','internal':True,'ipv6':False,'options':{},'project':self.plan['site'],
                 'network':'backend','ipam':{'Driver':'default','Options':None,'Config':[
                     {'Subnet':self.plan['network_subnet'],'Gateway':self.plan['network_gateway']}]}}
        volume={'name':self.plan['volume_name'],'driver':'local','options':{},'project':self.plan['site'],'volume':'redis-data'}
        with mock.patch.object(self.adapter,'_json',side_effect=[network,volume]): self.adapter._network_and_volume(self.plan)
        for change in ({'internal':False}, {'ipv6':True}, {'driver':'overlay'}, {'id':'f'*64},
                       {'ipam':{'Driver':'default','Config':[{'Subnet':'172.31.0.0/16','Gateway':'172.31.0.1'}]}}):
            with self.subTest(change=change), mock.patch.object(self.adapter,'_json',side_effect=[dict(network,**change),volume]):
                with self.assertRaises(fence.ComposeFenceAdapterError): self.adapter._network_and_volume(self.plan)

    def test_isolation_check_requires_signed_identity_and_rechecks_state(self):
        with mock.patch.object(self.adapter,'_plan',return_value=self.plan), mock.patch.object(self.adapter,'_signed') as signed, \
             mock.patch.object(self.adapter,'_state') as state, mock.patch.object(self.adapter,'_network_and_volume'), \
             mock.patch.object(self.adapter,'_peers'), mock.patch.object(self.adapter,'_redis_config'), \
             mock.patch.object(self.adapter,'_no_other_clients'):
            self.assertIs(self.adapter.verify_isolated(self.record),True)
        signed.assert_called_once_with(self.plan);self.assertEqual(state.call_count,2)

    def test_unknown_mutation_does_not_trigger_automatic_reconnect(self):
        with mock.patch.object(self.adapter,'_plan',return_value=self.plan), mock.patch.object(self.adapter,'_lock'), \
             mock.patch.object(self.adapter,'_state'), mock.patch.object(self.adapter,'_run',side_effect=fence.ComposeFenceAdapterError('uncertain')) as run:
            with self.assertRaisesRegex(fence.ComposeFenceAdapterError,'uncertain'):
                self.adapter.disconnect_network(self.record)
        self.assertEqual(run.call_count,1)
        self.assertFalse(self.adapter.verify_old_restoration_safe(self.record))


if __name__ == '__main__': unittest.main()
