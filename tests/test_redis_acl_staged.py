import unittest
import io
from types import SimpleNamespace
from unittest.mock import Mock, patch
from scripts import redis_acl_staged as subject, redis_acl_experiment as base
from scripts import redis_acl_staged_ci as ci


class StagedAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.profile_patch=patch.object(subject,'verify_profile',return_value={'version':'fixture'})
        self.profile_patch.start();self.addCleanup(self.profile_patch.stop)
        self.run_id='a'*40;self.admin='uter-maint-test';self.client='7'
        self.on=True;self.intents=[];self.receipts=[];self.calls=[];self.failure=None
        self.clients=['id=7 user='+self.admin,'id=8 user=uter-writer']
        self.roles=['default',self.admin,'uter-writer'];self.commands=set(base._UTER_TEST)
        self.guard=True;self.admin_hash='b'*64
        self.session=subject.StagedAdmission(self.call,bundle='/bundle',publisher='/pub',admin_user=self.admin,run_id=self.run_id,
            client_id=self.client,record_intent=self.intent,record_receipt=self.receipt,identity_guard=lambda:self.guard)

    def call(self,*args):
        self.calls.append(args)
        if self.failure==args:raise TimeoutError('secret-canary')
        if args==('INFO','SERVER'):return 'run_id:'+self.run_id+'\r\n'
        if args==('INFO','REPLICATION'):return 'role:master\r\nconnected_slaves:0\r\n'
        if args==('INFO','PERSISTENCE'):return 'loading:0\r\naof_enabled:1\r\naof_last_write_status:ok\r\naof_rewrite_in_progress:0\r\nrdb_bgsave_in_progress:0\r\n'
        if args in (('MODULE','LIST'),('FUNCTION','LIST')):return []
        if args==('CLIENT','ID'):return 7
        if args==('ACL','USERS'):return self.roles
        if args==('CLIENT','LIST'):return '\n'.join(self.clients)
        if args==('ACL','GETUSER','default'):return {'flags':['off','nopass'],'passwords':[],'commands':'-@all','selectors':[]}
        if args==('ACL','GETUSER',self.admin):return {'flags':['on'],'passwords':[self.admin_hash],'commands':'+@all','selectors':[]}
        if args==('ACL','GETUSER','uter-writer'):return {'flags':['on' if self.on else 'off'],
            'passwords':['c'*64],'commands':'-@all '+' '.join(sorted(self.commands)),
            'keys':'~*','channels':'&*','selectors':[]}
        if args==('ACL','SETUSER','uter-writer','off'):self.on=False;return 'OK'
        if args==('CLIENT','KILL','USER','uter-writer','SKIPME','yes'):
            count=len(self.clients)-1;self.clients=self.clients[:1];return count
        raise AssertionError(args)

    def intent(self,name):
        if name in self.intents:return False
        self.intents.append(name);return True

    def receipt(self,name):
        if name in self.receipts:return False
        self.receipts.append(name);return True

    def test_stages_preserve_existing_clients_until_drain(self):
        first=self.session.disable_new_auth()
        self.assertFalse(self.on);self.assertEqual(first['prior_writer_connections_retained'],1)
        self.assertEqual(self.intents,['disable-writer-auth']);self.assertEqual(len(self.clients),2)
        self.assertNotIn(('CLIENT','KILL','USER','uter-writer','SKIPME','yes'),self.calls)
        result=self.session.finish_after_drain(lambda:True)
        self.assertEqual(result['writer_clients_killed'],1)
        self.assertFalse(result['safe_to_backup']);self.assertFalse(result['safe_to_update'])
        self.assertEqual(self.intents,['disable-writer-auth','kill-writer-clients'])
        self.assertEqual(self.receipts,['writer-auth-disabled','writer-clients-killed'])

    def test_unknown_extra_user_or_privileged_writer_refuses_before_mutation(self):
        self.roles.append('other')
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertFalse(self.intents);self.assertTrue(self.on)
        self.setUp();self.commands.add('+acl')
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertFalse(self.intents);self.assertTrue(self.on)

    def test_unknown_result_cannot_be_retried_or_advance(self):
        self.failure=('ACL','SETUSER','uter-writer','off')
        with self.assertRaises(subject.StagedError) as error:self.session.disable_new_auth()
        self.assertNotIn('secret-canary',str(error.exception))
        self.assertEqual(self.session.phase,'uncertain')
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:True)
        self.assertEqual(self.calls.count(self.failure),1)

    def test_lost_response_after_disable_applied_cannot_retry(self):
        call=self.session.execute
        def lose_response(*args):
            result=call(*args)
            if args==('ACL','SETUSER','uter-writer','off'):raise TimeoutError
            return result
        self.session.execute=lose_response
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertFalse(self.on);self.assertEqual(self.intents,['disable-writer-auth'])
        self.assertFalse(self.receipts);self.assertEqual(self.session.phase,'uncertain')
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertEqual(self.calls.count(('ACL','SETUSER','uter-writer','off')),1)

    def test_lost_response_after_kill_applied_cannot_retry(self):
        self.session.disable_new_auth();call=self.session.execute
        def lose_response(*args):
            result=call(*args)
            if args==('CLIENT','KILL','USER','uter-writer','SKIPME','yes'):raise TimeoutError
            return result
        self.session.execute=lose_response
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:True)
        self.assertEqual(len(self.clients),1);self.assertEqual(self.session.phase,'uncertain')
        self.assertEqual(self.receipts,['writer-auth-disabled'])
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:True)
        self.assertEqual(self.calls.count(('CLIENT','KILL','USER','uter-writer','SKIPME','yes')),1)

    def test_restart_or_failed_drain_prevents_killing_existing_clients(self):
        self.session.disable_new_auth();self.run_id='f'*40
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:True)
        self.assertNotIn(('CLIENT','KILL','USER','uter-writer','SKIPME','yes'),self.calls)
        self.setUp();self.session.disable_new_auth()
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:False)
        self.assertNotIn(('CLIENT','KILL','USER','uter-writer','SKIPME','yes'),self.calls)

    def test_lost_identity_guard_prevents_next_mutation(self):
        self.session.disable_new_auth();self.guard=False
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:True)
        self.assertNotIn(('CLIENT','KILL','USER','uter-writer','SKIPME','yes'),self.calls)

    def test_shared_writer_and_admin_password_rejected_before_intent(self):
        self.admin_hash='c'*64
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertFalse(self.intents);self.assertTrue(self.on)

    def test_lost_drain_guard_during_durable_intent_forbids_kill(self):
        self.session.disable_new_auth();allowed=[True]
        original=self.session.intent
        def lose_guard(stage):
            result=original(stage);allowed[0]=False;return result
        self.session.intent=lose_guard
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:allowed[0])
        self.assertEqual(self.session.phase,'uncertain')
        self.assertNotIn(('CLIENT','KILL','USER','uter-writer','SKIPME','yes'),self.calls)

    def test_loss_of_identity_during_receipt_does_not_return_success(self):
        original=self.session.receipt
        def lose_guard(stage):
            result=original(stage);self.guard=False;return result
        self.session.receipt=lose_guard
        with self.assertRaises(subject.StagedError):self.session.disable_new_auth()
        self.assertEqual(self.session.phase,'uncertain')

    def test_loss_of_drain_during_final_receipt_does_not_return_success(self):
        self.session.disable_new_auth();allowed=[True]
        original=self.session.receipt
        def lose_guard(stage):
            result=original(stage);allowed[0]=False;return result
        self.session.receipt=lose_guard
        with self.assertRaises(subject.StagedError):self.session.finish_after_drain(lambda:allowed[0])
        self.assertEqual(self.session.phase,'uncertain')

    def test_ci_refuses_non_hosted_before_docker(self):
        with patch.dict('os.environ',{},clear=True),patch.object(ci,'docker') as docker:
            with self.assertRaisesRegex(ValueError,'STAGED_ACL_FIXTURE_ENVIRONMENT_UNVERIFIED'):
                ci.main()
            docker.assert_not_called()

    def test_ci_auth_classifies_only_ok_and_wrongpass(self):
        for response,expected in ((b'+OK\r\n',True),(b'-WRONGPASS disabled\r\n',False)):
            client=SimpleNamespace(sock=Mock(),file=io.BytesIO(response))
            self.assertIs(ci.auth(client,'user','key'),expected)
        for response in (b'-LOADING retry\r\n',b'-ERR unexpected\r\n',b'+NOT-OK\r\n',b'-WRONGPASS truncated'):
            client=SimpleNamespace(sock=Mock(),file=io.BytesIO(response))
            with self.assertRaisesRegex(ValueError,'AUTH_RESPONSE_UNVERIFIED') as error:
                ci.auth(client,'user','key')
            self.assertNotIn('retry',str(error.exception))

    def test_ci_identity_mount_order_is_normalized_without_masking_changes(self):
        left={'mounts':[{'Destination':'/b','RW':False},{'Destination':'/a','RW':True}],'pid':1}
        right={'mounts':list(reversed(left['mounts'])),'pid':1}
        self.assertEqual(ci.normalize_mounts(left),ci.normalize_mounts(right))
        right['mounts'][0]={'Destination':'/a','RW':False}
        self.assertNotEqual(ci.normalize_mounts(left),ci.normalize_mounts(right))
        with self.assertRaises(ValueError):
            ci.normalize_mounts({'mounts':[{'Destination':'/a'},{'Destination':'/a'}]})
