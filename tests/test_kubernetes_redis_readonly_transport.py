import tempfile
import subprocess
import os
import time
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import kubernetes_redis_readonly_transport as transport


class FixtureSession:
    def __init__(self,home,bundle):
        self.home=home;self.site='uter-ci';self._executor=object()
        self._record={'kubectl_sha256':'a'*64};self.config_sha256='b'*64
        self._inner=SimpleNamespace(bundle=bundle,config_fd=3,api=SimpleNamespace(binary_fd=4,context='kind-ci'))
    def _guard(self): pass
    def reverify(self): pass


class ReadonlyTransportTests(unittest.TestCase):
    def resp(self,data):
        reader,writer=os.pipe()
        self.addCleanup(os.close,reader);self.addCleanup(os.close,writer)
        os.write(writer,data)
        process=SimpleNamespace(stdout=SimpleNamespace(fileno=lambda:reader))
        value=transport.Connection(process,None,None,'a'*32,'b'*40);value._reply_bytes=0
        return value

    def test_resp2_nested_bulk_and_integer(self):
        value=self.resp(b'*4\r\n$5\r\nflags\r\n*1\r\n$2\r\non\r\n$5\r\ncount\r\n:7\r\n')
        self.assertEqual(value._reply(time.monotonic()+2,0),['flags',['on'],'count',7])
        self.assertEqual(value.buffer,bytearray())

    def test_resp2_malformed_error_and_limits_fail_closed(self):
        for data in (b'-ERR failed\r\n',b'+a\nb\r\n',b'+a\rb\r\n',b'$-2\r\n',b':-0\r\n',b'$262145\r\n',b'*4097\r\n',
                     b'*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+ok\r\n',b'$3\r\nabcXX'):
            with self.subTest(data=data):
                value=self.resp(data)
                with self.assertRaises((ValueError,TimeoutError)):
                    value._reply(time.monotonic()+0.05,0)

    def test_exchange_serializes_auth_and_rejects_extra_response(self):
        command_read,command_write=os.pipe();reply_read,reply_write=os.pipe()
        for fd in (command_read,command_write,reply_read,reply_write): self.addCleanup(os.close,fd)
        process=SimpleNamespace(stdin=SimpleNamespace(fileno=lambda:command_write),
                                stdout=SimpleNamespace(fileno=lambda:reply_read))
        value=transport.Connection(process,None,None,'a'*32,'b'*40)
        observed=[]
        def respond():
            observed.append(os.read(command_read,512));os.write(reply_write,b'+OK\r\n')
            observed.append(os.read(command_read,512));os.write(reply_write,b'+OK\r\n+EXTRA\r\n')
        worker=threading.Thread(target=respond);worker.start()
        self.assertEqual(value._exchange(('AUTH','uter-maint-test','d'*64)),'OK')
        wire=observed[0]
        self.assertTrue(wire.startswith(b'*3\r\n$4\r\nAUTH\r\n'))
        self.assertIn(b'$64\r\n'+b'd'*64+b'\r\n',wire)
        try:
            with self.assertRaises(ValueError): value._exchange(('CLIENT','ID'))
        finally: worker.join(timeout=2)

    def test_fragmented_bulk_frame_is_reassembled(self):
        reader,writer=os.pipe()
        self.addCleanup(os.close,reader);self.addCleanup(os.close,writer)
        process=SimpleNamespace(stdout=SimpleNamespace(fileno=lambda:reader))
        value=transport.Connection(process,None,None,'a'*32,'b'*40);value._reply_bytes=0
        def send():
            for part in (b'$5\r',b'\nhe',b'll',b'o\r',b'\n'):
                os.write(writer,part);time.sleep(.002)
        worker=threading.Thread(target=send);worker.start()
        try: self.assertEqual(value._reply(time.monotonic()+2,0),'hello')
        finally: worker.join(timeout=2)

    def test_nested_arrays_share_one_element_budget(self):
        value=self.resp(b'')
        value.buffer=bytearray(b'*2\r\n'+(b'*2048\r\n'+b'$-1\r\n'*2048)*2)
        with self.assertRaises(ValueError): value._reply(time.monotonic()+2,0)

    def test_extra_frame_arriving_before_next_command_is_rejected(self):
        command_read,command_write=os.pipe();reply_read,reply_write=os.pipe()
        for fd in (command_read,command_write,reply_read,reply_write): self.addCleanup(os.close,fd)
        process=SimpleNamespace(stdin=SimpleNamespace(fileno=lambda:command_write),
                                stdout=SimpleNamespace(fileno=lambda:reply_read))
        value=transport.Connection(process,None,None,'a'*32,'b'*40)
        def respond():
            os.read(command_read,512);os.write(reply_write,b'+OK\r\n')
        worker=threading.Thread(target=respond);worker.start()
        try: self.assertEqual(value._exchange(('CLIENT','ID')),'OK')
        finally: worker.join(timeout=2)
        os.write(reply_write,b'+EXTRA\r\n')
        with self.assertRaises(ValueError): value._exchange(('CLIENT','ID'))

    def test_unknown_commands_refused_before_any_io(self):
        value=transport.Connection(None,None,None,'a'*32,'b'*40)
        with patch.object(value,'_scope') as scope,patch.object(value,'_exchange') as exchange:
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('SET','key','value')
            scope.assert_not_called();exchange.assert_not_called()

    def test_mismatched_run_id_and_changed_client_id_fail_closed(self):
        value=transport.Connection(None,None,None,'a'*32,'b'*40);value.client_id='7'
        with patch.object(value,'_scope'),patch.object(value,'_exchange',side_effect=['run_id:'+'c'*40,7]) as exchange:
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('CLIENT','LIST')
            self.assertEqual(exchange.call_count,1)
            self.assertEqual(value.identity_detail,'RUN_MISMATCH')
        value.failed=False
        with patch.object(value,'_scope'),patch.object(value,'_exchange',side_effect=['run_id:'+'b'*40,8]) as exchange:
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('CLIENT','LIST')
            self.assertEqual(exchange.call_count,2)
            self.assertEqual(value.identity_detail,'CLIENT_CHANGED')

    def test_info_format_and_client_type_have_fixed_categories(self):
        value=transport.Connection(None,None,None,'a'*32,'b'*40)
        with patch.object(value,'_scope'),patch.object(value,'_exchange',return_value={}):
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('CLIENT','LIST')
            self.assertEqual(value.identity_detail,'INFO_FORMAT')
        value.failed=False
        with patch.object(value,'_scope'),patch.object(value,'_exchange',side_effect=['run_id:'+'b'*40,'7']):
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('CLIENT','LIST')
            self.assertEqual(value.identity_detail,'CLIENT_TYPE')

    def test_duplicate_acl_fields_are_rejected(self):
        value=transport.Connection(None,None,None,'a'*32,'b'*40);value.client_id='7'
        replies=['run_id:'+'b'*40,7,['flags',['on'],'flags',['off']],'run_id:'+'b'*40,7]
        with patch.object(value,'_scope'),patch.object(value,'_exchange',side_effect=replies):
            with self.assertRaises(transport.ReadonlyTransportError): value.execute('ACL','GETUSER','default')

    def test_uncertain_cleanup_always_closes_both_streams_and_fails(self):
        proc=SimpleNamespace(pid=12345,stdin=Mock(),stdout=Mock(),
                             wait=Mock(side_effect=subprocess.TimeoutExpired('kubectl',5)))
        proc.stdin.close.side_effect=OSError
        with patch.object(transport.os,'killpg'):
            with self.assertRaisesRegex(transport.ReadonlyTransportError,'CLEANUP_UNCERTAIN'):
                transport._cleanup(proc)
        proc.wait.assert_called_once();proc.stdin.close.assert_called_once();proc.stdout.close.assert_called_once()

    def test_expiry_during_scope_is_not_reported_as_success(self):
        session=FixtureSession(Path('/tmp/home'),Path('/tmp/bundle'))
        value=transport.Connection(None,session,{},'a'*32,'b'*40)
        value.deadline=10
        with patch.object(transport.time,'monotonic',side_effect=[9,11]), \
             patch.object(transport.finalizer,'_check_journal'), \
             patch.object(transport.redis_acl_operation_inspection,'_verify_plan_pod'), \
             patch.object(transport.kubernetes_trusted_kubectl,'verify'), \
             patch.object(transport.kubernetes_sealed_config,'verify_sealed'):
            with self.assertRaises(TimeoutError): value._scope()

    def test_auth_is_not_in_kubectl_argv(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);home=root/'home';home.mkdir();bundle=root/'bundle';bundle.mkdir()
            key=root/'admin';key.write_text('d'*64);key.chmod(0o600)
            session=FixtureSession(home,bundle);proc=SimpleNamespace(pid=12345,stdin=Mock(),stdout=Mock(),wait=Mock())
            plan={'pod':'uter-ci-redis-abcd-xyz'}
            with patch.object(transport.coordinator,'BoundSession',FixtureSession), \
                 patch.object(transport.finalizer,'read_plan',return_value=plan), \
                 patch.object(transport.finalizer,'_check_journal'), \
                 patch.object(transport.redis_acl_operation_inspection,'_verify_plan_pod'), \
                 patch.object(transport.kubernetes_trusted_kubectl,'verify'), \
                 patch.object(transport.kubernetes_sealed_config,'verify_sealed'), \
                 patch.object(transport.subprocess,'Popen',return_value=proc) as spawn, \
                 patch.object(transport.Connection,'_scope'), \
                 patch.object(transport.Connection,'_identity',return_value='9'), \
                 patch.object(transport.Connection,'_exchange',return_value='OK') as exchange, \
                 patch.object(transport.os,'killpg'):
                with transport.connect(session,'a'*32,'uter-maint-test',key,'b'*40) as connection:
                    self.assertEqual(connection.client_id,'9')
                argv=spawn.call_args.args[0]
                self.assertNotIn('d'*64,' '.join(argv))
                self.assertIn(('AUTH','uter-maint-test','d'*64),[c.args[0] for c in exchange.call_args_list])


if __name__ == '__main__': unittest.main()
