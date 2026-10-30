import socket
import threading
import time
import unittest
from unittest.mock import patch

from scripts import redis_digest_resp as digest


class RedisDigestTests(unittest.TestCase):
    def setUp(self):
        self.values={b'binary\x00key':(b'RDB\x00value',1700000000000),b'another':(b'value',-1)}
        self.modules=[];self.functions=[];self.order=list(self.values)
        outer=self
        class Fake:
            def __init__(inner,*args):pass
            def close(inner):pass
            def command(inner,*args):
                if args[0]=='AUTH':return b'OK'
                if args[0]=='PING':return b'PONG'
                if args[:2]==('CONFIG','GET'):return [b'databases',b'1']
                if args[0]=='MODULE':return outer.modules
                if args[0]=='FUNCTION':return outer.functions
                if args[0]=='SELECT':return b'OK'
                if args[0]=='SCAN':return [b'0',outer.order]
                if args[0]=='DUMP':return outer.values[args[1]][0]
                if args[0]=='PEXPIRETIME':return outer.values[args[1]][1]
                if args[0]=='DBSIZE':return len(outer.values)
                raise ValueError
        self.fake=Fake

    def invoke(self):
        with patch.object(digest,'Client',self.fake):return digest.fingerprint(object(),b'password',b'k'*32)

    def test_binary_values_are_order_independent_and_expiry_sensitive(self):
        first=self.invoke();self.order.reverse();second=self.invoke()
        self.assertEqual(first['digest'],second['digest']);self.assertFalse(first['rdb_compared'])
        self.assertFalse(first['safe_to_resume']);self.assertNotIn('binary',str(first))
        self.values[b'another']=(b'value',1700000000000)
        self.assertNotEqual(self.invoke()['digest'],first['digest'])

    def test_modules_functions_and_disappearing_key_fail_closed(self):
        self.modules=[b'unknown']
        with self.assertRaises(digest.RedisDigestError):self.invoke()
        self.modules=[];self.functions=[b'unknown']
        with self.assertRaises(digest.RedisDigestError):self.invoke()
        self.functions=[];self.values[b'another']=(b'value',-2)
        with self.assertRaises(digest.RedisDigestError):self.invoke()

    def test_resp_parser_is_binary_safe(self):
        left,right=socket.socketpair()
        def server():
            try:
                right.recv(4096)
                right.sendall(b'*2\r\n$3\r\na\x00b\r\n:42\r\n')
            finally:right.close()
        thread=threading.Thread(target=server);thread.start()
        try:
            client=digest.Client(left,time.monotonic()+5)
            self.assertEqual(client.command('TEST'),[b'a\x00b',42]);client.close()
        finally:left.close();thread.join()

    def test_recursive_reply_budget_rejects_before_large_allocation(self):
        for frame,budget in ((b'*2\r\n$1000\r\n',[20,100]),(b'*10000\r\n',[100,2])):
            left,right=socket.socketpair()
            try:
                right.sendall(frame)
                client=digest.Client(left,time.monotonic()+2)
                with self.subTest(frame=frame),self.assertRaises(ValueError):client._reply(budget=budget)
                client.close()
            finally:left.close();right.close()
