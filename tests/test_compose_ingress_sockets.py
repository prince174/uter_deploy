import unittest

from scripts import compose_ingress_sockets as sockets


class IngressSocketInventoryTests(unittest.TestCase):
    def check(self, extra=b''):
        return sockets.inspect(b'LISTEN 0 128 0.0.0.0:8000 0.0.0.0:*\n'+extra,
                               port=8000,service_addresses=('172.23.0.4','172.24.0.4'),
                               peer_addresses=('172.23.0.5','172.24.0.5'))

    def test_allows_only_loopback_and_authenticated_service_peer(self):
        self.assertTrue(self.check(b'ESTAB 0 0 172.23.0.4:8000 172.23.0.5:43210\n'
                                   b'ESTAB 0 0 127.0.0.1:8000 127.0.0.1:39000\n'))

    def test_existing_external_keepalive_and_half_closed_connections_block(self):
        for state in (b'ESTAB', b'SYN-RECV', b'CLOSE-WAIT', b'FIN-WAIT-2', b'TIME-WAIT'):
            with self.subTest(state=state),self.assertRaises(sockets.SocketInventoryError):
                self.check(state+b' 0 0 172.23.0.4:8000 172.23.0.1:49000\n')

    def test_unknown_listener_and_ipv6_listener_block(self):
        for line in (b'LISTEN 0 128 0.0.0.0:9999 0.0.0.0:*\n',
                     b'LISTEN 0 128 [::]:8000 [::]:*\n',
                     b'LISTEN 0 128 *:8000 *:*\n'):
            with self.subTest(line=line),self.assertRaises(sockets.SocketInventoryError):self.check(line)

    def test_nonempty_accept_queue_and_unexpected_listener_peer_block(self):
        for line in (b'LISTEN 1 128 0.0.0.0:8000 0.0.0.0:*\n',
                     b'LISTEN 0 128 0.0.0.0:8000 172.23.0.5:*\n'):
            with self.subTest(line=line),self.assertRaises(sockets.SocketInventoryError):
                sockets.inspect(line,port=8000,service_addresses=('172.23.0.4',),peer_addresses=('172.23.0.5',))

    def test_malformed_or_mapped_address_does_not_become_proof(self):
        for line in (b'ESTAB 0 0 127.0.0.1:8000 secret\n',
                     b'ESTAB 0 0 [::ffff:172.23.0.4]:8000 [::ffff:172.23.0.5]:9\n',
                     b'SOMETHING 0 0 127.0.0.1:8000 127.0.0.1:9\n'):
            with self.subTest(line=line),self.assertRaises(sockets.SocketInventoryError):self.check(line)

    def test_bounded_input_and_peer_count_fail_closed(self):
        for raw in (b'x'*262145, b'x'*513+b'\n', b'\n'*4097):
            with self.subTest(size=len(raw)),self.assertRaises(sockets.SocketInventoryError):
                sockets.inspect(raw,port=8000,service_addresses=('172.23.0.4',),peer_addresses=('172.23.0.5',))
        with self.assertRaises(sockets.SocketInventoryError):
            sockets.inspect(b'',port=8000,service_addresses=('172.23.0.5',)*3,
                            peer_addresses=('172.23.0.2','172.23.0.3','172.23.0.4'))

    def test_cross_network_or_unknown_local_address_fails_closed(self):
        for line in (b'ESTAB 0 0 172.23.0.4:8000 172.24.0.5:90\n',
                     b'ESTAB 0 0 172.99.0.4:8000 172.23.0.5:90\n'):
            with self.subTest(line=line),self.assertRaises(sockets.SocketInventoryError):self.check(line)


if __name__ == '__main__':unittest.main()
