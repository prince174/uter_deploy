import unittest
from unittest import mock
from scripts import experimental_compose_fence_ci as probe

class ComposeFenceProbeTests(unittest.TestCase):
    env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}
    def test_guard_prevents_any_docker_operations_on_local_host(self):
        with mock.patch.dict(probe.os.environ,{},clear=True),mock.patch.object(probe,'docker') as docker:
            with self.assertRaises(RuntimeError):probe.main()
            docker.assert_not_called()
    def test_require_running_detached_and_restart_disabled(self):
        good={'running':True,'restart':'no','network':{},'ports':None}
        probe.assert_detached(good)
        for bad in ({**good,'running':False},{**good,'restart':'unless-stopped'},
                    {**good,'network':{'backend':{}}},{**good,'ports':{'6379/tcp':[{}]}}):
            with self.subTest(bad=bad),self.assertRaises(RuntimeError):probe.assert_detached(bad)
    def test_cleanup_requires_identity_and_label(self):
        identifier='a'*64;owner='b'*32
        for kind in ('container','network'):
            with mock.patch.object(probe,'docker',return_value=identifier+' '+('c'*32)) as docker:
                with self.assertRaisesRegex(RuntimeError,'ownership'):probe.cleanup(kind,identifier,owner)
                self.assertEqual(docker.call_count,1)
    def test_volume_cleanup_requires_random_owned_name_and_label(self):
        owner='b'*32;volume='uter-synthetic-compose-fence-'+owner
        with mock.patch.object(probe,'docker',return_value='other') as docker:
            with self.assertRaisesRegex(RuntimeError,'ownership'):probe.cleanup('volume',volume,owner)
            self.assertEqual(docker.call_count,1)
        with mock.patch.object(probe,'docker') as docker:
            with self.assertRaisesRegex(RuntimeError,'invalid volume'):probe.cleanup('volume','other',owner)
            docker.assert_not_called()
    def test_detached_probe_accepts_only_expected_network_errors(self):
        import errno
        for code, accepted in ((errno.ECONNREFUSED, True), (errno.ENETUNREACH, True),
                               (errno.EHOSTUNREACH, True), (errno.ETIMEDOUT, True),
                               (0, False), (errno.EACCES, False)):
            socket_instance = mock.Mock()
            socket_instance.connect_ex.return_value = code
            with self.subTest(code=code), mock.patch('socket.socket', return_value=socket_instance), \
                    mock.patch('sys.argv', ['probe', '192.0.2.1']), mock.patch('builtins.print'):
                if accepted:
                    exec(probe.BLOCKED, {})
                else:
                    with self.assertRaises(SystemExit): exec(probe.BLOCKED, {})

    def test_tcp_fixture_treats_timeout_as_inconclusive(self):
        self.assertIn('except TimeoutError: raise',probe.CLIENT)

if __name__=='__main__':unittest.main()
