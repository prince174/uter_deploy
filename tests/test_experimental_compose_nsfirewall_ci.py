import os
import subprocess
import unittest
from unittest import mock

from scripts import experimental_compose_nsfirewall_ci as probe


@unittest.skipUnless(os.name=='posix','network namespaces require Linux')
class SyntheticNamespaceFirewallTests(unittest.TestCase):
    def test_host_namespace_is_always_rejected(self):
        fd=os.open('/proc/self/ns/net',os.O_RDONLY)
        try:
            with self.assertRaisesRegex(RuntimeError,'host network namespace'):
                probe.ensure_nonhost_namespace(fd)
        finally:os.close(fd)

    def test_rule_requires_exact_random_synthetic_identifier(self):
        good='uter-ci-'+'a'*32
        self.assertEqual(probe.rule(good)[-2:],['-j','DROP'])
        for bad in ('', 'uter-ci-a', good+';iptables', '../host', 'uter-ci-'+'g'*32):
            with self.subTest(bad=bad),self.assertRaises(RuntimeError):probe.rule(bad)

    def test_firewall_command_uses_only_pinned_netns_fd(self):
        with mock.patch.object(probe,'ensure_nonhost_namespace') as guard, \
             mock.patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
            self.assertEqual(probe.command(42,'-S','INPUT'),'')
        guard.assert_called_once_with(42)
        command=run.call_args.args[0]
        self.assertEqual(command[:3],[probe.NSENTER,'--net=/proc/self/fd/42','--'])
        self.assertEqual(command[3:],[probe.IPTABLES,'-w','10','-S','INPUT'])
        self.assertEqual(run.call_args.kwargs['pass_fds'],(42,))
        self.assertEqual(run.call_args.kwargs['timeout'],30)
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)

    def test_failed_namespace_check_never_calls_iptables(self):
        with mock.patch.object(probe,'ensure_nonhost_namespace',side_effect=RuntimeError('host')), \
             mock.patch.object(probe.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):probe.command(42,'-S','INPUT')
        run.assert_not_called()

    def test_guard_prevents_local_docker_or_namespace_operations(self):
        with mock.patch.dict(os.environ,{},clear=True), \
             mock.patch.object(probe.helper,'docker') as docker, \
             mock.patch.object(probe.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):probe.main()
        docker.assert_not_called();run.assert_not_called()

    def test_timeout_is_not_treated_as_a_closed_old_socket(self):
        self.assertIn('except TimeoutError:raise',probe.CLIENT)
        self.assertIn("if r:raise SystemExit(3)",probe.CLIENT)


if __name__=='__main__':unittest.main()
