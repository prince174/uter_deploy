import hashlib
import json
import unittest
from unittest import mock

from scripts import compose_writer_stop_probe_ci as probe


class WriterStopProbeTests(unittest.TestCase):
    def test_probe_refuses_non_ci_before_accessing_runtime(self):
        with mock.patch.dict(probe.os.environ,{},clear=True), \
             mock.patch.object(probe.compose_redis_diagnostic,'inspect_installation') as inspect:
            with self.assertRaisesRegex(probe.ProbeFailure,'^DISPOSABLE_RUNNER_REQUIRED$'):
                probe.probe('/nonexistent','bundle','key',{},'redis',mock.Mock(),mock.Mock())
            inspect.assert_not_called()

    def test_audit_probe_accepts_only_structured_verified_response(self):
        good={'size':4,'sha256':hashlib.sha256(b'data').hexdigest(),'prefix_matches':True}
        process=mock.Mock(returncode=0,stdout=json.dumps(good).encode())
        with mock.patch.object(probe.subprocess,'run',return_value=process) as run:
            self.assertEqual(probe.audit_snapshot(['docker'],{}),good)
            self.assertEqual(run.call_args.kwargs['stderr'],probe.subprocess.DEVNULL)
        for bad in (dict(good,prefix_matches=False),dict(good,extra='secret-canary'),dict(good,sha256='secret-canary')):
            process.stdout=json.dumps(bad).encode()
            with mock.patch.object(probe.subprocess,'run',return_value=process):
                with self.assertRaises(probe.ProbeFailure) as caught:probe.audit_snapshot(['docker'],{})
                self.assertNotIn('secret',str(caught.exception))

    def test_audit_probe_rejects_failing_helper_even_with_valid_output(self):
        process=mock.Mock(returncode=1,stdout=b'{"secret":"canary"}')
        with mock.patch.object(probe.subprocess,'run',return_value=process):
            with self.assertRaisesRegex(probe.ProbeFailure,'^AUDIT_UNVERIFIED$'):probe.audit_snapshot(['docker'],{})


if __name__=='__main__':unittest.main()
