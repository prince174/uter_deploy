from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import unittest

if sys.platform.startswith('linux'):
    from scripts import kubernetes_pinned_preflight_ci as ci
else:
    ci=None


@unittest.skipUnless(sys.platform.startswith('linux'),'Linux sealed kubeconfig required')
class PinnedPreflightCITests(unittest.TestCase):
    def test_bad_fixture_rejected_without_printing_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);work=root/'work';work.mkdir()
            home=work/'home';home.mkdir();bundle=work/'bundle';bundle.mkdir();key=work/'key';key.touch()
            raw='{"kind":"Config","clusters":[],"synthetic-secret":"not-for-logs"}'
            env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                 'UTER_CI_STRICT_RUNNER':'true','UTER_CI_VERIFY_KUBE_LOOPBACK':'true','BACKEND':'kubernetes'}
            output=io.StringIO()
            with patch.object(ci,'ROOT',root),patch.object(ci.adopt_backup_ci,'runner_guard'), \
                 patch.object(ci.install_recovery,'run_readonly',return_value=raw), \
                 patch.dict(os.environ,env,clear=True),redirect_stdout(output):
                with self.assertRaisesRegex(ci.PinnedCITestError,'^KUBE_PINNED_CI_UNVERIFIED$') as error:
                    ci.verify(home,bundle,key,{})
            self.assertNotIn('not-for-logs',str(error.exception));self.assertEqual(output.getvalue(),'')
