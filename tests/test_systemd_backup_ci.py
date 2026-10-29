import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import systemd_backup_ci as ci


class SystemdBackupCITests(unittest.TestCase):
    def test_refuses_local_environment_before_systemd_or_docker(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'false'},clear=True), \
                patch.object(ci,'call') as call:
            with self.assertRaises(Exception):
                ci.run()
            call.assert_not_called()

    def test_rejects_unexpected_unit_names(self):
        for name in ('other.service','uter-backup-uter-offline-ci-abc.service',
                     '../uter-backup-uter-offline-ci-0123456789ab.service'):
            with self.assertRaises(ci.StageError):
                ci.TestUnit(name,'/tmp/source')

    def test_owned_unit_only_is_removed_and_changed_unit_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'source';source.write_text('[Service]\nType=oneshot\n')
            systemd=root/'units';systemd.mkdir()
            real_open=os.open;real_fstat=os.fstat
            def open_for_test(path,flags,mode=0o777,**kwargs):
                if path == '/run/systemd/system':
                    path=systemd
                return real_open(path,flags,mode,**kwargs)
            def root_fstat(fd):
                info=list(real_fstat(fd));info[4]=0
                return os.stat_result(info)
            query=subprocess.CompletedProcess([],4,b'not-found\n',b'')
            name='uter-backup-uter-offline-ci-0123456789ab.service'
            with patch.object(ci.os,'open',side_effect=open_for_test), \
                 patch.object(ci.os,'fstat',side_effect=root_fstat), \
                 patch.object(ci.subprocess,'run',return_value=query), \
                 patch.object(ci,'call',return_value=b''), \
                 patch.object(ci,'cleanup',return_value=True) as cleanup:
                unit=ci.TestUnit(name,source);unit.install()
                self.assertTrue(unit.owned())
                unit.close()
                self.assertFalse((systemd/name).exists())
                self.assertEqual(cleanup.call_count,1) # reload, never start or enable
                unit=ci.TestUnit(name,source);unit.install()
                (systemd/name).write_text('replaced')
                with self.assertRaisesRegex(ci.StageError,'UNIT_CLEANUP_FAILED'):
                    unit.close()
                self.assertEqual((systemd/name).read_text(),'replaced')

    def test_workflow_verifies_publisher_before_extraction_and_never_enables_timer(self):
        workflow=(Path(__file__).resolve().parents[1]/'.github/workflows/systemd-backup-e2e.yml').read_text()
        self.assertLess(workflow.index('sha256sum -c'),workflow.index('extract_signed_bundle.py'))
        self.assertIn('m["version"]=="0.1.5"',workflow)
        self.assertIn('--proto-redir',workflow)
        self.assertNotIn('systemctl enable',workflow)
        self.assertIn('runs-on: ubuntu-24.04',workflow)


if __name__=='__main__':
    unittest.main()
