"""Safety checks for CI-only synthetic writer fixtures, never product claims."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import compose_synthetic_writer_images_ci as images


@unittest.skipUnless(os.name=='posix','CI fixture guard requires POSIX')
class SyntheticImageSafetyTests(unittest.TestCase):
    def test_builder_guard_rejects_nonhosted_or_wrong_backend_before_docker(self):
        good={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
              'UTER_CI_STRICT_RUNNER':'true','BACKEND':'compose','DOCKER_CONTEXT':'default'}
        with tempfile.TemporaryDirectory() as temp:
            for field,value in (('GITHUB_ACTIONS','false'),('RUNNER_ENVIRONMENT','self-hosted'),
                                ('RUNNER_OS','Windows'),('UTER_CI_STRICT_RUNNER','false'),
                                ('BACKEND','kubernetes'),('DOCKER_CONTEXT','remote'),('DOCKER_HOST','tcp://other')):
                env=dict(good,**{field:value})
                with self.subTest(field=field),patch.dict(os.environ,env,clear=True),patch.object(images.os,'geteuid',return_value=0):
                    with self.assertRaisesRegex(images.SyntheticImageError,'^SYNTHETIC_IMAGE_CI_ONLY$'):
                        images.guard(Path(temp))

    def test_registry_lookup_rejects_unknown_names_and_never_contacts_network(self):
        cases=(('uter-ci-guardrail','public'),('uter-guardrail','old'),('other/agent','target'),
               ('uter-ci-agent','latest'))
        with patch.object(images.urllib.request,'urlopen') as network:
            for repository,tag in cases:
                with self.subTest(repository=repository,tag=tag),self.assertRaisesRegex(images.SyntheticImageError,'^SYNTHETIC_IMAGE_INVALID$'):
                    images.registry_digest(repository,tag)
        network.assert_not_called()

    def test_synthetic_wrapper_and_builder_are_absent_from_product_bundle(self):
        from tests import test_bundle_provenance
        fixture=test_bundle_provenance.BundleProvenanceTests(methodName='test_changed_or_deleted_placeholder_rejected_by_signed_inventory')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        bundle=fixture.make_bundle()
        for name in ('ci_synthetic_writer_wrapper.py','compose_synthetic_writer_images_ci.py'):
            self.assertFalse((bundle/'scripts'/name).exists())

    def test_ci_capture_diagnostics_are_fixed_and_do_not_echo_output(self):
        from scripts import compose_fenced_update_e2e_ci as ci
        accepted='FENCED_UPDATE_CAPTURE_FENCE_START_WRITER_STOP_GUARDRAIL_EXIT_TERM_LIKE_OOM_FALSE'
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp)
            raw=('uterctl: FencedUpdateError: '+accepted+'\n').encode()
            self.assertEqual(ci.apply_error(raw,home),'APPLY_'+accepted+'_PHASE_NONE')
            for bad in (b'uterctl: FencedUpdateError: SECRET_CANARY\n',
                        raw.rstrip(b'\n')+b' SECRET_CANARY\n',b'SECRET_CANARY'):
                result=ci.apply_error(bad,home)
                self.assertEqual(result,'APPLY_UNKNOWN_PHASE_NONE');self.assertNotIn('SECRET_CANARY',result)

    @unittest.skipUnless(os.name=='posix','POSIX signals required')
    def test_wrapper_artificially_maps_termination_to_zero_but_preserves_other_errors(self):
        wrapper=Path(__file__).resolve().parents[1]/'scripts/ci_synthetic_writer_wrapper.py'
        with tempfile.TemporaryDirectory() as temp:
            child=Path(temp)/'child.py'
            child.write_text('import signal,sys,time\nsignal.signal(signal.SIGTERM,lambda *_:sys.exit(12))\nprint("ready",flush=True)\ntime.sleep(10)\n')
            process=subprocess.Popen([sys.executable,str(wrapper),sys.executable,str(child)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(),'ready')
                time.sleep(0.1)
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=10),0)
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=10)
                process.stdout.close()
            failed=subprocess.run([sys.executable,str(wrapper),sys.executable,'-c','raise SystemExit(7)'],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            self.assertEqual(failed.returncode,7)


if __name__=='__main__':unittest.main()
