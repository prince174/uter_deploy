import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import install_wizard as wizard


def args(**overrides):
    data = dict(non_interactive=True, release='release-test', version='1.2.3',
                fingerprint='a'*64, release_dir='/tmp/private/release', backend='compose',
                home='/tmp/private/home', name='uter-test', context=None,
                llm_url='https://llm.invalid/v1', llm_model='model', llm_key_file='/tmp/private/key',
                llm_ca_bundle=None, health_url=None, storage_class=None, port=18000,
                guardrail_cpus=2, allow_http_llm=False, skip_llm_preflight=False, offline=False,
                reuse_release=False, use_env_proxy=False, _interactive_key=None)
    data.update(overrides)
    return argparse.Namespace(**data)


class InstallWizardTests(unittest.TestCase):
    def test_collect_noninteractive_uses_pinned_defaults_and_never_prompts(self):
        data=args(release=None,version=None,name=None,backend=None)
        with mock.patch('builtins.input', side_effect=AssertionError('unexpected prompt')):
            wizard.collect(data)
        self.assertEqual(data.release,wizard.DEFAULT_TAG)
        self.assertEqual(data.version,wizard.DEFAULT_VERSION)
        self.assertEqual(data.backend,'compose')

    def test_validate_rejects_invalid_before_any_download(self):
        for changed in (dict(fingerprint='no'),dict(backend='kubernetes',context=None),
                        dict(name='UPPER'),dict(offline=True,backend='kubernetes',context='ctx'),
                        dict(llm_url='http://llm.invalid/v1'),dict(llm_key_file='')):
            with self.subTest(changed=changed), mock.patch.object(wizard.fetch_release,'fetch_with_deadline') as fetch:
                with self.assertRaises(wizard.WizardError): wizard.validate(args(**changed))
                fetch.assert_not_called()

    def test_release_fingerprint_and_signature_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'downloads').mkdir(); (root/'bundle').mkdir()
            (root/'downloads/publisher-public.pem').write_text('publisher')
            with mock.patch.object(wizard.uterctl,'verify',return_value={'version':'1.2.3','installation_archive_sha256':'a'*64}) as verify:
                with self.assertRaisesRegex(wizard.WizardError,'RELEASE_VERIFICATION_FAILED'):
                    wizard.verify_release(root,'a'*64,'1.2.3')
                verify.assert_not_called()
            import hashlib
            fingerprint=hashlib.sha256(b'publisher').hexdigest()
            with mock.patch.object(wizard.uterctl,'verify',side_effect=ValueError('secret-canary')):
                with self.assertRaisesRegex(wizard.WizardError,'RELEASE_VERIFICATION_FAILED'):
                    wizard.verify_release(root,fingerprint,'1.2.3')
            with mock.patch.object(wizard.uterctl,'verify',return_value={'version':'9.9.9','installation_archive_sha256':'a'*64}):
                with self.assertRaisesRegex(wizard.WizardError,'RELEASE_VERIFICATION_FAILED'):
                    wizard.verify_release(root,fingerprint,'1.2.3')

    def test_real_signed_release_and_tampered_inputs_fail_closed(self):
        from tests.test_fetch_release import FetchReleaseTests
        import hashlib
        fixture = FetchReleaseTests('test_real_signature_and_signed_inputs_are_checked')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        release = Path(fixture.fetch()['output'])
        bundle,key,manifest = wizard.verify_release(release,fixture.fingerprint,'0.1.4')
        wizard.authenticated_inputs(release,bundle,key,manifest,fixture.root/'verified-inputs')
        archive = release/'downloads/installation-inputs.tar.gz'
        payload = archive.read_bytes() + b'tampered'
        archive.write_bytes(payload)
        (release/'downloads/installation-inputs.tar.gz.sha256').write_text(
            hashlib.sha256(payload).hexdigest()+'  installation-inputs.tar.gz\n')
        with self.assertRaisesRegex(wizard.WizardError,'SIGNED_INPUTS_INVALID'):
            wizard.authenticated_inputs(release,bundle,key,manifest,fixture.root/'rejected-inputs')

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_home_parent_allows_0755_but_rejects_writable_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); safe=root/'safe'; safe.mkdir(mode=0o755); safe.chmod(0o755)
            self.assertEqual(wizard.trusted_home_parent(safe),safe)
            safe.chmod(0o777)
            with self.assertRaisesRegex(wizard.WizardError,'INSTALLATION_PARENT_UNTRUSTED'):
                wizard.trusted_home_parent(safe)
            safe.chmod(0o755); link=root/'link'; link.symlink_to(safe,target_is_directory=True)
            with self.assertRaisesRegex(wizard.WizardError,'INSTALLATION_PARENT_UNTRUSTED'):
                wizard.trusted_home_parent(link)

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_download_parent_alias_cannot_redirect_verified_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); original = root/'original'; original.mkdir(mode=0o700)
            other = root/'other'; other.mkdir(mode=0o700)
            alias = root/'alias'; alias.symlink_to(original,target_is_directory=True)
            key = root/'key'; key.write_text(''); key.chmod(0o600)
            release,home = wizard.validate(args(release_dir=str(alias/'release'),
                                                home=str(root/'home'),llm_key_file=str(key)))
            self.assertEqual(release,original/'release')
            alias.unlink(); alias.symlink_to(other,target_is_directory=True)
            self.assertEqual(release.parent,original)
            self.assertNotEqual(release.parent,alias.resolve())

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_existing_release_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); release=root/'release'; release.mkdir(mode=0o700)
            alias=root/'alias';alias.symlink_to(release,target_is_directory=True)
            key=root/'key';key.write_text('');key.chmod(0o600)
            with self.assertRaisesRegex(wizard.WizardError,'INPUT_OR_PATH_INVALID'):
                wizard.validate(args(release_dir=str(alias),home=str(root/'home'),
                                     llm_key_file=str(key),reuse_release=True))

    def test_authenticated_inputs_reject_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            def fake_extract(*arguments, **kw):
                target=arguments[2];target.mkdir();(target/'images.json').write_text('{"agent":"wrong"}')
            with mock.patch.object(wizard.extract_release_inputs,'extract',side_effect=fake_extract):
                with self.assertRaisesRegex(wizard.WizardError,'SIGNED_INPUTS_INVALID'):
                    wizard.authenticated_inputs(root,root/'bundle',root/'key',{'images':{'agent':'signed'}},root/'out')

    def test_preflight_failure_stops_before_prepare(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); release=root/'release'; release.mkdir();home=root/'home'
            report={'result':'fail','checks':[{'name':'llm','status':'fail','code':'UNAVAILABLE'}]}
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline'), \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',{'images':{}})), \
                 mock.patch.object(wizard,'authenticated_inputs'), \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='hidden-secret'), \
                 mock.patch.object(wizard.preflight,'preflight',return_value=report), \
                 mock.patch.object(wizard,'run_install') as run, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(wizard.WizardError,'HOST_PREFLIGHT_FAILED'): wizard.execute(args())
                run.assert_not_called()
                self.assertNotIn('hidden-secret',output.getvalue())

    def test_explicit_skip_runs_signed_stages_and_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); release=root/'release'; release.mkdir();home=root/'home'; manifest={'images':{}}
            data=args(skip_llm_preflight=True)
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline') as fetch, \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',manifest)) as verify, \
                 mock.patch.object(wizard,'authenticated_inputs') as inputs, \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='hidden-secret'), \
                 mock.patch.object(wizard.preflight,'preflight',side_effect=AssertionError('not skipped')), \
                 mock.patch.object(wizard.preflight,'runtime_checks',return_value=[]) as runtime, \
                 mock.patch.object(wizard,'run_install') as run, mock.patch.object(wizard,'smoke') as smoke, \
                 mock.patch.object(wizard,'mark_acceptance') as mark, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(wizard.execute(data),0)
                self.assertEqual([call.args[1] for call in run.call_args_list],['prepare','check','install'])
                self.assertEqual(verify.call_count,5)
                fetch.assert_called_once(); inputs.assert_called_once();smoke.assert_called_once();mark.assert_called_once_with(home)
                runtime.assert_called_once_with('compose',None)
                self.assertIn('Проверка LLM с хоста пропущена',output.getvalue())
                self.assertNotIn('hidden-secret',output.getvalue())

    def test_installer_arguments_pass_key_path_not_value(self):
        data=args(allow_http_llm=True,offline=True)
        with mock.patch.object(wizard.subprocess,'run',return_value=argparse.Namespace(returncode=0)) as run:
            wizard.run_install(Path('/verified/bundle'),'prepare',Path('/private/home'),data,
                               Path('/private/inputs'),Path('/private/keyfile'))
            command=run.call_args.args[0]
            self.assertEqual(command[1:4],['-I','-B','/verified/bundle/scripts/install.py'])
            self.assertEqual(command[command.index('--llm-key-file')+1],'/private/keyfile')
            self.assertNotIn('hidden-secret',' '.join(command))
            self.assertIs(run.call_args.kwargs['stdout'],wizard.subprocess.DEVNULL)

    def test_failed_check_never_installs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); release=root/'release';release.mkdir();home=root/'home'
            def run(_bundle,stage,*_):
                if stage == 'check':raise wizard.WizardError('CHECK_FAILED')
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline'), \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',{'images':{}})), \
                 mock.patch.object(wizard,'authenticated_inputs'), \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='hidden-secret'), \
                 mock.patch.object(wizard.preflight,'runtime_checks',return_value=[]), \
                 mock.patch.object(wizard,'run_install',side_effect=run) as stages, mock.patch.object(wizard,'smoke') as smoke:
                with self.assertRaisesRegex(wizard.WizardError,'CHECK_FAILED'):
                    wizard.execute(args(skip_llm_preflight=True))
                self.assertEqual([call.args[1] for call in stages.call_args_list],['prepare','check'])
                smoke.assert_not_called()

    def test_busy_port_stops_before_download(self):
        with mock.patch.object(wizard,'validate',return_value=(Path('/release'),Path('/home'))), \
             mock.patch.object(wizard,'port_is_free',return_value=False), \
             mock.patch.object(wizard.fetch_release,'fetch_with_deadline') as fetch:
            with self.assertRaisesRegex(wizard.WizardError,'LOCAL_PORT_UNAVAILABLE'): wizard.execute(args())
            fetch.assert_not_called()

    def test_kubernetes_forward_is_stopped_if_smoke_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);release=root/'release';release.mkdir();home=root/'home'
            forward=mock.Mock()
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline'), \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',{'images':{}})), \
                 mock.patch.object(wizard,'authenticated_inputs'), \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='hidden-secret'), \
                 mock.patch.object(wizard.preflight,'runtime_checks',return_value=[]), \
                 mock.patch.object(wizard,'run_install'),mock.patch.object(wizard,'start_forward',return_value=forward), \
                 mock.patch.object(wizard,'stop_forward') as stop, \
                 mock.patch.object(wizard,'smoke',side_effect=wizard.WizardError('ACCEPTANCE_FAILED')):
                with self.assertRaisesRegex(wizard.WizardError,'ACCEPTANCE_FAILED'):
                    wizard.execute(args(backend='kubernetes',context='explicit',skip_llm_preflight=True))
                stop.assert_called_once_with(forward)

    def test_mark_acceptance_only_after_ready_and_never_rewrites_pending(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp); state=home/'install-state.json'
            state.write_text('{"status":"ready","acceptance":"not-run"}')
            state.chmod(0o600)
            wizard.mark_acceptance(home)
            self.assertEqual(json.loads(state.read_text()),{'status':'ready','acceptance':'passed'})
            state.write_text('{"status":"pending"}')
            with self.assertRaisesRegex(wizard.WizardError,'ACCEPTANCE_STATE_WRITE_FAILED'):
                wizard.mark_acceptance(home)
            self.assertEqual(json.loads(state.read_text()),{'status':'pending'})

    def test_reuse_release_does_not_download(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); release=root/'release';release.mkdir();home=root/'home'
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline') as fetch, \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',{'images':{}})), \
                 mock.patch.object(wizard,'authenticated_inputs'), \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='hidden-secret'), \
                 mock.patch.object(wizard.preflight,'runtime_checks',return_value=[]), \
                 mock.patch.object(wizard,'run_install'), mock.patch.object(wizard,'smoke'), \
                 mock.patch.object(wizard,'mark_acceptance'):
                wizard.execute(args(reuse_release=True,offline=True,skip_llm_preflight=True))
                fetch.assert_not_called()

    def test_interactive_secret_is_hidden_and_empty_requires_explicit_choice(self):
        data=args(non_interactive=False,llm_key_file=None,skip_llm_preflight=True)
        with mock.patch.object(wizard.sys.stdin,'isatty',return_value=True), \
             mock.patch.object(wizard,'ask',side_effect=['18000','enter','','']), \
             mock.patch.object(wizard.getpass,'getpass',return_value='hidden-secret'), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            wizard.collect(data)
            self.assertEqual(data._interactive_key,'hidden-secret')
            self.assertNotIn('hidden-secret',output.getvalue())
        data=args(non_interactive=False,llm_key_file=None)
        with mock.patch.object(wizard.sys.stdin,'isatty',return_value=True), \
             mock.patch.object(wizard,'ask',side_effect=['18000','enter']), \
             mock.patch.object(wizard.getpass,'getpass',return_value=''):
            with self.assertRaisesRegex(wizard.WizardError,'EMPTY_KEY_REQUIRES_EXPLICIT_NONE'):
                wizard.collect(data)
        data=args(non_interactive=False,llm_key_file=None)
        with mock.patch.object(wizard.sys.stdin,'isatty',return_value=True), \
             mock.patch.object(wizard,'ask',side_effect=['18000','enter']), \
             mock.patch.object(wizard.getpass,'getpass',side_effect=wizard.getpass.GetPassWarning()):
            with self.assertRaisesRegex(wizard.WizardError,'HIDDEN_INPUT_UNAVAILABLE_USE_KEY_FILE'):
                wizard.collect(data)

    def test_skip_llm_does_not_skip_runtime_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);release=root/'release';release.mkdir();home=root/'home'
            with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                 mock.patch.object(wizard,'port_is_free',return_value=True), \
                 mock.patch.object(wizard.fetch_release,'fetch_with_deadline'), \
                 mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',{'images':{}})), \
                 mock.patch.object(wizard,'authenticated_inputs'), \
                 mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='secret-canary'), \
                 mock.patch.object(wizard.preflight,'runtime_checks',return_value=[{'status':'fail','code':'DOCKER_UNAVAILABLE'}]), \
                 mock.patch.object(wizard,'run_install') as run:
                with self.assertRaisesRegex(wizard.WizardError,'HOST_PREFLIGHT_FAILED'):
                    wizard.execute(args(skip_llm_preflight=True))
                run.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_release_tree_rejects_writable_files_hardlinks_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); nested=root/'nested';nested.mkdir(mode=0o700)
            file=nested/'file';file.write_text('x');file.chmod(0o644)
            wizard.protected_release_tree(root)
            file.chmod(0o664)
            with self.assertRaisesRegex(wizard.WizardError,'RELEASE_TREE_UNTRUSTED'):
                wizard.protected_release_tree(root)
            file.chmod(0o644);hardlink=nested/'hardlink';os.link(file,hardlink)
            with self.assertRaisesRegex(wizard.WizardError,'RELEASE_TREE_UNTRUSTED'):
                wizard.protected_release_tree(root)
            hardlink.unlink();link=nested/'symlink';link.symlink_to(file)
            with self.assertRaisesRegex(wizard.WizardError,'RELEASE_TREE_UNTRUSTED'):
                wizard.protected_release_tree(root)

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner and mode checks')
    def test_acceptance_does_not_follow_redirect_with_bearer(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        received = []
        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get('Authorization'))
                self.send_response(200);self.end_headers()
            def log_message(self, *args): pass
        target=HTTPServer(('127.0.0.1',0),Target)
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location',f'http://127.0.0.1:{target.server_port}/redirected')
                self.end_headers()
            def log_message(self, *args): pass
        origin=HTTPServer(('127.0.0.1',0),Redirect)
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (origin,target)]
        for thread in threads:thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);home=root/'home';home.mkdir(mode=0o700)
                creds=home/'credentials.json';creds.write_text('{"admin":"secret-canary"}');creds.chmod(0o600)
                bundle=root/'bundle';(bundle/'scripts').mkdir(parents=True)
                (bundle/'scripts/smoke_http.py').write_text(
                    'import urllib.request\n'
                    'def check(base, user, password):\n'
                    '    req=urllib.request.Request(base, headers={"Authorization":"Bearer "+password})\n'
                    '    urllib.request.urlopen(req, timeout=3)\n'
                    '    return {"chat":"pass"}\n')
                with self.assertRaisesRegex(wizard.WizardError,'ACCEPTANCE_FAILED'):
                    wizard.smoke(bundle,home,origin.server_port)
                self.assertEqual(received,[])
        finally:
            for server in (origin,target):server.shutdown();server.server_close()
            for thread in threads:thread.join(timeout=3)

if __name__ == '__main__': unittest.main()
