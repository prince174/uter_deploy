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
from tests.test_install_wizard import args


SOURCE = {name: 'ghcr.io/prince174/uter-'+name+'@sha256:'+str(index)*64
          for index, name in enumerate(wizard.IMAGE_SERVICES, 1)}
REPOS = {name: 'nexus.example:5443/docker-proxy/uter/'+name for name in wizard.IMAGE_SERVICES}


def options(**overrides):
    values = {'image_'+name+'_repository': repo for name, repo in REPOS.items()}
    values.update(overrides)
    return args(**values)


class ImageRegistryWizardTests(unittest.TestCase):
    def test_mapping_changes_repository_only_and_does_not_mutate_signed_manifest(self):
        manifest = {'images': dict(SOURCE)}
        mapped = wizard.mapped_images(manifest, wizard.image_repositories(options()))
        for name in wizard.IMAGE_SERVICES:
            self.assertEqual(mapped[name], REPOS[name]+'@'+SOURCE[name].split('@')[1])
        self.assertEqual(manifest['images'], SOURCE)

    def test_default_keeps_signed_refs_and_partial_mapping_fails(self):
        self.assertIsNone(wizard.image_repositories(args()))
        with self.assertRaisesRegex(wizard.WizardError, 'IMAGE_REPOSITORIES_REQUIRED'):
            wizard.image_repositories(options(image_redis_repository=None))

    def test_multiple_images_may_share_one_repository_with_distinct_signed_digests(self):
        common='nexus.example:5443/docker/uter'
        data=options(**{'image_'+name+'_repository':common for name in wizard.IMAGE_SERVICES})
        mapped=wizard.mapped_images({'images':SOURCE},wizard.image_repositories(data))
        self.assertEqual(len(set(mapped.values())),3)
        for name in wizard.IMAGE_SERVICES:
            self.assertEqual(mapped[name],common+'@'+SOURCE[name].split('@')[1])

    def test_rejects_credentials_urls_tags_digest_and_malformed_repositories(self):
        values = ('https://nexus.example/repo/guardrail', 'user:password@nexus.example/a',
                  'nexus.example/a:latest', 'nexus.example/a@sha256:'+'a'*64,
                  'nexus.example:0/a', 'nexus.example:65536/a', 'nexus.example/../a',
                  'nexus.example//a', 'nexus.example/A', '-nexus.example/a', 'nexus.example/a\n', 'nexus/a')
        for value in values:
            with self.subTest(value=value), self.assertRaisesRegex(wizard.WizardError, 'IMAGE_REPOSITORY_INVALID'):
                wizard.image_repositories(options(image_guardrail_repository=value))

    def test_rejects_missing_extra_and_invalid_signed_digest(self):
        for images in ({}, {**SOURCE, 'extra': SOURCE['agent']},
                       {**SOURCE, 'agent': 'ghcr.io/a@sha256:'+'X'*64},
                       {**SOURCE, 'agent': 'ghcr.io/a@sha256:'+'a'*64+'@sha256:'+'b'*64}):
            with self.subTest(images=images), self.assertRaisesRegex(wizard.WizardError, 'SIGNED_IMAGES_INVALID'):
                wizard.mapped_images({'images': images}, REPOS)

    def test_localhost_and_short_registry_with_explicit_port_are_unambiguous(self):
        data=options(image_guardrail_repository='nexus:5000/repo/guardrail',
                     image_agent_repository='localhost/repo/agent')
        self.assertEqual(wizard.image_repositories(data)['guardrail'], 'nexus:5000/repo/guardrail')
        self.assertEqual(wizard.image_repositories(data)['agent'], 'localhost/repo/agent')

    def test_interactive_choice_requires_all_three_repository_paths(self):
        data = args(non_interactive=False, skip_llm_preflight=True)
        prompts = ['18000', '', '', '', 'да', *(REPOS[name] for name in wizard.IMAGE_SERVICES), '']
        with mock.patch.object(wizard.sys.stdin, 'isatty', return_value=True), mock.patch.object(wizard, 'ask', side_effect=prompts):
            wizard.collect(data)
        self.assertEqual(wizard.image_repositories(data), REPOS)
        data = args(non_interactive=False, skip_llm_preflight=True)
        prompts = ['18000', '', '', '', 'да', REPOS['guardrail'], '', REPOS['redis'], '']
        with mock.patch.object(wizard.sys.stdin, 'isatty', return_value=True), mock.patch.object(wizard, 'ask', side_effect=prompts):
            with self.assertRaisesRegex(wizard.WizardError, 'IMAGE_REPOSITORIES_REQUIRED'):
                wizard.collect(data)

    @unittest.skipUnless(os.name == 'posix', 'Private file ownership and modes')
    def test_registry_config_requires_trusted_inline_credentials_and_expected_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'config.json'
            path.write_text(json.dumps({'auths': {'nexus.example:5443': {'auth': 'hidden-canary'}}}))
            path.chmod(0o600)
            self.assertIn(b'hidden-canary', wizard.read_registry_config(path, {'nexus.example:5443'}))
            self.assertIn(b'hidden-canary', wizard.read_registry_config(path, {'nexus.example:5443', 'public.example'}))
            with self.assertRaisesRegex(wizard.WizardError, 'REGISTRY_CONFIG_INVALID') as error:
                wizard.read_registry_config(path, {'other.example'})
            self.assertNotIn('hidden-canary', str(error.exception))
            path.write_text(json.dumps({'auths': {'nexus.example:5443': {'auth':'x'}, 'extra.example': {'auth':'y'}}}))
            with self.assertRaisesRegex(wizard.WizardError, 'REGISTRY_CONFIG_INVALID'):
                wizard.read_registry_config(path, {'nexus.example:5443'})
            for data in ({'credsStore':'secret','auths':{'nexus.example:5443':{'auth':'x'}}},
                         {'credHelpers':{'nexus.example:5443':'helper'},'auths':{}},
                         {'auths': {'nexus.example:5443': {}}}):
                path.write_text(json.dumps(data))
                with self.assertRaisesRegex(wizard.WizardError, 'REGISTRY_CONFIG_INVALID'):
                    wizard.read_registry_config(path)
            path.write_text('{"auths":{"a":{"auth":"x"}},"auths":{"b":{"auth":"y"}}}')
            with self.assertRaisesRegex(wizard.WizardError, 'REGISTRY_CONFIG_INVALID'):
                wizard.read_registry_config(path)
            path.chmod(0o644)
            with self.assertRaisesRegex(wizard.WizardError, 'REGISTRY_CONFIG_INVALID'):
                wizard.read_registry_config(path)

    def test_signed_installer_receives_derived_file_and_registry_in_backend_specific_form(self):
        for backend in ('compose', 'kubernetes'):
            data = options(backend=backend, context='ctx' if backend == 'kubernetes' else None)
            with self.subTest(backend=backend), mock.patch.object(wizard.subprocess,'run', return_value=argparse.Namespace(returncode=0)) as run:
                wizard.run_install(Path('/signed/bundle'), 'prepare', Path('/private/home'), data,
                                   Path('/private/inputs'), Path('/private/llm-key'),
                                   Path('/private/mapped.json'), Path('/private/registry/config.json'))
                command = run.call_args.args[0]
                self.assertEqual(command[command.index('--images')+1], '/private/mapped.json')
                if backend == 'kubernetes':
                    self.assertEqual(command[command.index('--registry-config')+1], '/private/registry/config.json')
                    self.assertIsNone(run.call_args.kwargs['env'])
                else:
                    self.assertNotIn('--registry-config', command)
                    self.assertEqual(run.call_args.kwargs['env']['DOCKER_CONFIG'], '/private/registry')

    @unittest.skipUnless(os.name == 'posix', 'private directory checks')
    def test_signed_inputs_preserved_and_provenance_recorded_for_both_backends(self):
        for backend in ('compose', 'kubernetes'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); release = root/'release'; release.mkdir(mode=0o700)
                home = root/'home'; manifest = {'version':'0.1.6', 'images':dict(SOURCE)}
                seen = []
                data = options(backend=backend, context='ctx' if backend == 'kubernetes' else None,
                               skip_llm_preflight=True)
                def inputs(_release, _bundle, _key, _manifest, destination):
                    destination.mkdir(mode=0o700)
                    (destination/'images.json').write_text(json.dumps(SOURCE))
                def install(_bundle, phase, target, _args, source, _key_file, mapped, _registry):
                    self.assertEqual(json.loads((source/'images.json').read_text()), SOURCE)
                    self.assertEqual(json.loads(mapped.read_text()), wizard.mapped_images(manifest,REPOS))
                    if phase == 'prepare': target.mkdir(mode=0o700)
                    seen.append(phase)
                with mock.patch.object(wizard,'validate',return_value=(release,home)), \
                     mock.patch.object(wizard,'port_is_free',return_value=True), \
                     mock.patch.object(wizard.fetch_release,'fetch_with_deadline'), \
                     mock.patch.object(wizard,'verify_release',return_value=(release/'bundle',release/'key',manifest)), \
                     mock.patch.object(wizard,'authenticated_inputs',side_effect=inputs), \
                     mock.patch.object(wizard.workload_preflight,'read_trusted_key',return_value='private-canary'), \
                     mock.patch.object(wizard.preflight,'runtime_checks',return_value=[]), \
                     mock.patch.object(wizard,'run_install',side_effect=install), \
                     mock.patch.object(wizard,'accept_with_operation_lock'), \
                     mock.patch.object(wizard,'start_forward',return_value=None), \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(wizard.execute(data),0)
                provenance=json.loads((home/'image-provenance.json').read_text())
                self.assertEqual(provenance['source_images'], SOURCE)
                self.assertEqual(provenance['installed_images'], wizard.mapped_images(manifest,REPOS))
                self.assertEqual((home/'image-provenance.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(seen,['prepare','check','install'])
                self.assertNotIn('private-canary',output.getvalue())

    def test_existing_adoption_rejects_changed_signed_repository_before_workload_mutation(self):
        from scripts import adopt_managed
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);home=root/'home';home.mkdir();bundle=root/'bundle';bundle.mkdir()
            cfg={'images': wizard.mapped_images({'images':SOURCE},REPOS)}
            with mock.patch.object(adopt_managed.uterctl,'verify',return_value={'images':SOURCE}), \
                 mock.patch.object(adopt_managed.uterctl,'read',return_value=cfg), \
                 mock.patch.object(adopt_managed.adopt_installation,'adopt') as change:
                with self.assertRaisesRegex(ValueError,'does not match installed images'):
                    adopt_managed.adopt(home,bundle,root/'key')
                change.assert_not_called()

