import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import published_pair_ci as p
from scripts import adopt_backup_ci as driver

class PublishedPairSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.old=self.root/'old';self.new=self.root/'new';self.old.mkdir();self.new.mkdir()
        self.key=self.root/'key';self.key.write_text('fixture')
        self.env={'UTER_CI_RELEASE_MODE':'published','OLD_SIGNED_BUNDLE_PATH':str(self.old),
                  'NEW_SIGNED_BUNDLE_PATH':str(self.new),'PUBLISHER_KEY_PATH':str(self.key)}
        self.old_m={'images':{x:'old-'+x for x in ('guardrail','agent','redis')},'image_config_ids':{x:'id-'+x for x in ('guardrail','agent','redis')}}
        self.new_m={'images':{x:'new-'+x for x in ('guardrail','agent','redis')},'image_config_ids':{x:'new-id-'+x for x in ('guardrail','agent','redis')}}
        for release, m in [('published-old',self.old_m),('published-new',self.new_m)]:
            folder=self.root/'input'/release;folder.mkdir(parents=True)
            (folder/'images.json').write_text(json.dumps(m['images']))
            (folder/'publication.json').write_text(json.dumps({'images':{n:{'image_id':v} for n,v in m['image_config_ids'].items()}}))

    def test_default_mode_is_synthetic(self):
        self.assertEqual(p.select_mode({},self.root),{'mode':'synthetic'})
        with self.assertRaisesRegex(ValueError,'explicit published'):
            p.select_mode({'OLD_SIGNED_BUNDLE_PATH':str(self.old)},self.root)
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            p.select_mode({'UTER_CI_RELEASE_MODE':'other'},self.root)

    def test_published_requires_signature_pair_and_uses_old_installer(self):
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)) as verify:
            result=p.select_mode(self.env,self.root)
        verify.assert_called_once_with(self.old.resolve(),self.new.resolve(),self.key.resolve(),p.FINGERPRINT,'0.1.2','0.1.3')
        self.assertEqual(result['installer'],self.old.resolve()/'scripts/install.py')
        self.assertEqual(result['old_manifest'],self.old_m)
        self.assertEqual(result['new_manifest'],self.new_m)

    def test_invalid_signed_transition_fails_before_install(self):
        with patch.object(p,'verify_pair',side_effect=ValueError('Unsupported upgrade path')):
            with self.assertRaisesRegex(ValueError,'Unsupported upgrade path'):
                p.select_mode(self.env,self.root)
        bad=dict(self.env);bad.pop('PUBLISHER_KEY_PATH')
        with self.assertRaisesRegex(ValueError,'requires both'):
            p.select_mode(bad,self.root)

    def test_mismatched_images_or_configuration_ids_refused(self):
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)):
            images=self.root/'input'/'published-old'/'images.json'
            images.write_text(json.dumps(dict(self.old_m['images'],agent='tampered')))
            with self.assertRaisesRegex(ValueError,'images do not match'):
                p.select_mode(self.env,self.root)
            images.write_text(json.dumps(self.old_m['images']))
            publication=self.root/'input'/'published-new'/'publication.json'
            publication.write_text(json.dumps({'images':{n:{'image_id':'tampered'} for n in self.new_m['images']}}))
            with self.assertRaisesRegex(ValueError,'identities do not match'):
                p.select_mode(self.env,self.root)

    def test_signed_update_pretty_json_and_trailing_warning(self):
        payload=json.dumps({'version':'0.1.3','backup':'/tmp/backup'},indent=2).encode()+b'\nStore key securely\n'
        self.assertEqual(p.parse_update_output(payload)['backup'],'/tmp/backup')
        with self.assertRaises(ValueError):
            p.parse_update_output(b'{"version":"0.1.3"}')
        with self.assertRaises(ValueError):
            p.parse_update_output(b'not-json')

    def test_signed_update_scans_progress_without_emitting_secrets(self):
        result={'version':'0.1.4','backup':'/tmp/backup'}
        payload=b'pod changed; secret should not be logged\n{not-json}\n'+json.dumps(result,indent=2).encode()+b'\nDone\n'
        self.assertEqual(p.parse_update_output(payload),result)
        double=payload+b'\n'+json.dumps(result).encode()
        with self.assertRaisesRegex(ValueError,'exactly one'):
            p.parse_update_output(double)
        with self.assertRaisesRegex(ValueError,'too large'):
            p.parse_update_output(b'x'*(8*1024*1024+1))

    def test_release_version_overrides_are_checked_by_signature_verifier(self):
        self.env['UTER_CI_NEW_VERSION']='0.1.4'
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)) as verify:
            result=p.select_mode(self.env,self.root)
        self.assertEqual(result['new_version'],'0.1.4')
        self.assertEqual(verify.call_args.args[-2:],('0.1.2','0.1.4'))
        self.env['UTER_CI_OLD_VERSION']='0.1.4'
        self.env['UTER_CI_NEW_VERSION']='0.1.5'
        with patch.object(p,'verify_pair',return_value=(self.old_m,self.new_m)) as verify:
            result=p.select_mode(self.env,self.root)
        self.assertEqual((result['old_version'],result['new_version']),('0.1.4','0.1.5'))
        self.assertEqual(verify.call_args.args[-2:],('0.1.4','0.1.5'))

    def test_published_update_uses_target_signed_tool_with_old_bundle_as_current(self):
        command=driver.published_update_command('python',self.old,self.new,self.root/'home',self.key,
                                                self.root/'backups',self.root/'backup-key')
        self.assertEqual(command[1],self.new/'scripts/update_installation.py')
        self.assertEqual(command[command.index('--bundle')+1],self.new)
        self.assertEqual(command[command.index('--current-bundle')+1],self.old)
        self.assertIn('--create-backup-key',command)

    def test_evidence_uses_selected_tags_and_legacy_defaults(self):
        self.assertEqual(driver.evidence_releases(True,{}),
                         ('deploy-2026.10.28-signed-3','deploy-2026.10.28-signed-4'))
        self.assertEqual(driver.evidence_releases(True,{'UTER_CI_OLD_TAG':'release-old','UTER_CI_NEW_TAG':'release-new'}),
                         ('release-old','release-new'))
        self.assertEqual(driver.evidence_releases(False,{}),(driver.OLD,driver.NEW))

    def test_same_digests_are_reported_without_claiming_migration(self):
        digest='sha256:'+'a'*64
        old={name:'registry.example/'+name+'@'+digest for name in ('guardrail','agent','redis')}
        new={name:'mirror.example/'+name+'@'+digest for name in old}
        self.assertEqual(driver.image_digest_evidence(old,new),
                         {'product_image_digests_unchanged':True,'arbitrary_data_migration':'not_verified'})
        new['agent']='registry.example/agent@sha256:'+'b'*64
        self.assertFalse(driver.image_digest_evidence(old,new)['product_image_digests_unchanged'])

    def test_strict_runner_rejects_self_hosted_wrong_workspace_and_nonroot(self):
        env={'GITHUB_ACTIONS':'true','UTER_CI_STRICT_RUNNER':'true',
             'RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_WORKSPACE':str(self.root)}
        driver.runner_guard(env,self.root,os_name='posix',euid=0)
        for key,value in [('RUNNER_ENVIRONMENT','self-hosted'),('RUNNER_OS','Windows'),
                          ('GITHUB_WORKSPACE',str(self.root/'other')),('GITHUB_ACTIONS','false')]:
            changed=dict(env);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                driver.runner_guard(changed,self.root,os_name='posix',euid=0)
        with self.assertRaises(ValueError):
            driver.runner_guard(env,self.root,os_name='posix',euid=1000)
        # Older explicitly-dispatched workflows did not pass strict-runner flags.
        driver.runner_guard({'GITHUB_ACTIONS':'true'},self.root,os_name='posix',euid=0)

    def test_strict_command_failure_redacts_even_prefixed_secrets(self):
        failed=subprocess.CompletedProcess(['fixture'],1,b'',b'uterctl: secret-canary')
        with patch.dict(os.environ,{'UTER_CI_STRICT_RUNNER':'true'}), \
                patch.object(driver.subprocess,'run',return_value=failed):
            with self.assertRaises(RuntimeError) as error:
                driver.call(['fixture'])
        self.assertNotIn('canary',str(error.exception))

    def test_compose_project_refuses_existing_resources_before_mutation(self):
        with patch.object(driver,'call',side_effect=[b'',b'',b'']) as command:
            driver.assert_compose_project_absent('uter-upgrade-ci')
        self.assertEqual(command.call_count,3)
        self.assertEqual([c.args[0][3] for c in command.call_args_list],['container','network','volume'])
        for responses in ([b'foreign'], [b'',b'foreign'], [b'',b'',b'foreign']):
            with patch.object(driver,'call',side_effect=responses) as command:
                with self.assertRaisesRegex(ValueError,'already exists'):
                    driver.assert_compose_project_absent('uter-upgrade-ci')
                self.assertEqual(command.call_count,len(responses))
        with patch.object(driver,'call') as command:
            with self.assertRaises(ValueError):
                driver.assert_compose_project_absent('-bad')
            command.assert_not_called()

    def test_restored_cleanup_targets_only_created_container_id(self):
        with patch.object(driver.subprocess,'run') as command:
            driver.remove_created_container(None)
            command.assert_not_called()
            with self.assertRaises(ValueError):
                driver.remove_created_container('uter-ci-restored-redis')
            command.assert_not_called()
            container_id='a'*64
            driver.remove_created_container(container_id)
            command.assert_called_once_with(['docker','rm','-f',container_id],capture_output=True)
