import unittest
from unittest.mock import patch

from scripts import image_integration


class ACLProductFixtureGuardTests(unittest.TestCase):
    def test_unhosted_acl_probe_does_not_touch_files_or_docker(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS':'true','UTER_CI_REDIS_ACL':'true',
                                      'RUNNER_ENVIRONMENT':'self-hosted','RUNNER_OS':'Linux'}, clear=True), \
             patch.object(image_integration.subprocess, 'check_output') as docker, \
             patch.object(image_integration.Path, 'mkdir') as mkdir:
            with self.assertRaises(SystemExit): image_integration.main()
            docker.assert_not_called()
            mkdir.assert_not_called()

    def test_project_occupation_fails_before_start(self):
        with patch.object(image_integration.subprocess, 'check_output', side_effect=[b'existing\n']):
            with self.assertRaises(ValueError): image_integration.ensure_unused_project('uter-acl-'+('a'*32))

    def test_unexpected_owned_resource_blocks_cleanup(self):
        with patch.object(image_integration.subprocess, 'check_output', side_effect=[b'unexpected\n']):
            with self.assertRaises(ValueError): image_integration.ensure_owned_project('uter-acl-'+('a'*32))

    def test_expected_names_are_accepted_for_cleanup(self):
        project='uter-acl-'+('a'*32)
        with patch.object(image_integration.subprocess, 'check_output', side_effect=[
                (project+'-guardrail-1\n').encode(), (project+'_redis-data\n').encode(),
                (project+'_backend\n').encode()]):
            image_integration.ensure_owned_project(project)

    def test_startup_diagnostics_do_not_return_raw_logs(self):
        state=b'[{"Service":"redis","State":"exited"}]'
        result=lambda value: type('Result',(),{'stdout':value})()
        with patch.object(image_integration.subprocess,'run',side_effect=[result(state),result(b'FATAL CONFIG FILE ERROR SECRET')]):
            self.assertEqual(image_integration.acl_startup_failure(['docker'],{}),'STARTUP_REDIS_CONFIG_INVALID')

    def test_redis_health_diagnostic_classifies_without_exposing_output(self):
        state=b'[{"Service":"redis","State":"running","Health":"unhealthy","ID":"aaaaaaaaaaaa"}]'
        result=lambda value: type('Result',(),{'stdout':value})()
        with patch.object(image_integration.subprocess,'run',side_effect=[result(state),result(b''),result(b'WRONGPASS secret')]):
            self.assertEqual(image_integration.acl_startup_failure(['docker'],{}),'STARTUP_REDIS_HEALTH_AUTH_REJECTED')


if __name__ == '__main__': unittest.main()
