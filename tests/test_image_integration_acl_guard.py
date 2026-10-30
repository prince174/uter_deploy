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


if __name__ == '__main__': unittest.main()
