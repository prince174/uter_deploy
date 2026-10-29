import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import render_backup_systemd as render


class RenderTests(unittest.TestCase):
    def test_paths_and_time_reject_systemd_metacharacters_and_traversal(self):
        for path in ('relative', '/', '/safe/../other', '/safe//x', '/safe/x y',
                     '/safe/%n', '/safe/$HOME', '/safe/\nExecStart=evil', '/safe/тест'):
            with self.subTest(path=path), self.assertRaises(render.RenderError):
                render.simple_path(path)
        self.assertEqual(render.simple_path('/srv/uter-v1/.venv/bin/python'), Path('/srv/uter-v1/.venv/bin/python'))
        for clock in ('24:00', '12:60', '2:00', '12:00 UTC\nExecStart=bad', '*:*'):
            with self.subTest(clock=clock), self.assertRaises(render.RenderError):
                render.render_timer('uter-one', clock)
        timer = render.render_timer('uter-one', '02:15')
        self.assertIn('OnCalendar=*-*-* 02:15:00 UTC', timer)
        self.assertIn('Persistent=false', timer)

    def test_generator_publishes_once_without_invoking_services(self):
        with tempfile.TemporaryDirectory(prefix='uter-test-') as root:
            p=Path(root); (p/'keys').mkdir();key=p/'keys/key';key.write_bytes(b'x'*32)
            home=p/'home';out=p/'generated'; identity=p/'identity/id'
            site={'backend':'compose','name':'uter-one','context':'default'}
            pinned={'schema':1,'runtime':{'docker_daemon_id':'test'}}
            args=dict(home=home,backup_root=p/'backups',backup_key=key,identity_file=identity,
                      publisher_key=p/'public',publisher_sha256='a'*64,bundle=p/'bundle',
                      python=p/'python',name='uter-one',schedule='02:15',output=out)
            with patch.object(render.os,'geteuid',return_value=0), \
                 patch.object(render.backup,'private_directory',side_effect=lambda x:Path(x)), \
                 patch.object(render,'checked_file',side_effect=lambda x,**kw:Path(x)), \
                 patch.object(render,'secure_bundle',return_value=({'version':'0.1.5'},p/'bundle/scripts/backup_installation.py')), \
                 patch.object(render.backup,'installation_metadata',return_value=({},site,{})), \
                 patch.object(render.backup,'expected_identity'), \
                 patch.object(render.backup,'verify_current_bundle'), \
                 patch.object(render.backup,'safe_json',return_value=pinned), \
                 patch.object(render.backup,'identity_record',return_value=pinned), \
                 patch('subprocess.run') as run:
                result=render.generate(**args)
                self.assertEqual(result['enabled'],False)
                self.assertFalse(result['runtime_checked'])
                self.assertEqual(sorted(x.name for x in out.iterdir()),
                                 ['uter-backup-uter-one.service','uter-backup-uter-one.timer'])
                service=(out/'uter-backup-uter-one.service').read_text()
                self.assertIn('--backup-key '+str(key),service)
                self.assertNotIn('x'*32,service)
                self.assertIn('TimeoutStartSec=infinity',service)
                self.assertFalse((out/'INCOMPLETE').exists())
                with self.assertRaisesRegex(render.RenderError,'OUTPUT_EXISTS'):
                    render.generate(**args)
                run.assert_not_called()

    def test_atomic_publish_preserves_existing_output(self):
        if not sys_linux(): self.skipTest('Linux only')
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);stage=p/'stage';stage.mkdir();(stage/'file').write_text('new')
            target=p/'target';target.mkdir();(target/'file').write_text('original')
            with self.assertRaisesRegex(render.RenderError,'OUTPUT_EXISTS'):
                render.publish_no_replace(stage,target)
            self.assertEqual((target/'file').read_text(),'original')
            self.assertEqual((stage/'file').read_text(),'new')

    def test_wrong_publisher_fingerprint_stops_before_bundle_verification(self):
        with patch.object(render.backup,'checked_existing_path',side_effect=lambda p:Path(p)), \
             patch.object(render,'checked_file',side_effect=lambda p,**kw:Path(p)), \
             patch.object(render.backup,'safe_file',return_value=b'public key'), \
             patch.object(render.uterctl,'verify') as verify:
            with self.assertRaisesRegex(render.RenderError,'PUBLISHER_FINGERPRINT_MISMATCH'):
                render.secure_bundle('/tmp/trusted-bundle','/tmp/publisher.pem','0'*64)
            verify.assert_not_called()

    def test_identity_mismatch_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory(prefix='uter-test-') as root:
            p=Path(root); (p/'keys').mkdir();key=p/'keys/key';key.write_bytes(b'x'*32); out=p/'output'
            args=dict(home=p/'home',backup_root=p/'backups',backup_key=key,identity_file=p/'identity/id',
                      publisher_key=p/'public',publisher_sha256='a'*64,bundle=p/'bundle',
                      python=p/'python',name='uter-one',schedule='02:15',output=out)
            with patch.object(render.os,'geteuid',return_value=0), \
                 patch.object(render.backup,'private_directory',side_effect=lambda x:Path(x)), \
                 patch.object(render,'checked_file',side_effect=lambda x,**kw:Path(x)), \
                 patch.object(render,'secure_bundle',return_value=({'version':'0.1.5'},p/'tool')), \
                 patch.object(render.backup,'installation_metadata',return_value=({},{},{})), \
                 patch.object(render.backup,'expected_identity'), \
                 patch.object(render.backup,'verify_current_bundle'), \
                 patch.object(render.backup,'safe_json',return_value={'runtime':{}}), \
                 patch.object(render.backup,'identity_record',return_value={}):
                with self.assertRaisesRegex(render.RenderError,'IDENTITY_MISMATCH'):
                    render.generate(**args)
            self.assertFalse(out.exists())

    def test_systemd_verify_generated_units_when_available(self):
        tool=shutil.which('systemd-analyze')
        if not tool or not sys_linux(): self.skipTest('systemd-analyze unavailable')
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)
            (p/'uter-backup-uter-one.service').write_text(render.render_service(
                'uter-one','/usr/bin/true','/usr/bin/true','/home/test','/backups','/keys/key',
                '/identity/id','/identity/public'))
            (p/'uter-backup-uter-one.timer').write_text(render.render_timer('uter-one','02:15'))
            result=subprocess.run([tool,'verify',str(p/'uter-backup-uter-one.service'),
                                   str(p/'uter-backup-uter-one.timer')],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))


def sys_linux():
    import sys
    return sys.platform == 'linux'


if __name__ == '__main__':
    unittest.main()
