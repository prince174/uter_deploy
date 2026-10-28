import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

runtime=load('runtime_rootfs','packaging/runtime_rootfs.py')
gate=load('security_gate','scripts/security_gate.py')

class RuntimeInventoryTests(unittest.TestCase):
    def test_missing_package_record_fails_closed(self):
        with self.assertRaises(ValueError):
            runtime.package_records('Package: libc6\nStatus: install ok installed\nVersion: 1\n',{'libc6','libssl3'})

    def test_missing_version_or_uninstalled_record_rejected(self):
        for record in ('Package: libc6\nStatus: install ok installed', 'Package: libc6\nVersion: 1\nStatus: deinstall ok config-files'):
            with self.assertRaises(ValueError):runtime.package_records(record,{'libc6'})

    def test_only_retained_package_metadata_survives(self):
        text='Package: libc6\nStatus: install ok installed\nVersion: 2\nSource: glibc\n\nPackage: mount\nStatus: install ok installed\nVersion: 3\n'
        output=runtime.package_records(text,{'libc6'})
        self.assertIn('Source: glibc',output)
        self.assertNotIn('Package: mount',output)

    def test_unowned_library_rejected(self):
        with patch.object(runtime.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','')):
            with self.assertRaises(ValueError):runtime.owners_for({Path('/unowned/libexample.so')})

    def test_os_lookup_failure_not_treated_as_absence(self):
        with patch.object(runtime.subprocess,'run',return_value=subprocess.CompletedProcess([],2,'','failed')):
            with self.assertRaises(ValueError):runtime.owners_for({Path('/unowned/libexample.so')})

class SecurityGateTests(unittest.TestCase):
    def test_missing_os_detection_cannot_pass(self):
        for data in ({},{'Metadata':{},'Results':[{'Vulnerabilities':[]}]}):
            with self.assertRaises(ValueError):gate.summary(data)

    def test_unfixed_high_and_secret_counted(self):
        data={'Metadata':{'OS':{'Family':'debian'}},'Results':[{'Class':'os-pkgs','Vulnerabilities':[{'Severity':'HIGH','FixedVersion':''},{'Severity':'CRITICAL'}],'Secrets':[{}]}]}
        report=gate.summary(data)
        self.assertEqual(report['critical_high'],2)
        self.assertEqual(report['secrets'],1)

    def test_low_medium_remain_visible(self):
        data={'Metadata':{'OS':{'Family':'alpine'}},'Results':[{'Class':'os-pkgs','Vulnerabilities':[{'Severity':'LOW'},{'Severity':'MEDIUM'}]}]}
        self.assertEqual(gate.summary(data),{'vulnerabilities':{'LOW':1,'MEDIUM':1},'secrets':0,'critical_high':0})
