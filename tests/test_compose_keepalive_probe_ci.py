import os
from pathlib import Path
import subprocess
import unittest


SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'compose_keepalive_probe_ci.sh'


@unittest.skipUnless(os.name=='posix','bash CI guard')
class KeepaliveProbeGuardTests(unittest.TestCase):
    def test_refuses_before_touching_host_outside_hosted_runner(self):
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','GITHUB_ACTIONS':'false',
             'RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}
        result=subprocess.run(['bash',str(SCRIPT)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')

    def test_script_syntax(self):
        result=subprocess.run(['bash','-n',str(SCRIPT)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__':unittest.main()
