"""Classify kubectl output for a missing fixture Pod; disposable CI only."""
import json
import os
import subprocess
import sys


def classify(raw):
    if not raw.strip():return 'EMPTY'
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):return 'MALFORMED'
    if isinstance(value,dict) and value.get('apiVersion')=='v1' and value.get('kind')=='List' and value.get('items')==[]:
        return 'EMPTY_LIST'
    return 'OTHER'


def main():
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('UTER_CI_STRICT_RUNNER')!='true'):
        raise ValueError('GUARD')
    try:
        result=subprocess.run(['kubectl','--context','kind-uter-empty-get','--namespace','default',
                               'get','pod','uter-ci-missing-0f5f6b2c','--ignore-not-found=true','-o','json'],
                              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              timeout=30,check=True)
        if len(result.stdout)>16384:raise ValueError
        print('KUBE_EMPTY_GET_'+classify(result.stdout))
    except (OSError,subprocess.SubprocessError,ValueError):
        print('KUBE_EMPTY_GET_UNVERIFIED');sys.exit(1)


if __name__=='__main__':main()
