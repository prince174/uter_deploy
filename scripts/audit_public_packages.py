"""Read-only audit of every GHCR package version; never export secrets or source files."""
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import scan_image_archive as scanner

SERVICE=os.environ['SERVICE'];OWNER=os.environ['GITHUB_REPOSITORY_OWNER'].lower()
if SERVICE not in ('guardrail','agent','redis') or not re.fullmatch(r'[a-z0-9-]+',OWNER):raise SystemExit('Invalid package')


def invoke(args, **kwargs):
    p=subprocess.run([str(x) for x in args],capture_output=True,**kwargs)
    if p.returncode:raise RuntimeError(f'{args[0]} operation failed; output withheld')
    return p.stdout


def source_fingerprints(root):
    paths=invoke(['git','-C',root,'rev-list','--objects','--all']).decode().splitlines()
    hashes={}
    objects={line.split(' ',1)[0] for line in paths if ' ' in line and
             line.split(' ',1)[1].startswith(('guardrail/','agent/')) and line.endswith('.py')}
    p=subprocess.Popen(['git','-C',root,'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    try:
        for sha in objects:
            p.stdin.write((sha+'\n').encode());p.stdin.flush()
            header=p.stdout.readline().split()
            if len(header)!=3:raise ValueError('Source object metadata incomplete')
            size=int(header[2]);data=p.stdout.read(size)
            if len(data)!=size or p.stdout.read(1)!=b'\n':raise ValueError('Source object truncated')
            if header[1]==b'blob':hashes.setdefault(size,set()).add(__import__('hashlib').sha256(data).hexdigest())
    finally:
        p.stdin.close();p.stdout.close();p.wait()
    if not hashes:raise ValueError('No source fingerprints')
    return hashes


def main():
    endpoint=f'/users/{OWNER}/packages/container/uter-{SERVICE}/versions?per_page=100'
    pages=json.loads(invoke(['gh','api','--paginate','--slurp',endpoint]))
    versions=[v for page in pages for v in page]
    if not versions:raise ValueError('No package versions')
    fingerprints=source_fingerprints('work/upstream')
    scanner.fingerprints=lambda _:fingerprints
    results=[]
    for version in versions:
        digest=version['name']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',digest):raise ValueError('Invalid package digest')
        base=f'ghcr.io/{OWNER}/uter-{SERVICE}'
        ref=f'{base}@{digest}'
        raw=json.loads(invoke(['docker','buildx','imagetools','inspect','--raw',ref]))
        if raw.get('manifests'):
            targets=[]
            for entry in raw['manifests']:
                platform=entry.get('platform',{});osname=platform.get('os');arch=platform.get('architecture')
                if not osname or not arch or osname=='unknown' or arch=='unknown':raise ValueError('Unscannable manifest entry')
                if not re.fullmatch(r'sha256:[0-9a-f]{64}',entry.get('digest','')) or not re.fullmatch(r'[a-z0-9]+',osname+arch):
                    raise ValueError('Invalid manifest entry')
                targets.append((f'{base}@{entry["digest"]}',osname+'/'+arch))
        else:targets=[(ref,'linux/amd64')]
        for target,platform in targets:
            print('Auditing',SERVICE,digest,platform,flush=True)
            invoke(['docker','pull','--platform',platform,target])
            with tempfile.TemporaryDirectory(dir='work') as tmp:
                tmp=Path(tmp);report=tmp/'trivy.json';archive=tmp/'image.tar'
                invoke(['trivy','image','--quiet','--scanners','vuln,secret','--format','json','--output',report,'--timeout','15m',target])
                data=json.loads(report.read_text());secret_count=sum(len(r.get('Secrets',[])) for r in data.get('Results',[]))
                severities=collections.Counter(v.get('Severity','UNKNOWN') for r in data.get('Results',[]) for v in r.get('Vulnerabilities',[]))
                invoke(['docker','save',target,'-o',archive])
                scan=scanner.audit(archive,source_root='work/upstream')
                results.append({'version_digest':digest,'platform':platform,'image_digest':target.rsplit('@',1)[1],
                    'tags':version.get('metadata',{}).get('container',{}).get('tags',[]),
                    'vulnerabilities':dict(sorted(severities.items())),'secret_findings':secret_count,
                    'source_violations':len(scan['violations']),'violations':scan['violations'],
                    'source_fingerprints_compared':scan['source_fingerprints']})
            subprocess.run(['docker','image','rm',target],capture_output=True)
    output=Path(f'work/public-audit/{SERVICE}.json');output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(results,indent=2)+'\n')
    if any(x['secret_findings'] or x['source_violations'] for x in results):
        raise SystemExit('Public disclosure audit failed: source or secret findings')


if __name__=='__main__':main()
