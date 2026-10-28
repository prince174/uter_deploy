"""Audit one stored image artifact; reports only counts, never file contents."""
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('SERVICE','guardrail')
from scripts.audit_public_packages import source_fingerprints
from scripts import scan_image_archive as scanner

artifact=os.environ['ARTIFACT_ID']
if not re.fullmatch(r'[0-9]+',artifact):raise ValueError('Invalid artifact ID')
work=Path('work/historical-audit');work.mkdir(parents=True,exist_ok=True)
archive=work/'artifact.zip'
with archive.open('wb') as out:
    p=subprocess.run(['gh','api',f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/{artifact}/zip"],stdout=out,stderr=subprocess.PIPE)
if p.returncode:raise RuntimeError('Artifact download failed; output withheld')
with zipfile.ZipFile(archive) as z:
    entries=z.infolist()
    if sum(x.file_size for x in entries)>4_000_000_000:raise ValueError('Artifact size limit exceeded')
    for x in entries:
        p=PurePosixPath(x.filename)
        if p.is_absolute() or '..' in p.parts or '\\' in x.filename or ((x.external_attr>>16)&0o170000)==0o120000:
            raise ValueError('Unsafe artifact path')
    z.extractall(work/'input')
images=list((work/'input').rglob('*.tar'))+list((work/'input').rglob('*.tar.gz'))
if len(images)!=1:raise ValueError('Expected one image archive')
scanner.fingerprints=lambda _:source_fingerprints('work/upstream')
report=scanner.audit(images[0],source_root='work/upstream')
trivy=work/'trivy.json'
p=subprocess.run(['trivy','image','--quiet','--input',str(images[0]),'--scanners','secret','--format','json','--output',str(trivy),'--timeout','15m'],capture_output=True)
if p.returncode:raise RuntimeError('Secret scan failed; output withheld')
findings=json.loads(trivy.read_text())
count=sum(len(x.get('Secrets',[])) for x in findings.get('Results',[]))
result={'artifact_id':artifact,'source_violations':len(report['violations']),'secret_findings':count,'layers':report['layers']}
(work/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
if count or result['source_violations']:raise SystemExit('Historical image requires review')
