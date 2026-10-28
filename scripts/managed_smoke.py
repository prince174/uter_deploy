"""Create a runtime-owned, noninteractive service acceptance command."""
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
WRAPPER='''import json,subprocess,time,urllib.error
from pathlib import Path
from uter_managed_smoke_http import check
home=Path(__file__).resolve().parent.parent
cfg=json.loads((home/'install.json').read_text())
creds=json.loads((home/'credentials.json').read_text())
forward=None
try:
 if cfg['backend']=='kubernetes':
  forward=subprocess.Popen(['kubectl','--context',cfg['context'],'-n',cfg['name'],'port-forward',
                            'service/'+cfg['name']+'-guardrail',str(cfg['port'])+':8000'],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for attempt in range(45):
  try:
   check('http://127.0.0.1:'+str(cfg['port']),'admin',creds['admin']);break
  except (OSError,urllib.error.URLError):
   if attempt==44:raise
   time.sleep(1)
finally:
 if forward:forward.terminate();forward.wait(timeout=10)
'''


def prepare(home):
    runtime=Path(home)/'runtime'
    helper=runtime/'uter_managed_smoke_http.py';wrapper=runtime/'uter_managed_smoke.py'
    if helper.exists() or helper.is_symlink() or wrapper.exists() or wrapper.is_symlink():
        raise ValueError('Managed smoke files already exist; refusing overwrite')
    created=[]
    try:
        for path,data in ((helper,(ROOT/'scripts/smoke_http.py').read_bytes()),(wrapper,WRAPPER.encode())):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            created.append(path)
            with os.fdopen(fd,'wb') as f:f.write(data)
    except BaseException:
        for path in created:path.unlink(missing_ok=True)
        raise
    return [sys.executable,str(wrapper)],created
