"""CI fixture: deliberately map a child SIGTERM outcome to exit 0.

The container runtime may put an init process ahead of this wrapper. This does
not prove drain, audit flush, or graceful shutdown. Never use in product images.
"""
import os
import signal
import subprocess
import sys

if len(sys.argv)<2:raise SystemExit(2)
child=subprocess.Popen(sys.argv[1:],start_new_session=True)
stopping=False


def stop(_signum,_frame):
    global stopping
    stopping=True
    try:os.killpg(child.pid,signal.SIGTERM)
    except ProcessLookupError:pass


signal.signal(signal.SIGTERM,stop)
code=child.wait()
raise SystemExit(0 if stopping else code)
