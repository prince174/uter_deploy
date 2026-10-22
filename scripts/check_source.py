"""Run from an isolated product snapshot; keep pytest suites in separate processes."""
import subprocess
import sys

for suite in ("tests/unit", "tests/api"):
    result = subprocess.run([sys.executable, "-m", "pytest", suite, "-q"])
    if result.returncode:
        raise SystemExit(result.returncode)
