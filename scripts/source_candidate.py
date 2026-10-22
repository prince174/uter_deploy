"""Record a tested source commit as a candidate, never as a deployable release."""
import argparse
import json
from pathlib import Path
import re

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--sha", required=True)
p.add_argument("--repository", default="prince174/uter")
p.add_argument("--run-url", required=True)
p.add_argument("--output", type=Path, default=Path("candidates/source.json"))
a = p.parse_args()
if not re.fullmatch(r"[0-9a-f]{40}", a.sha):
    p.error("full commit SHA required")
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps({"source_repository": a.repository, "source_commit": a.sha,
    "status": "source-tests-passed", "evidence": a.run_url,
    "next": "Build source-free images, record real digests, test upgrade, approve and sign release."}, indent=2) + "\n")
