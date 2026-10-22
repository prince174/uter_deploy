"""Executed inside the final image with networking disabled. No source imports."""
import importlib
import json
from pathlib import Path
import sys

service = sys.argv[1]
modules = sorted(p.name.split(".")[0] for p in Path("/app").glob("*.so"))
assert modules and "main" in modules
assert not list(Path("/app").rglob("*.py"))
assert not list(Path("/app").rglob("*.pyc"))
for name in modules:
    module = importlib.import_module(name)
    assert str(module.__file__).endswith(".so"), (name, module.__file__)
app = importlib.import_module("main").app
schema = app.openapi()
assert schema["paths"], "FastAPI schema missing"
if service == "guardrail":
    from toxicity_guard import ToxicityGuard
    guard = ToxicityGuard()
    guard.load()
    assert guard.available, "Real toxicity model unavailable without network"
    result = guard._pipeline("Have a nice day")
    assert result, "No model inference result"
print(json.dumps({"service": service, "compiled_modules": modules,
                  "openapi_paths": len(schema["paths"]),
                  "offline_toxicity_inference": service == "guardrail"}))
