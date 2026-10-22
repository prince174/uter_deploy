"""Executed inside the final image with networking disabled. No source imports."""
import importlib
import importlib.util
import importlib.machinery
import json
from pathlib import Path
import sys

service = sys.argv[1]
sys.path.insert(0, "/app")
modules = sorted(p.name.split(".")[0] for p in Path("/app").glob("*.so"))
assert modules and "main" in modules
assert not list(Path("/app").rglob("*.py"))
assert not list(Path("/app").rglob("*.pyc"))
for name in modules:
    spec = importlib.util.find_spec(name)
    assert spec and isinstance(spec.loader, importlib.machinery.ExtensionFileLoader), (name, spec)
    assert spec.origin.endswith(".so") and Path(spec.origin).is_file(), (name, spec.origin)
    module = importlib.import_module(name)
    # Nuitka intentionally exposes a diagnostic .py __file__; it is not a source file.
    assert not Path("/app", name + ".py").exists(), name
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
