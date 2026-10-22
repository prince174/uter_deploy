"""Check EVERY docker-save layer for application source; no extraction to disk."""
import argparse
import json
from pathlib import PurePosixPath
import tarfile


def scan(path):
    violations = []
    with tarfile.open(path) as outer:
        manifests = json.load(outer.extractfile("manifest.json"))
        for layer in sorted({x for m in manifests for x in m["Layers"]}):
            with tarfile.open(fileobj=outer.extractfile(layer), mode="r|*") as contents:
                for member in contents:
                    p = PurePosixPath(member.name.lstrip("./"))
                    if p.parts and p.parts[0] == "app" and (p.suffix in {".py", ".pyc", ".pyo"} or ".git" in p.parts or p.name.startswith(".env")):
                        violations.append(f"{layer}: {member.name}")
    return violations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    failures = scan(parser.parse_args().archive)
    if failures:
        raise SystemExit("Forbidden application files:\n" + "\n".join(failures))
    print("No forbidden /app sources found in any layer; not a full secret scan")
