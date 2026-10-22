"""Render both backends without contacting a daemon or Kubernetes cluster."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        for name in ["guardrail.env", "agent.env", "redis.conf", "redis-password", "audit-hmac-key", "empty.env"]:
            (d / name).write_text("" if name.endswith(".env") else "test-only")
        for name in ["models", "policies", "profiles"]:
            (d / name).mkdir()
        images = {name: "registry.example/" + name + "@sha256:" + "a" * 64 for name in ["guardrail", "agent", "redis"]}
        env = os.environ.copy()
        env.update({k.upper() + "_IMAGE": v for k, v in images.items()})
        env["CUSTOMER_DIR"] = d.as_posix()
        raw = subprocess.check_output(["docker", "compose", "--env-file", str(d / "empty.env"), "-f", str(ROOT / "compose/compose.yaml"), "config", "--format", "json"], env=env)
        compose = json.loads(raw)
        assert set(compose["services"]) == set(images)
        assert all("build" not in s for s in compose["services"].values())
        for service in compose["services"].values():
            assert service["tmpfs"] == ["/tmp:size=128m,mode=1777"], "tmpfs options must remain one absolute mount"
        assert not any("ports" in compose["services"][x] for x in ["redis", "agent"])
        values = d / "images.json"
        values.write_text(json.dumps({"images": images, "productVersion": "1.0.0"}))
        args = [str(ROOT / "charts/uter"), "-f", str(ROOT / "examples/values.yaml"), "-f", str(values)]
        subprocess.run(["helm", "lint"] + args, check=True)
        raw = subprocess.check_output(["helm", "template", "uter-test"] + args)
        docs = [x for x in yaml.safe_load_all(raw) if x]
        workloads = [x for x in docs if x["kind"] == "Deployment"]
        assert len(workloads) == 3
        for obj in workloads:
            spec = obj["spec"]["template"]["spec"]
            assert spec["automountServiceAccountToken"] is False
            assert spec["securityContext"]["runAsNonRoot"] is True
            container = spec["containers"][0]
            assert container["image"] in images.values()
            assert container["securityContext"]["readOnlyRootFilesystem"] is True
            keys = [e["name"] for e in container.get("env", [])]
            assert len(keys) == len(set(keys)), "duplicate environment key"
        assert len([x for x in docs if x["kind"] == "NetworkPolicy"]) == 3
        assert len([x for x in docs if x["kind"] == "PersistentVolumeClaim"]) == 2
        print("Compose and Helm rendering/contract checks passed; no workloads started")


if __name__ == "__main__":
    main()
