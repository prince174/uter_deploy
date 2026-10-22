import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ToolTests(unittest.TestCase):
    def test_workflow_yaml_is_valid(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            workflow = yaml.safe_load(path.read_text())
            self.assertIn("jobs", workflow)

    def test_scan_detects_deleted_source_in_old_layer(self):
        scanner = load("scan_image_archive")
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "image.tar"
            with tarfile.open(archive, "w") as outer:
                for name, member in [("one.tar", "app/main.py"), ("two.tar", "app/.wh.main.py")]:
                    buf = io.BytesIO()
                    with tarfile.open(fileobj=buf, mode="w") as layer:
                        info = tarfile.TarInfo(member); info.size = 1
                        layer.addfile(info, io.BytesIO(b"x"))
                    data = buf.getvalue(); info = tarfile.TarInfo(name); info.size = len(data)
                    outer.addfile(info, io.BytesIO(data))
                data = json.dumps([{"Layers": ["one.tar", "two.tar"]}]).encode()
                info = tarfile.TarInfo("manifest.json"); info.size = len(data)
                outer.addfile(info, io.BytesIO(data))
            self.assertTrue(any("one.tar: app/main.py" in x for x in scanner.scan(archive)))

    def test_watcher_checks_snapshot_without_mutating_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "source"; source.mkdir()
            subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
            (source / "test.py").write_text("original")
            (source / ".env").write_text("secret")
            command = root / "command.json"
            command.write_text(json.dumps([sys.executable, "-c", "from pathlib import Path; assert not Path('.env').exists(); Path('test.py').write_text('changed')"]))
            subprocess.run([sys.executable, ROOT / "scripts/watch_source.py", "--source", source, "--work", root / "work", "--command-json", command, "--once"], check=True, capture_output=True)
            self.assertEqual((source / "test.py").read_text(), "original")
            result = json.loads((root / "work/status.json").read_text())
            self.assertEqual(result["exit_code"], 0)
            self.assertFalse(result["published"])

    def test_watcher_refuses_work_under_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmd = root / "cmd.json"; cmd.write_text('["echo"]')
            result = subprocess.run([sys.executable, ROOT / "scripts/watch_source.py", "--source", root, "--work", root / "work", "--command-json", cmd, "--once"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "work").exists())

    def test_deploy_repo_does_not_contain_product_sources(self):
        self.assertFalse((ROOT / "guardrail").exists())
        self.assertFalse((ROOT / "agent").exists())


if __name__ == "__main__": unittest.main()
