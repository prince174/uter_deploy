import io,json,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from test_tools import load

class WholeImageTests(unittest.TestCase):
    def image(self, path, files, config=None):
        layer=io.BytesIO()
        with tarfile.open(fileobj=layer,mode='w') as t:
            for name,data in files.items():
                x=tarfile.TarInfo(name);x.size=len(data);t.addfile(x,io.BytesIO(data))
        with tarfile.open(path,'w') as t:
            items={'layer.tar':layer.getvalue(),'config.json':json.dumps(config or {}).encode(),
                   'manifest.json':json.dumps([{'Layers':['layer.tar'],'Config':'config.json'}]).encode()}
            for name,data in items.items():
                x=tarfile.TarInfo(name);x.size=len(data);t.addfile(x,io.BytesIO(data))

    def test_source_outside_app_and_hidden_git(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'i.tar';self.image(p,{'home/uter/backup.py':b'code','opt/.git/config':b'git'})
            self.assertEqual(len(load('scan_image_archive').scan(p)),2)

    def test_renamed_product_source_inside_dependency_path(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'agent').mkdir();(root/'agent/a.py').write_bytes(b'proprietary')
            p=root/'i.tar';self.image(p,{'usr/local/lib/python3.12/site-packages/hidden.dat':b'proprietary'})
            result=load('scan_image_archive').audit(p,root)
            self.assertIn('exact product source copy',result['violations'][0])

    def test_nested_archive_source(self):
        z=io.BytesIO()
        with zipfile.ZipFile(z,'w') as f:f.writestr('main.py','code')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'i.tar';self.image(p,{'opt/backup.zip':z.getvalue()})
            result=load('scan_image_archive').audit(p)
            self.assertEqual(result['nested_archives'],1)
            self.assertIn('main.py',result['violations'][0])

    def test_stdlib_permitted_and_env_value_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'i.tar';self.image(p,{'usr/local/lib/python3.12/json/__init__.py':b'library'},
                {'config':{'Env':['API_KEY=do-not-print-me']}})
            result=load('scan_image_archive').audit(p)
            self.assertEqual(result['allowed_python_files'],1)
            self.assertEqual(len(result['violations']),1)
            self.assertNotIn('do-not-print-me',json.dumps(result))

    def test_uninspectable_archive_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'i.tar';self.image(p,{'opt/backup.zip':b'broken'})
            self.assertIn('uninspectable',load('scan_image_archive').scan(p)[0])

    def test_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'i.tar';self.image(p,{'../escape':b'data'})
            self.assertIn('unsafe',load('scan_image_archive').scan(p)[0])
