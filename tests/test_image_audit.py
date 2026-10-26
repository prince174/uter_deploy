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


class BinaryExposureTests(unittest.TestCase):
    def test_elf_section_parser_reports_debug(self):
        import struct
        data=bytearray(64+3*64+24)
        data[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<Q',data,40,64)
        struct.pack_into('<HHH',data,58,64,3,1)
        names=b'\0.shstrtab\0.debug_info\0'
        struct.pack_into('<IIQQQQIIQQ',data,128,1,3,0,0,256,len(names),0,0,1,0)
        struct.pack_into('<IIQQQQIIQQ',data,192,11,1,0,0,0,0,0,0,1,0)
        data[256:256+len(names)]=names
        self.assertIn('.debug_info',load('audit_binary_exposure').sections(data))

    def test_invalid_binary_is_not_reported_as_clean(self):
        with self.assertRaises(ValueError):load('audit_binary_exposure').sections(b'not ELF')


class ModelExportTests(unittest.TestCase):
    def exporter(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('model_export',Path(__file__).resolve().parents[1]/'packaging/copy_model_cache.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def prepare(self,root):
        m=self.exporter();hub=root/'hub';model=hub/m.MODEL;rev='a'*40
        (model/'refs').mkdir(parents=True);(model/'refs/main').write_text(rev)
        snapshot=model/'snapshots'/rev;snapshot.mkdir(parents=True)
        for name in m.REQUIRED:(snapshot/name).write_bytes(b'model-fixture')
        (snapshot/'unrelated.py').write_text('must not ship')
        return m,hub,snapshot

    def test_only_named_resources_are_exported(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m,hub,snapshot=self.prepare(root)
            self.assertEqual(m.export(hub,root/'out'),len(m.REQUIRED))
            self.assertFalse(list((root/'out').rglob('*.py')))
            self.assertEqual(len(list((root/'out').rglob('model.safetensors'))),1)

    def test_shared_blob_is_materialized_and_escape_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m,hub,snapshot=self.prepare(root)
            blob=hub/'blobs/shared';blob.parent.mkdir();blob.write_bytes(b'shared')
            weight=snapshot/'model.safetensors';weight.unlink()
            try:weight.symlink_to(blob)
            except OSError:self.skipTest('Symlink creation unavailable; exercised on Linux CI')
            m.export(hub,root/'out')
            output=next((root/'out').rglob('model.safetensors'))
            self.assertFalse(output.is_symlink());self.assertEqual(output.read_bytes(),b'shared')
            weight.unlink();outside=root/'secret';outside.write_bytes(b'not-a-model');weight.symlink_to(outside)
            with self.assertRaises(ValueError):m.export(hub,root/'bad')
