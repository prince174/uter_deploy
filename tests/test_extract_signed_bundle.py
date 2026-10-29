import base64
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uterctl
from scripts import extract_signed_bundle
from scripts.bundle import build
from scripts.extract_signed_bundle import extract


class SignedBundleExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        key=Ed25519PrivateKey.generate();self.private=self.root/'private';self.public=self.root/'public'
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        manifest={'schema':1,'config_schema':1,'tooling_schema':1,'status':'released','version':'1.0.0',
                  'source_commit':'a'*40,'data_epoch':1,'upgrade_from':[],
                  'images':{s:'registry.example/'+s+'@sha256:'+'b'*64 for s in ('guardrail','agent','redis')}}
        source=self.root/'manifest.json';source.write_text(json.dumps(manifest));self.bundle=self.root/'bundle'
        build(source,self.bundle,self.private)

    def archive(self,name='bundle.tar.gz'):
        path=self.root/name
        with tarfile.open(path,'w:gz') as tar:tar.add(self.bundle,arcname='bundle')
        return path

    def test_verified_bundle_and_no_overwrite(self):
        archive=self.archive();output=self.root/'output'
        self.assertEqual(extract(archive,self.public,output)['version'],'1.0.0')
        self.assertTrue((output/'scripts/recover_compose.py').is_file())
        self.assertFalse((output/'INCOMPLETE').exists())
        with self.assertRaisesRegex(ValueError,'already exists'):extract(archive,self.public,output)

    def test_tampered_content_never_creates_destination(self):
        (self.bundle/'compose/compose.yaml').write_text('tampered')
        with self.assertRaisesRegex(ValueError,'inventory mismatch'):
            extract(self.archive(),self.public,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_rejects_parent_path_and_links(self):
        for index,name in enumerate(('bundle/../../escape','/absolute')):
            path=self.root/f'bad-{index}.tar'
            with tarfile.open(path,'w') as tar:
                info=tarfile.TarInfo(name);info.size=1;tar.addfile(info,io.BytesIO(b'x'))
            with self.assertRaisesRegex(ValueError,'Unsafe bundle path'):
                extract(path,self.public,self.root/f'out-{index}')
        path=self.root/'link.tar'
        with tarfile.open(path,'w') as tar:
            info=tarfile.TarInfo('bundle/link');info.type=tarfile.SYMTYPE;info.linkname='/tmp';tar.addfile(info)
        with self.assertRaisesRegex(ValueError,'Links'):
            extract(path,self.public,self.root/'out-link')

    def test_signed_raw_tar_and_large_payload_are_supported(self):
        # A valid signed file larger than the metadata-read cap must be copied in chunks.
        payload = b'x' * (3 * 1024 * 1024)
        (self.bundle/'large-fixture.bin').write_bytes(payload)
        inventory=json.dumps(uterctl.inventory(self.bundle),sort_keys=True).encode()
        private=serialization.load_pem_private_key(self.private.read_bytes(),password=None)
        (self.bundle/'checksums.json').write_bytes(inventory)
        (self.bundle/'checksums.sig').write_bytes(base64.b64encode(private.sign(inventory)))
        for mode,name in [('w:gz','large.tar.gz'),('w','large.tar')]:
            path=self.root/name
            with tarfile.open(path,mode) as tar:tar.add(self.bundle,arcname='bundle')
            out=self.root/('out-'+name)
            extract(path,self.public,out)
            self.assertEqual((out/'large-fixture.bin').read_bytes(),payload)

    def test_pax_metadata_bomb_is_rejected_before_large_gzip_read(self):
        path=self.root/'pax-bomb.tar.gz'
        with tarfile.open(path,'w:gz',format=tarfile.PAX_FORMAT) as tar:
            info=tarfile.TarInfo('bundle/file')
            info.pax_headers={'comment':'x'*50000}
            info.size=1;tar.addfile(info,io.BytesIO(b'x'))
        reads=[]
        original=extract_signed_bundle.gzip.GzipFile.read
        def tracked(stream,size=-1):
            reads.append(size)
            return original(stream,size)
        with patch.object(extract_signed_bundle,'MAX_TAR_READ',4096), \
             patch.object(extract_signed_bundle.gzip.GzipFile,'read',tracked):
            with self.assertRaisesRegex(ValueError,'metadata or read request exceeds'):
                extract(path,self.public,self.root/'out-pax')
        self.assertTrue(reads)
        self.assertTrue(all(0 <= size <= 4096 for size in reads),reads)
        self.assertFalse((self.root/'out-pax').exists())

    def test_gnu_longname_bomb_is_rejected_before_read(self):
        path=self.root/'gnu-bomb.tar.gz'
        with tarfile.open(path,'w:gz',format=tarfile.GNU_FORMAT) as tar:
            info=tarfile.TarInfo('bundle/'+'a'*50000)
            info.size=1;tar.addfile(info,io.BytesIO(b'x'))
        with patch.object(extract_signed_bundle,'MAX_TAR_READ',4096):
            with self.assertRaisesRegex(ValueError,'metadata or read request exceeds'):
                extract(path,self.public,self.root/'out-gnu')
        self.assertFalse((self.root/'out-gnu').exists())

    def test_decompressed_stream_limit_applies_before_skipping_payload(self):
        path=self.root/'payload-bomb.tar.gz'
        with tarfile.open(path,'w:gz') as tar:
            info=tarfile.TarInfo('bundle/file');info.size=128*1024
            tar.addfile(info,io.BytesIO(b'x'*info.size))
        self.assertLess(path.stat().st_size,4096)
        with patch.object(extract_signed_bundle,'MAX_TAR_STREAM',32*1024):
            with self.assertRaisesRegex(ValueError,'Decompressed tar stream exceeds limit'):
                extract(path,self.public,self.root/'out-payload')
        self.assertFalse((self.root/'out-payload').exists())

    def test_repeated_gzip_seek_work_is_bounded(self):
        stream=extract_signed_bundle.BoundedTarReader(io.BytesIO(b'abcdefghij'))
        stream.work_limit=5
        self.assertEqual(stream.read(4),b'abcd')
        stream.seek(0)
        with self.assertRaisesRegex(ValueError,'processing exceeds limit'):
            stream.read(4)

    def test_unadvertised_compression_and_nonregular_inputs_are_rejected(self):
        for index,data in enumerate((b'BZh9junk',b'\xfd7zXZ\x00junk')):
            path=self.root/f'unsupported-{index}'
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'Only gzip or uncompressed'):
                extract(path,self.public,self.root/f'out-compression-{index}')
        if os.name=='posix':
            fifo=self.root/'fifo'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError,'regular file'):
                extract(fifo,self.public,self.root/'out-fifo')
