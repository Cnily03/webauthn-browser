import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_webrtc_control', ROOT / 'runtime/install_webrtc_control.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def field(tag, value):
    def varint(n):
        result = bytearray()
        while n > 127:
            result.append((n & 127) | 128)
            n >>= 7
        result.append(n)
        return result
    return bytes(varint(tag << 3 | 2) + varint(len(value))) + value


class WebRTCControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.key = cls.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def fixture(self, **overrides):
        lock = json.loads((ROOT / 'vendor/webrtc-control/release.json').read_text())
        lock['manifest_key'] = base64.b64encode(self.key).decode()
        lock['extension_id'] = module.extension_id(self.key)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            for name, value in {'manifest.json': json.dumps({'name': 'WebRTC Control',
                    'manifest_version': 3, 'version': '0.3.5',
                    'background': {'service_worker': 'background.js'}}),
                    'background.js': '// publisher fixture', '_metadata/verified_contents.json': '{}',
                    **overrides}.items():
                bundle.writestr(name, value)
        signed = field(1, hashlib.sha256(self.key).digest()[:16])
        message = b'CRX3 SignedData\0' + struct.pack('<I', len(signed)) + signed + archive.getvalue()
        signature = self.private.sign(message, padding.PKCS1v15(), hashes.SHA256())
        header = field(2, field(1, self.key) + field(2, signature)) + field(10000, signed)
        data = b'Cr24' + struct.pack('<II', 3, len(header)) + header + archive.getvalue()
        lock['archive']['sha256'] = hashlib.sha256(data).hexdigest()
        return lock, data

    def install(self, lock, data, root):
        response = io.BytesIO(data)
        response.geturl = lambda: lock['archive']['url']
        with mock.patch.object(module, 'EXTENSION_ID', lock['extension_id']), \
                mock.patch.object(module.urllib.request, 'urlopen', return_value=response) as fetch:
            module.install(lock, root / 'installed', root / 'provenance')
        fetch.assert_called_once_with(lock['archive']['url'], timeout=60)

    def test_official_pinned_identity_and_source(self):
        lock = json.loads((ROOT / 'vendor/webrtc-control/release.json').read_text())
        self.assertEqual(module.extension_id(base64.b64decode(lock['manifest_key'])), module.EXTENSION_ID)
        self.assertEqual(lock['version'], '0.3.5')
        self.assertEqual(lock['archive']['sha256'], '9e5b82cedd9374e6bc132296eb8918c655d8df28d554a0fe8a57423f24c91b67')
        self.assertTrue(lock['archive']['url'].startswith('https://clients2.googleusercontent.com/crx/blobs/'))
        self.assertTrue(lock['archive']['url'].endswith('/FJKMABMDEPJFAMMLPLILJPNBHLEEGEHM_0_3_5_0.crx'))

    def test_fresh_install_retains_original_and_preserves_existing_profile(self):
        lock, data = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / 'profile/Local Extension Settings'
            profile.mkdir(parents=True)
            sentinel = profile / 'saved-settings'; sentinel.write_bytes(b'user preferences')
            self.install(lock, data, root)
            manifest = json.loads((root / 'installed/manifest.json').read_text())
            self.assertEqual(manifest['key'], lock['manifest_key'])
            self.assertEqual((root / 'installed/background.js').read_text(), '// publisher fixture')
            self.assertFalse((root / 'installed/_metadata').exists())
            self.assertEqual((root / 'provenance' / lock['archive']['filename']).read_bytes(), data)
            self.assertEqual((root / 'installed/manifest.json').stat().st_mode & 0o777, 0o444)
            self.assertEqual((root / 'installed').stat().st_mode & 0o777, 0o555)
            self.assertEqual(sentinel.read_bytes(), b'user preferences')
            with self.assertRaisesRegex(ValueError, 'existing'):
                module.install(lock, root / 'installed', root / 'provenance')

    def test_bad_hash_and_wrong_source_fail_closed(self):
        for mutation, message in [('hash', 'SHA-256'), ('source', 'source')]:
            lock, data = self.fixture()
            if mutation == 'hash': lock['archive']['sha256'] = '0' * 64
            else: lock['archive']['url'] = 'https://example.com/extension.crx'
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(ValueError, message):
                    self.install(lock, data, Path(tmp))
                self.assertFalse((Path(tmp) / 'installed').exists())

    def test_signed_identity_and_tampered_signature_rejected(self):
        lock, data = self.fixture()
        with mock.patch.object(module, 'EXTENSION_ID', lock['extension_id']):
            lock['manifest_key'] = base64.b64encode(b'wrong public key').decode()
            with self.assertRaisesRegex(ValueError, 'key/ID'):
                module.verified_zip(data, lock)
        lock, data = self.fixture()
        with mock.patch.object(module, 'EXTENSION_ID', lock['extension_id']):
            from cryptography.exceptions import InvalidSignature
            with self.assertRaises(InvalidSignature):
                module.verified_zip(data[:-1] + bytes([data[-1] ^ 1]), lock)

    def test_traversal_mv2_and_missing_worker_rejected(self):
        cases = [{'../escape': 'no'}, {'/absolute': 'no'}, {'dir\\escape': 'no'},
                 {'manifest.json': '{"name":"WebRTC Control","manifest_version":2,"version":"0.3.5"}'},
                 {'manifest.json': '{"name":"WebRTC Control","manifest_version":3,"version":"0.3.5"}'}]
        for entries in cases:
            lock, data = self.fixture(**entries)
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError): self.install(lock, data, Path(tmp))
                self.assertFalse((Path(tmp) / 'installed').exists())

    def test_malformed_crx_rejected(self):
        lock, data = self.fixture()
        for malformed in [b'', b'Cr24' + struct.pack('<II', 2, 0), data[:16]]:
            with self.assertRaises(ValueError): module.verified_zip(malformed, lock)
        for malformed in [b'\x80', b'\x0a\x03x', b'\x08\x01', b'\x80' * 11]:
            with self.assertRaises(ValueError): list(module.fields(malformed))

    def test_loader_preserves_other_extensions_and_profile_state(self):
        source = (ROOT / 'runtime/supervisor.py').read_text()
        self.assertIn('--load-extension=/opt/webauthn-browser/extension,/opt/webauthn-browser/extensions/zeroomega,/opt/webauthn-browser/extensions/webrtc-control', source)
        self.assertNotIn('--disable-extensions-except', source)
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('COPY vendor/webrtc-control ', docker)
        self.assertIn('python3-cryptography', docker)
        self.assertIn('runtime/install_webrtc_control.py', docker)
        self.assertNotIn('/data/', (ROOT / 'runtime/install_webrtc_control.py').read_text())
        self.assertNotIn('--cache', (ROOT / 'runtime/install_webrtc_control.py').read_text())


if __name__ == '__main__':
    unittest.main()
