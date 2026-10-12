import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_zeroomega', ROOT / 'runtime/install_zeroomega.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ZeroOmegaTests(unittest.TestCase):
    def fixture(self, root, **overrides):
        lock = json.loads((ROOT / 'vendor/zeroomega/release.json').read_text())
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for name, value in {'manifest.json': json.dumps({'manifest_version': 3, 'version': '3.5.2', 'background': {'service_worker': 'worker.js'}}), 'worker.js': '', 'COPYING': 'GPL', 'AUTHORS': 'Upstream', **overrides}.items():
                archive.writestr(name, value)
        for name, blob in [('archive', data.getvalue()), ('source', b'fixture source')]:
            (root / lock[name]['filename']).write_bytes(blob)
            lock[name]['sha256'] = hashlib.sha256(blob).hexdigest()
        return lock

    def test_verified_id_is_official_store_id(self):
        lock = json.loads((ROOT / 'vendor/zeroomega/release.json').read_text())
        digest = hashlib.sha256(base64.b64decode(lock['manifest_key'])).hexdigest()[:32]
        self.assertEqual(''.join(chr(97 + int(c, 16)) for c in digest), 'pfnededegaaopdmhkdmcofjmoldfiped')

    def test_installs_readonly_assets_and_source_without_profile_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lock = self.fixture(root)
            profile = root / 'profile'; profile.mkdir()
            user = profile / 'Local Extension Settings'; user.write_bytes(b'user proxy configuration')
            with mock.patch.object(module.urllib.request, 'urlopen', side_effect=AssertionError('unexpected download')):
                module.install(lock, root, root / 'installed', root / 'licenses')
            manifest = json.loads((root / 'installed/manifest.json').read_text())
            self.assertEqual(manifest['key'], lock['manifest_key'])
            self.assertEqual((root / 'installed/manifest.json').stat().st_mode & 0o777, 0o444)
            self.assertEqual((root / 'licenses' / lock['source']['filename']).read_bytes(), b'fixture source')
            self.assertEqual(user.read_bytes(), b'user proxy configuration')

    def test_bad_cached_hash_fails_without_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lock = self.fixture(root); lock['archive']['sha256'] = '0' * 64
            with mock.patch.object(module.urllib.request, 'urlopen', side_effect=AssertionError('unexpected download')):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    module.install(lock, root, root / 'target', root / 'source')
            self.assertFalse((root / 'target').exists())

    def test_zip_traversal_and_mv2_rejected(self):
        for entries in ({'../escape': 'no'}, {'manifest.json': '{"manifest_version":2,"version":"3.5.2"}'}):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); lock = self.fixture(root, **entries)
                with self.assertRaises(ValueError):
                    module.install(lock, root, root / 'target', root / 'source')
                self.assertFalse((root / 'target').exists())

    def test_existing_target_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lock = self.fixture(root); (root / 'target').mkdir()
            sentinel = root / 'target/user'; sentinel.write_bytes(b'preserve')
            with self.assertRaisesRegex(ValueError, 'existing'):
                module.install(lock, root, root / 'target', root / 'source')
            self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_engine_coexists_without_disabling_user_extensions(self):
        source = (ROOT / 'runtime/supervisor.py').read_text()
        self.assertIn('--load-extension=/opt/webauthn-browser/extension,/opt/webauthn-browser/extensions/zeroomega', source)
        self.assertNotIn('--disable-extensions-except', source)
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('install_zeroomega.py', docker)
        self.assertNotIn('/data/chromium', (ROOT / 'runtime/install_zeroomega.py').read_text())


if __name__ == '__main__':
    unittest.main()
