import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
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

    def test_build_command_without_cache_fetches_both_pinned_official_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lock = self.fixture(root)
            blobs = {lock[key]['url']: (root / lock[key]['filename']).read_bytes()
                     for key in ('archive', 'source')}
            # The CLI must succeed with no downloads directory or --cache input.
            for key in ('archive', 'source'):
                (root / lock[key]['filename']).unlink()
            lock_path = root / 'release.json'; lock_path.write_text(json.dumps(lock))
            def download(url, timeout):
                self.assertEqual(timeout, 60)
                self.assertTrue(url.startswith('https://github.com/zero-peak/ZeroOmega/'))
                return io.BytesIO(blobs[url])
            with mock.patch('sys.argv', ['install_zeroomega.py', '--lock', str(lock_path),
                    '--target', str(root / 'installed'), '--source-target', str(root / 'licenses')]), \
                    mock.patch.object(module.urllib.request, 'urlopen', side_effect=download) as fetch:
                runpy.run_path(str(ROOT / 'runtime/install_zeroomega.py'), run_name='__main__')
            self.assertEqual([call.args[0] for call in fetch.call_args_list],
                             [lock['archive']['url'], lock['source']['url']])
            self.assertEqual((root / 'licenses' / lock['source']['filename']).read_bytes(), b'fixture source')
            self.assertEqual(json.loads((root / 'installed/manifest.json').read_text())['key'], lock['manifest_key'])
            self.assertFalse((root / 'downloads').exists())

    def test_uncached_download_hash_and_origin_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); lock = self.fixture(root)
            with mock.patch.object(module.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupt')):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    module.install(lock, None, root / 'target', root / 'source')
            self.assertFalse((root / 'target').exists())
            lock['archive']['url'] = 'https://example.invalid/untrusted.zip'
            with mock.patch.object(module.urllib.request, 'urlopen') as fetch:
                with self.assertRaisesRegex(ValueError, 'Unexpected asset source'):
                    module.install(lock, None, root / 'target', root / 'source')
                fetch.assert_not_called()

    def test_pinned_release_identity_is_unchanged(self):
        lock = json.loads((ROOT / 'vendor/zeroomega/release.json').read_text())
        self.assertEqual(lock['version'], '3.5.2')
        self.assertEqual(lock['archive']['url'], 'https://github.com/zero-peak/ZeroOmega/releases/download/v3.5.2/chromium-release.zip')
        self.assertEqual(lock['archive']['sha256'], '8e662c1ebc5b4ddb63e65a7c8664709c15cedf27c933c8ba8ff6d99b0c037ab0')
        self.assertEqual(lock['source']['url'], 'https://github.com/zero-peak/ZeroOmega/archive/refs/tags/v3.5.2.zip')
        self.assertEqual(lock['source']['sha256'], '72914e1cdd213b8ee2ca23955b3c5829cf22df6c3665288bb59ab9ccc1799379')

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
