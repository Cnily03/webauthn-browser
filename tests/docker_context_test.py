"""Tracked-input Docker contracts, without running a daemon or fetching assets."""
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def local_copy_sources(dockerfile):
    """Read the Dockerfile's shell-form COPYs; stage outputs are not host inputs."""
    sources = []
    for line in dockerfile.replace('\\\n', '').splitlines():
        words = shlex.split(line, comments=True)
        if not words or words[0].upper() != 'COPY':
            continue
        if any(word.startswith('--from=') for word in words[1:]):
            continue
        if any(word.startswith('--') for word in words[1:]):
            raise AssertionError('Review new COPY options in the tracked-context contract')
        sources.extend(words[1:-1])
    return sources


class DockerContextTests(unittest.TestCase):
    def test_every_local_copy_resolves_in_a_tracked_only_checkout(self):
        if not (ROOT / '.git').exists() or shutil.which('git') is None:
            self.skipTest('Requires Git checkout metadata to verify tracked-only inputs')
        tracked = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
        tracked = [path for path in tracked if path]
        self.assertFalse(any(path.startswith('downloads/') for path in tracked))
        dockerfile = (ROOT / 'Dockerfile').read_text()
        sources = local_copy_sources(dockerfile)
        with tempfile.TemporaryDirectory(prefix='webauthn-tracked-context-') as temporary:
            context = pathlib.Path(temporary)
            # Read current versions of tracked files: ignored local artifacts and
            # unrelated untracked work cannot satisfy any COPY in this fixture.
            for name in tracked:
                source = ROOT / name
                self.assertFalse(source.is_symlink(), name)
                target = context / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            for source in sources:
                self.assertNotIn('$', source)
                self.assertNotIn('*', source)
                path = context / source
                self.assertTrue(path.exists(), f'COPY requires an untracked input: {source}')
                if path.is_dir():
                    self.assertTrue(any(path.rglob('*')), source)
            for generated in ('downloads', 'web/dist', 'web/node_modules', 'target',
                              'helper/target', 'helper/dist', 'native-hid-hook/target'):
                self.assertFalse((context / generated).exists(), generated)
            # These shared includes/path dependencies must survive relocation,
            # rather than being supplied by a local compiler output or old tree.
            for crate in (context, context / 'helper'):
                manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
                shared = (crate / manifest['dependencies']['fido-report-relay']['path']).resolve()
                self.assertEqual(shared, context / 'src/fido-relay')
                self.assertTrue((shared / 'src/lib.rs').is_file())
            for required in ('src/fido-relay/src/control.rs', 'extension/build.sha256',
                             'native-hid-hook/build.rs', 'native-hid-hook/native/abi.c',
                             'native-hid-hook/Cargo.lock', 'helper/build.rs',
                             'vendor/zeroomega/release.json', 'vendor/webrtc-control/release.json',
                             'runtime/install_webrtc_control.py', 'web/pnpm-lock.yaml'):
                self.assertTrue((context / required).is_file(), required)

    def test_downloads_are_empty_image_mount_not_a_build_input(self):
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertNotIn('downloads', local_copy_sources(dockerfile))
        self.assertNotIn('--cache ', dockerfile)
        self.assertIn('install -d -o root -g root -m 0755 /downloads', dockerfile)
        ignores = (ROOT / '.dockerignore').read_text().splitlines()
        for path in ('downloads', 'helper/dist', 'web/dist', 'web/node_modules',
                     'target', 'helper/target', 'native-hid-hook/target', 'src/fido-relay/target'):
            self.assertIn(path, ignores)
        self.assertIn('/downloads/', (ROOT / '.gitignore').read_text().splitlines())
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('      - "./downloads:/downloads:ro"', compose)
        self.assertIn('      - "./.data:/data"', compose)
        self.assertNotIn('create_host_path:', compose)
        self.assertIn('AUTH_BROWSER_DOWNLOADS_DIR=/downloads', dockerfile)

    def test_generated_web_and_native_outputs_come_from_image_build_stages(self):
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertIn('RUN pnpm install --frozen-lockfile', dockerfile)
        self.assertIn('RUN pnpm run build', dockerfile)
        self.assertIn('COPY --from=frontend /build/web/dist /opt/webauthn-browser/web/dist', dockerfile)
        self.assertIn('RUN cargo build --locked --release', dockerfile)
        self.assertIn('cargo build --locked --release --manifest-path native-hid-hook/Cargo.toml', dockerfile)
        self.assertIn('COPY --from=builder /build/native-hid-runtime /opt/webauthn-browser/native', dockerfile)
        self.assertNotIn('COPY target', dockerfile)
        self.assertNotIn('COPY web/dist', dockerfile)
        self.assertNotIn('COPY helper/dist', dockerfile)


if __name__ == '__main__':
    unittest.main()
