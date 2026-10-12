"""Actual download-directory HTTP checks; requires a release backend and free 8080.

Uses real release executables plus isolated arbitrary-file fixtures. Never starts
Chromium or a BLE scan, and never changes the repository's downloads directory.
"""
import argparse
from datetime import datetime
from contextlib import contextmanager
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    'webauthn-helper-linux-x86_64',
    'webauthn-helper-desktop-linux-x86_64',
    'webauthn-helper-windows-x86_64.exe',
    'webauthn-helper-desktop-windows-x86_64.exe',
    'webauthn-helper-macos-universal',
    'webauthn-helper-desktop-macos-universal',
)


def encode_name(name):
    # Match the server's conservative byte-based URL encoding, including names
    # that cannot be represented as UTF-8. Never normalize or double-decode them.
    return ''.join(chr(b) if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122
                   else f'%{b:02X}' for b in name)


class Client:
    def __init__(self):
        self.client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.token = ''

    def request(self, path, body=None, method=None, token=None, headers=None):
        request_headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': self.token if token is None else token,
        }
        request_headers.update(headers or {})
        return self.client.open(urllib.request.Request(
            'http://127.0.0.1:8080' + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=request_headers, method=method), timeout=10)

    def json(self, path, body=None, method=None):
        with self.request(path, body, method) as response:
            return json.load(response)

    def status(self):
        status = self.json('/api/status')
        self.token = status['csrf_token']
        return status

    def expect_error(self, path, codes, **kwargs):
        try:
            with self.request(path, **kwargs) as response:
                raise AssertionError(f'Unexpected {response.status} for {path}')
        except urllib.error.HTTPError as error:
            with error:
                assert error.code in codes, (path, error.code, error.read())


@contextmanager
def server(tmp, binary, directory=None, cwd=ROOT):
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1', 8080)) == 0:
            raise RuntimeError('Port 8080 is occupied; stop the other smoke/backend first')
    env = dict(os.environ, AUTH_BROWSER_STORE=str(tmp / 'store.json'),
               AUTH_BROWSER_PROXY_SOCKET=str(tmp / 'run/proxy.sock'))
    env.pop('AUTH_BROWSER_DOWNLOADS_DIR', None)
    if directory is not None:
        env['AUTH_BROWSER_DOWNLOADS_DIR'] = str(directory)
    with (tmp / 'backend.log').open('w+b') as log:
        child = subprocess.Popen([str(binary)], cwd=cwd, env=env,
                                 stdout=subprocess.DEVNULL, stderr=log)
        try:
            client = Client()
            for _ in range(200):
                if child.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read().decode(errors='replace'))
                try:
                    client.status()
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Backend did not start')
            yield client
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def path_for(directory, name):
    return os.path.join(os.fsencode(directory), name)


def digest_file(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def read_directory(client, names, path='/downloads'):
    with client.request(path) as response:
        assert response.headers['Content-Type'].startswith('text/html')
        assert response.headers['Cache-Control'] == 'no-store'
        page = response.read().decode('utf-8')
        assert '<title>WebAuthn Browser</title>' in page
        assert '下载目录中的文件（不包含子目录和符号链接）' not in page
        assert response.headers['Content-Security-Policy']
    with client.request('/api/downloads') as response:
        assert response.headers['Content-Type'].startswith('application/json')
        assert response.headers['Cache-Control'] == 'no-store'
        entries = json.load(response)['files']
    actual = [urllib.parse.unquote_to_bytes(entry['url'].removeprefix('/downloads/'))
              for entry in entries]
    assert actual == sorted(names), (actual, sorted(names))
    for entry in entries:
        name = urllib.parse.unquote_to_bytes(entry['url'].removeprefix('/downloads/'))
        assert entry['name'] == name.decode('utf-8', errors='replace'), entry
        assert entry['url'] == '/downloads/' + encode_name(name), entry
        assert isinstance(entry['size'], int) and entry['size'] >= 0, entry
        if entry['created_at'] is not None:
            assert datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00')).tzinfo
    return entries


def check_download(client, route, name, source, method=None):
    with client.request(route + encode_name(name), method=method) as response:
        assert response.headers['Content-Type'] == 'application/octet-stream'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['Content-Security-Policy'] == "sandbox; default-src 'none'"
        assert response.headers['Cache-Control'] == 'no-store'
        assert response.headers['X-Injected'] is None
        size = os.stat(source).st_size
        assert int(response.headers['Content-Length']) == size
        disposition = response.headers['Content-Disposition']
        assert disposition.startswith('attachment; filename="download"')
        try:
            name.decode('utf-8')
        except UnicodeDecodeError:
            assert 'filename*=' not in disposition
        else:
            assert disposition == "attachment; filename=\"download\"; filename*=UTF-8''" + encode_name(name)
        digest = hashlib.sha256()
        length = 0
        while chunk := response.read(64 * 1024):
            length += len(chunk)
            digest.update(chunk)
        if method == 'HEAD':
            assert length == 0
        else:
            assert length == size
            assert digest.hexdigest() == digest_file(source), name


def exercise_directory(tmp, binary):
    directory = tmp / 'published'
    directory.mkdir()
    names = set()
    builds = {name for name in TARGETS if (ROOT / 'downloads' / name).is_file()}
    assert builds, 'Build real helper release artifacts first'
    for name in builds:
        shutil.copyfile(ROOT / 'downloads' / name, directory / name)
        names.add(name.encode())
    fixtures = {
        b'README.md': b'an unrelated document\n',
        b'builds.json': b'{"fixture": true}\n',
        b'zero-byte': b'',
        b'page.html': b'<script>alert("must download")</script>',
        '下载 空格 #?.txt'.encode(): b'unicode filename',
        b'\"><img src=x onerror=alert(1)>&\'.html': b'markup filename',
        b'header\r\nX-Injected: yes.txt': b'header filename',
        b'raw-\xff.bin': b'raw Unix filename',
        b'back\\slash.txt': b'backslash is a Unix filename byte',
        b'literal%2Fname.txt': b'percent escapes decode once',
        b'.hidden': b'dot files are regular files too',
    }
    for name, data in fixtures.items():
        with open(path_for(directory, name), 'wb') as file:
            file.write(data)
        names.add(name)
    # Creation metadata must never be fabricated from a backdated mtime.
    os.utime(directory / 'README.md', (946684800, 946684800))
    # General downloads have no helper catalog size cap. Keep this sparse on
    # disk and consume HTTP in chunks, never buffer the whole file in the test.
    large_name = b'large-over-manifest-limit.bin'
    with open(path_for(directory, large_name), 'wb') as file:
        file.truncate(64 * 1024 * 1024 + 1)
    names.add(large_name)
    outside = tmp / 'outside-secret.txt'
    outside.write_bytes(b'not downloadable')
    nested = directory / 'nested'
    nested.mkdir()
    (nested / 'private.txt').write_bytes(b'not recursively listed')
    (directory / 'outside-link').symlink_to(outside)
    (directory / 'inside-link').symlink_to(directory / 'README.md')
    (directory / 'linked-directory').symlink_to(tmp, target_is_directory=True)
    (directory / 'broken-link').symlink_to(tmp / 'absent')
    os.mkfifo(directory / 'fifo')

    tested_files = len(names)
    with server(tmp, binary, directory) as client:
        initial = read_directory(client, names)
        metadata = next(entry for entry in initial if entry['name'] == 'README.md')
        assert metadata['size'] == len(fixtures[b'README.md'])
        if metadata['created_at'] is not None:
            assert datetime.fromisoformat(metadata['created_at'].replace('Z', '+00:00')).timestamp() > 946684800
        read_directory(client, names, '/downloads/')
        manifest = client.json('/api/helper/downloads')
        assert client.json('/api/companion/downloads') == manifest  # Compatibility alias.
        assert len(manifest['downloads']) + len(manifest['unavailable']) == 6
        assert {entry['filename'] for entry in manifest['downloads']} == builds
        for entry in manifest['downloads']:
            assert entry['url'] == '/download/' + entry['filename']
            assert entry['mode'] in ('cli', 'desktop')
            source = directory / entry['filename']
            assert source.stat().st_size == entry['size']
            assert digest_file(source) == entry['sha256']
        for name in names:
            source = path_for(directory, name)
            check_download(client, '/downloads/', name, source)
            if name != large_name:
                check_download(client, '/download/', name, source)
        check_download(client, '/downloads/', b'README.md', directory / 'README.md', 'HEAD')
        for prefix in ('/downloads/', '/download/'):
            for name in ('outside-link', 'inside-link', 'linked-directory', 'broken-link',
                         'nested', 'fifo', 'missing', '.', '..', '%2e', '%2e%2e',
                         '%2e%2e%2foutside-secret.txt', '%2Fetc%2Fpasswd',
                         'nested%2Fprivate.txt', 'linked-directory%2Foutside-secret.txt',
                         '%00', 'README.md%00'):
                client.expect_error(prefix + name, (400, 404))
            client.expect_error(prefix + 'nested/private.txt', (400, 404))
        for headers in ({'Origin': 'https://proxy.example:9443'},
                        {'Host': 'browser.example:9443'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with client.request('/downloads', headers=headers) as response:
                assert response.status == 200
                assert response.headers['Access-Control-Allow-Origin'] is None
        with (directory / 'later.txt').open('wb') as file:
            file.write(b'new without restart')
        names.add(b'later.txt')
        read_directory(client, names)
        check_download(client, '/downloads/', b'later.txt', directory / 'later.txt')
        (directory / 'later.txt').unlink()
        names.remove(b'later.txt')
        read_directory(client, names)
        client.expect_error('/downloads/later.txt', (404,))
        # Replacing a once-listed ordinary file with a symlink never exposes the
        # target on a later request. Already-open file descriptors are unit-tested.
        (directory / 'README.md').unlink()
        (directory / 'README.md').symlink_to(outside)
        names.remove(b'README.md')
        read_directory(client, names)
        client.expect_error('/downloads/README.md', (404,))
        client.expect_error('/download/README.md', (404,))
        generation = client.json('/api/browser/mode')['generation']
        for token, expected in (('', 403), (client.token, 409)):
            client.expect_error('/api/browser/mode', (expected,),
                                body={'mode': 'native', 'expected_generation': generation},
                                token=token)
        assert client.json('/api/helper/status')['active'] is False

        # Every download surface is guarded by the existing VNC session, rather
        # than the settings login or a separate download-specific password.
        client.json('/api/security', {'scope': 'vnc', 'password': 'download-test-password'}, 'PUT')
        protected = ('/api/downloads', '/downloads/page.html',
                     '/download/page.html', '/api/helper/downloads', '/api/companion/downloads')
        assert client.status()['vnc_authenticated'] is False
        for shell in ('/downloads', '/downloads/'):
            with Client().request(shell) as response:
                assert response.status == 200
                assert '<div id="root"></div>' in response.read().decode()
        for path in protected:
            client.expect_error(path, (401,))
            Client().expect_error(path, (401,))
        client.expect_error('/downloads/page.html', (401,), method='HEAD')
        client.expect_error('/api/login', (401,), body={'scope': 'vnc', 'password': 'wrong'})
        client.json('/api/login', {'scope': 'settings', 'password': ''})
        client.expect_error('/api/downloads', (401,))
        client.json('/api/login', {'scope': 'vnc', 'password': 'download-test-password'})
        assert client.status()['vnc_authenticated'] is True
        read_directory(client, names)
        read_directory(client, names, '/downloads/')
        assert client.json('/api/helper/downloads') == manifest
        for prefix in ('/downloads/', '/download/'):
            check_download(client, prefix, b'page.html', directory / 'page.html')
        client.json('/api/logout', {'scope': 'vnc'})
        for path in protected:
            client.expect_error(path, (401,))

    # The persisted VNC password still protects every route after restart.
    with server(tmp, binary, directory) as client:
        status = client.status()
        assert status['vnc_password_enabled'] and not status['vnc_authenticated']
        for path in protected:
            client.expect_error(path, (401,))
        client.json('/api/login', {'scope': 'vnc', 'password': 'download-test-password'})
        read_directory(client, names)
    return len(builds), tested_files


def exercise_missing_and_root_symlink(tmp, binary):
    # The SPA uses cwd-relative built assets just like a normal deployment.
    (tmp / 'web').symlink_to(ROOT / 'web', target_is_directory=True)
    # Unset the override and run outside the repository, proving the default is
    # relative to the working directory and a missing directory permits startup.
    with server(tmp, binary, cwd=tmp) as client:
        assert read_directory(client, set()) == []
        assert client.json('/api/helper/downloads')['downloads'] == []
        client.expect_error('/downloads/missing', (404,))
        client.expect_error('/download/missing', (404,))
        default = tmp / 'downloads'
        default.mkdir()
        (default / 'new.txt').write_bytes(b'default directory')
        read_directory(client, {b'new.txt'})
        check_download(client, '/downloads/', b'new.txt', default / 'new.txt')
    missing = tmp / 'explicit-missing'
    with server(tmp, binary, missing) as client:
        assert read_directory(client, set()) == []
        assert client.json('/api/helper/downloads')['downloads'] == []
        client.expect_error('/downloads/new.txt', (404,))
    linked = tmp / 'linked-root'
    linked.symlink_to(default, target_is_directory=True)
    with server(tmp, binary, linked) as client:
        client.expect_error('/api/downloads', (500,))
        with client.request('/downloads') as response:
            assert response.status == 200
        client.expect_error('/downloads/new.txt', (404,))
        client.expect_error('/download/new.txt', (404,))
        assert client.json('/api/helper/downloads')['downloads'] == []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend-binary', type=Path,
                        default=ROOT / 'target/release/webauthn-browser')
    binary = parser.parse_args().backend_binary.resolve()
    with tempfile.TemporaryDirectory(prefix='download-directory-test-') as temp:
        tmp = Path(temp)
        files_tmp = tmp / 'files'
        files_tmp.mkdir()
        builds, files = exercise_directory(files_tmp, binary)
        defaults_tmp = tmp / 'defaults'
        defaults_tmp.mkdir()
        exercise_missing_and_root_symlink(defaults_tmp, binary)
    print(f'PASS: {builds} real executable hashes; {files} regular-file downloads; '
          'streamed >64 MiB, empty/HTML/Unicode/raw Unix names, safe headers, '
          'traversal/symlink/FIFO rejection, live directory changes, VNC login/logout/restart, '
          'default/custom/missing/root-symlink directories')


if __name__ == '__main__':
    main()
