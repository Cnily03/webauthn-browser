"""Real HTTP profile authorization and persistence checks using disposable data.

No browser, VNC, helper, Bluetooth or HID device is opened. Runtime isolation and
engine ownership have separate subprocess/protocol tests; this verifies the
actual gateway routing, cookies, persisted token digests and shared key store.
"""
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import quote_from_bytes

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8080'
MONTH = 30 * 24 * 60 * 60


class Client:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookies))
        self.csrf = ''

    def send(self, path, method='GET', body=None, expected=200, headers=None):
        outgoing = {'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf}
        outgoing.update(headers or {})
        request = urllib.request.Request(BASE + path, method=method, headers=outgoing,
            data=None if body is None else json.dumps(body).encode())
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            assert response.status == expected, (path, response.status, raw[:300])
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw.decode()
            if isinstance(value, dict) and 'csrf_token' in value:
                self.csrf = value['csrf_token']
            return value, response.headers


def main():
    executable = Path(os.environ.get('AUTH_BROWSER_TEST_BINARY', ROOT / 'target/release/webauthn-browser'))
    assert executable.is_file(), 'Build the current gateway before running this smoke.'
    with tempfile.TemporaryDirectory(prefix='webauthn-profile-http-') as temporary:
        directory = Path(temporary)
        store = directory / 'store.json'
        downloads = directory / 'downloads'
        downloads.mkdir()
        file_names = [b'plain.txt', b'spaced name.txt', '中文.txt'.encode(), b'literal%25.txt', b'raw-\xff.txt']
        for index, name in enumerate(file_names):
            with open(os.fsencode(downloads) + b'/' + name, 'wb') as output:
                output.write(f'profile-download-{index}'.encode())
        # A populated legacy store makes accidental key loss or profile reset visible.
        store.write_text(json.dumps({'keys': [], 'vnc_password_hash': None, 'settings_password_hash': None}))
        environment = dict(os.environ, AUTH_BROWSER_STORE=str(store),
            AUTH_BROWSER_PROXY_SOCKET=str(directory / 'proxy.sock'), AUTH_BROWSER_DOWNLOADS_DIR=str(downloads),
            AUTH_BROWSER_PROFILE_CONTROL_PATH=str(directory / 'missing-manager.sock'))
        environment.pop('AUTH_BROWSER_PROFILE_CONTROL_TOKEN', None)
        process = None

        def start():
            nonlocal process
            process = subprocess.Popen([str(executable)], cwd=ROOT, env=environment,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            probe = Client()
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    probe.send('/healthz')
                    return
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            raise RuntimeError('Gateway did not start')

        def stop():
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            if process and process.stderr:
                process.stderr.close()

        try:
            start()
            admin, alice, bob = Client(), Client(), Client()
            for client in (admin, alice, bob):
                client.send('/api/status')
            admin.send('/api/keys', 'POST', {'name': 'shared test authenticator', 'attachment': 'platform', 'enabled': True})
            shared_keys = admin.send('/api/keys')[0]['keys']
            assert len(shared_keys) == 1
            listing, _ = admin.send('/api/profiles')
            default = next(p for p in listing['profiles'] if p['id'] == 'default')
            assert default['name'] == 'default' and default['idle_timeout_seconds'] == 180
            assert not listing['multi_profile'] and default['effective_enabled']
            for method, body in [('PATCH', {'name': 'renamed'}), ('DELETE', {})]:
                admin.send('/api/profiles/default', method, body, expected=400)
            admin.send('/api/profiles/config', 'PUT', {'multi_profile': True})
            for name in ('.github', 'Work', 'personal'):
                admin.send('/api/profiles', 'POST', {'name': name, 'enabled': True,
                    'password': 'private-value' if name == 'Work' else None, 'idle_timeout_seconds': 180})
            profiles, _ = admin.send('/api/profiles')
            work = next(p for p in profiles['profiles'] if p['name'] == 'work')
            personal = next(p for p in profiles['profiles'] if p['name'] == 'personal')
            assert work['id'] != personal['id'] and work['password_enabled']
            admin.send('/api/profiles', 'POST', {'name': 'WORK'}, expected=409)
            for name in ('.', '..', '../escape', 'name.git', 'name.WIKI', 'not valid'):
                admin.send('/api/profiles', 'POST', {'name': name}, expected=400)
            for idle in (0, 86401, -1):
                admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'idle_timeout_seconds': idle}, expected=400)
            admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'password': ''}, expected=400)
            work_path = f"/p/{work['name']}"
            personal_path = f"/p/{personal['name']}"
            discovery, _ = alice.send('/api/profiles/public')
            assert all('id' not in profile for profile in discovery['profiles'])
            assert work['id'] not in json.dumps(discovery) and personal['id'] not in json.dumps(discovery)
            alice.send(f"/p/{work['id']}/api/status", expected=404)
            status, _ = alice.send(work_path + '/api/status')
            assert 'id' not in status['profile'] and status['profile']['name'] == 'work'
            assert work['id'] not in json.dumps(status)
            assert not status['vnc_authenticated']
            alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'wrong'}, expected=401)
            _, headers = alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'private-value'})
            cookie_header = headers.get('Set-Cookie', '')
            assert 'HttpOnly' in cookie_header and 'SameSite=Strict' in cookie_header
            assert f'Path={work_path}/' in cookie_header and f'Max-Age={MONTH}' in cookie_header
            assert work['id'] not in cookie_header and work['id'].replace('-', '') not in cookie_header
            access_cookie = next(c for c in alice.cookies if c.name == 'ab_profile_access')
            raw_access = access_cookie.value
            persisted = json.loads(store.read_text())
            assert raw_access not in store.read_text() and 'private-value' not in store.read_text()
            assert any(t['token_hash'] == hashlib.sha256(raw_access.encode()).hexdigest()
                       and t['profile_id'] == work['id'] for t in persisted['profile_access_tokens'])
            assert alice.send(work_path + '/api/status')[0]['vnc_authenticated']
            files = Client().send('/api/downloads')[0]['files']
            assert len(files) == len(file_names)
            assert alice.send(work_path + '/api/downloads')[0]['files'] == files
            bob.send(work_path + '/api/downloads', expected=401)
            assert all(file['url'].startswith('/downloads/') for file in files)
            assert work['id'] not in json.dumps(files)
            for index, name in enumerate(file_names):
                url = '/downloads/' + quote_from_bytes(name, safe='')
                assert alice.send(url)[0] == f'profile-download-{index}'
                assert bob.send(url)[0] == f'profile-download-{index}'
                assert Client().send(url)[0] == f'profile-download-{index}'
            for encoded in ('..%2Fstore.json', '%2Fstore.json', '%00'):
                Client().send('/downloads/' + encoded, expected=404)
            assert not bob.send(work_path + '/api/status')[0]['vnc_authenticated']
            assert bob.send(personal_path + '/api/status')[0]['vnc_authenticated']
            assert alice.send('/api/keys')[0]['keys'] == shared_keys
            assert bob.send('/api/keys')[0]['keys'] == shared_keys
            # A valid token belonging to another profile cannot authorize this one.
            bob.send(personal_path + '/api/login', 'POST', {'scope': 'vnc', 'password': ''})
            other_cookie = next(c for c in bob.cookies if c.name == 'ab_profile_access')
            forged = { 'Cookie': f'{access_cookie.name}={other_cookie.value}' }
            assert not bob.send(work_path + '/api/status', headers=forged)[0]['vnc_authenticated']

            # Persisted last-use state slides across a real gateway restart.
            stop()
            persisted = json.loads(store.read_text())
            for token in persisted['profile_access_tokens']:
                if token['profile_id'] == work['id']:
                    token['last_used_at'] = int(time.time()) - MONTH + 20
            store.write_text(json.dumps(persisted))
            start()
            status, headers = alice.send(work_path + '/api/status')
            assert status['vnc_authenticated']
            renewed = next(t for t in json.loads(store.read_text())['profile_access_tokens'] if t['profile_id'] == work['id'])
            assert renewed['last_used_at'] > int(time.time()) - 20
            stop()
            persisted = json.loads(store.read_text())
            for token in persisted['profile_access_tokens']:
                if token['profile_id'] in (work['id'], personal['id']):
                    token['last_used_at'] = int(time.time()) - MONTH - 1
            store.write_text(json.dumps(persisted))
            start()
            expired_status, expired_headers = alice.send(work_path + '/api/status')
            assert not expired_status['vnc_authenticated']
            assert any('Max-Age=0' in value for value in expired_headers.get_all('Set-Cookie', []))
            personal_expired_at = next(t['last_used_at'] for t in persisted['profile_access_tokens']
                                       if t['profile_id'] == personal['id'])
            public_status, public_headers = bob.send(personal_path + '/api/status')
            assert public_status['vnc_authenticated']
            assert any('Max-Age=0' in value for value in public_headers.get_all('Set-Cookie', []))
            assert next(t['last_used_at'] for t in json.loads(store.read_text())['profile_access_tokens']
                        if t['profile_id'] == personal['id']) == personal_expired_at
            alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'private-value'})
            admin.send('/api/status')
            before_rename = next(p for p in json.loads(store.read_text())['profiles'] if p['id'] == work['id'])
            admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'name': 'renamed'})
            alice.send(work_path + '/api/status', expected=404)
            after_rename = next(p for p in json.loads(store.read_text())['profiles'] if p['id'] == work['id'])
            assert after_rename['auth_revision'] == before_rename['auth_revision'] + 1
            replacement, _ = admin.send('/api/profiles', 'POST', {'name': 'work', 'password': 'private-value'})
            assert replacement['id'] != work['id']
            assert not alice.send(work_path + '/api/status')[0]['vnc_authenticated']
            work_path = '/p/renamed'
            assert not alice.send(work_path + '/api/status')[0]['vnc_authenticated']
            assert not alice.send(work_path + '/api/status', headers={'Cookie': f'ab_profile_access={raw_access}'})[0]['vnc_authenticated']
            alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'private-value'})
            admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'password': 'changed-value'})
            assert not alice.send(work_path + '/api/status')[0]['vnc_authenticated']
            alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'changed-value'})
            alice.send(work_path + '/api/logout', 'POST', {'scope': 'vnc'})
            assert not alice.send(work_path + '/api/status')[0]['vnc_authenticated']

            # Configuration changes retain both remembered profile access and admin login.
            alice.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'changed-value'})
            bob.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'changed-value'})
            cookie_name = 'ab_profile_access'
            alice_access = next(c.value for c in alice.cookies if c.name == cookie_name and c.path == work_path + '/')
            alice_hash = hashlib.sha256(alice_access.encode()).hexdigest()
            revision = next(p['auth_revision'] for p in json.loads(store.read_text())['profiles'] if p['id'] == work['id'])
            admin.send('/api/security', 'PUT', {'scope': 'settings', 'password': 'admin-value'})
            admin.send('/api/login', 'POST', {'scope': 'settings', 'password': 'admin-value'})
            admin_access = next(c.value for c in admin.cookies if c.name == 'ab_settings')
            admin.send('/api/profiles/default', 'PATCH', {'enabled': False})
            for _ in range(3):
                admin.send('/api/profiles/config', 'PUT', {'multi_profile': False})
                listing, _ = admin.send('/api/profiles')
                assert not next(p for p in listing['profiles'] if p['id'] == 'default')['enabled']
                assert [p['id'] for p in listing['profiles'] if p['effective_enabled']] == ['default']
                before = next(t['last_used_at'] for t in json.loads(store.read_text())['profile_access_tokens']
                              if t['token_hash'] == alice_hash)
                status, headers = alice.send(work_path + '/api/status')
                assert not status['vnc_authenticated']
                assert not any(value.startswith(cookie_name + '=') for value in headers.get_all('Set-Cookie', []))
                alice.send(work_path + '/api/downloads', expected=401)
                alice.send(work_path + '/api/helper/downloads', expected=401)
                assert Client().send('/api/downloads')[0]['files'] == files
                assert Client().send('/downloads/plain.txt')[0] == 'profile-download-0'
                assert next(c.value for c in alice.cookies if c.name == cookie_name and c.path == work_path + '/') == alice_access
                after = json.loads(store.read_text())
                assert next(t['last_used_at'] for t in after['profile_access_tokens'] if t['token_hash'] == alice_hash) == before
                assert next(p['auth_revision'] for p in after['profiles'] if p['id'] == work['id']) == revision
                admin.send('/api/profiles/config', 'PUT', {'multi_profile': True})
                assert alice.send(work_path + '/api/status')[0]['vnc_authenticated']
                assert admin.send('/api/status')[0]['settings_authenticated']
                assert next(c.value for c in admin.cookies if c.name == 'ab_settings') == admin_access
            listing, _ = admin.send('/api/profiles')
            assert not next(p for p in listing['profiles'] if p['id'] == 'default')['effective_enabled']
            assert next(p for p in listing['profiles'] if p['id'] == work['id'])['effective_enabled']

            # Forget works while unavailable, and affects only this browser's cookie.
            admin.send('/api/profiles/config', 'PUT', {'multi_profile': False})
            alice.send(work_path + '/api/logout', 'POST', {'scope': 'vnc'}, expected=403,
                       headers={'X-CSRF-Token': ''})
            alice.send(work_path + '/api/logout', 'POST', {'scope': 'vnc'})
            assert all(c.name != cookie_name or c.path != work_path + '/' for c in alice.cookies)
            assert not any(t['token_hash'] == alice_hash for t in json.loads(store.read_text())['profile_access_tokens'])
            admin.send('/api/profiles/config', 'PUT', {'multi_profile': True})
            assert bob.send(work_path + '/api/status')[0]['vnc_authenticated']
            assert not alice.send(work_path + '/api/status')[0]['vnc_authenticated']

            # Explicit profile disable remains a credential revocation.
            admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'enabled': False})
            admin.send(f"/api/profiles/{work['id']}", 'PATCH', {'enabled': True})
            assert not bob.send(work_path + '/api/status')[0]['vnc_authenticated']
            bob.send(work_path + '/api/login', 'POST', {'scope': 'vnc', 'password': 'changed-value'})
            # This smoke deliberately has no runtime manager. Configuration and
            # access are revoked, but physical deletion must remain unconfirmed.
            admin.send(f"/api/profiles/{work['id']}", 'DELETE', {}, expected=503)
            assert work['id'] in json.loads(store.read_text())['pending_profile_deletion']
            alice.send(work_path + '/api/status', expected=404)
            bob.send(work_path + '/api/logout', 'POST', {'scope': 'vnc'}, expected=403,
                     headers={'X-CSRF-Token': ''})
            bob.send(work_path + '/api/logout', 'POST', {'scope': 'settings'}, expected=400)
            _, headers = bob.send(work_path + '/api/logout', 'POST', {'scope': 'vnc'})
            assert any(value.startswith(cookie_name + '=') and 'Max-Age=0' in value
                       for value in headers.get_all('Set-Cookie', []))
            assert all(c.name != cookie_name or c.path != work_path + '/' for c in bob.cookies)
            admin.send('/api/profiles', 'POST', {'name': 'renamed'})
            listing, _ = admin.send('/api/profiles')
            assert next(p for p in listing['profiles'] if p['name'] == 'renamed')['id'] != work['id']
            assert admin.send('/api/keys')[0]['keys'] == shared_keys
            print('PASS: name-only public identity, private immutable UUID storage, rename/reuse revocation, HTTP CRUD, cookie isolation, sliding access, mode-preserved login, scoped forget, public global raw downloads and shared keys')
        finally:
            stop()


if __name__ == '__main__':
    main()
