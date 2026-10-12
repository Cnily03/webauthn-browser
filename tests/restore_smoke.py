"""Real HTTP keys-only restore with disposable public fixture; no real user data."""
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='webauthn-browser-restore-') as directory:
        env = dict(os.environ, AUTH_BROWSER_STORE=f'{directory}/store.json',
                   AUTH_BROWSER_PROXY_SOCKET=f'{directory}/run/proxy.sock')
        process = subprocess.Popen([str(ROOT / 'target/release/webauthn-browser')], cwd=ROOT,
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        token = ''

        def send(path, body=None, csrf=True):
            headers = {'Content-Type': 'application/json'}
            if csrf:
                headers['X-CSRF-Token'] = token
            request = urllib.request.Request('http://127.0.0.1:8080' + path,
                data=None if body is None else json.dumps(body).encode(), headers=headers)
            try:
                with client.open(request, timeout=5) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode()

        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    _, status = send('/api/status')
                    token = status['csrf_token']
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('backend unavailable')
            fixture = json.loads((ROOT / 'tests/fixtures/legacy-cdp-store.json').read_text())
            raw = json.dumps({'version': 1, 'keys': fixture['keys']})
            assert send('/api/restore/preview', {'backup': raw}, csrf=False)[0] == 403
            assert send('/api/restore/preview', {'backup': '{'})[0] == 400
            code, preview = send('/api/restore/preview', {'backup': raw})
            assert code == 200 and preview['key_count'] == 1 and preview['credential_count'] == 1
            assert not any(secret in json.dumps(preview) for secret in ['privateKey', 'pin_hash'])
            ticket = preview['token']
            confirm = {'token': ticket, 'backup': raw}
            assert send('/api/restore/confirm', confirm)[0] == 409
            code, before = send('/api/restore/backup', {'token': ticket})
            assert code == 200 and before['keys'] == []
            assert send('/api/restore/confirm', confirm)[0] == 200
            assert send('/api/restore/confirm', confirm)[0] == 409
            _, keys = send('/api/keys')
            assert len(keys['keys']) == 1 and len(keys['keys'][0]['credentials']) == 1
            stored = json.loads(Path(directory, 'store.json').read_text())
            assert stored['keys'][0]['credentials'][0]['privateKey'] == fixture['keys'][0]['credentials'][0]['privateKey']
            assert stored['vnc_password_hash'] is None and stored['settings_password_hash'] is None
            print('PASS: real HTTP restore validation, CSRF, sanitized preview, mandatory safety backup, atomic import and one-shot token')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    main()
