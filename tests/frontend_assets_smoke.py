"""Real Rust HTTP checks for the built frontend. Not a browser/rendering test."""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    assert (ROOT / 'web/dist/index.html').is_file(), 'Run pnpm --dir web install --frozen-lockfile && pnpm --dir web run build first'
    with tempfile.TemporaryDirectory(prefix='webauthn-browser-ui-assets-') as temp:
        env = dict(os.environ, AUTH_BROWSER_STORE=f'{temp}/store.json',
                   AUTH_BROWSER_PROXY_SOCKET=f'{temp}/run/proxy.sock')
        process = subprocess.Popen([os.environ.get('AUTH_BROWSER_TEST_BINARY', str(ROOT / 'target/release/webauthn-browser'))], cwd=ROOT,
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        token = ''

        def send(path, body=None, method=None):
            return client.open(urllib.request.Request('http://127.0.0.1:8080' + path,
                data=None if body is None else json.dumps(body).encode(),
                headers={'Content-Type': 'application/json', 'X-CSRF-Token': token}, method=method), timeout=5)

        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    with send('/api/status') as response:
                        token = json.load(response)['csrf_token']
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            else:
                raise RuntimeError('backend did not start')
            nonces = set()
            for route in ('/', '/login', '/profile/default', '/profile/default/', '/settings', '/settings/', '/downloads', '/downloads/', '/index.html'):
                try:
                    response = send(route)
                except urllib.error.HTTPError as error:
                    raise AssertionError(f'SPA route {route} returned {error.code}') from error
                with response:
                    html = response.read().decode()
                    assert '<title>WebAuthn Browser</title>' in html
                    assert response.headers['Content-Type'].startswith('text/html')
                    assert response.headers['X-Frame-Options'] == 'DENY'
                    assert response.headers['X-Content-Type-Options'] == 'nosniff'
                    assert response.headers['Cache-Control'] == 'no-store'
                    assert response.headers['Referrer-Policy'] == 'no-referrer'
                    csp = response.headers['Content-Security-Policy']
                nonce = re.search(r'<meta name="csp-nonce" content="([0-9a-f]{64})"', html).group(1)
                assert nonce not in nonces
                nonces.add(nonce)
                assert '__CSP_NONCE__' not in html
                assert f"style-src-elem 'self' 'nonce-{nonce}'" in csp
                assert "style-src-attr 'unsafe-inline'" in csp
                assert "script-src 'self';" in csp
                assert 'unsafe-eval' not in csp
                assert all(not body.strip() for body in re.findall(r'<script\b[^>]*>(.*?)</script>', html, re.S))
                scripts = re.findall(r'<script[^>]+src="([^"]+)"', html)
                styles = re.findall(r'<link[^>]+href="([^"]+\.css)"', html)
                assert scripts and styles
                for asset in scripts + styles:
                    assert asset.startswith('/assets/'), asset
                    with send(asset) as response:
                        content = response.read()
                        assert content
                        mime = response.headers['Content-Type']
                        assert ('javascript' in mime) if asset.endswith('.js') else ('text/css' in mime)
                assert '<div id="root"></div>' in html
            # Source now shares web/ with dist/: serve only generated output.
            for source in ('/src/App.tsx', '/package.json', '/vite.config.ts'):
                try:
                    send(source)
                    raise AssertionError(f'frontend source exposed: {source}')
                except urllib.error.HTTPError as error:
                    assert error.code == 404, (source, error.code)
            with send('/api/security', {'scope': 'vnc', 'password': 'test-password'}, 'PUT') as response:
                assert json.load(response)['ok']
            try:
                send('/p/default/novnc/core/rfb.js')
                raise AssertionError('noVNC route bypassed browser session')
            except urllib.error.HTTPError as error:
                assert error.code == 401
            print('PASS: built hashed assets served by Rust, nine HTML routes get unique matching CSP nonces, secure headers and authenticated noVNC boundary')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
