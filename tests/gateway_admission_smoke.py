"""Real loopback HTTP/WS gateway admission and auth regression; no browser/device.

Synthetic credentials only. Requires a release backend and free port 8080.
Public/proxy headers are exercised over loopback, without DNS or LAN traffic.
"""
import argparse
import base64
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PROXY = {
    'Host': 'gateway.internal:8080',
    'Origin': 'https://browser.example:9443',
    'Sec-Fetch-Site': 'cross-site',
    'Forwarded': 'for=192.0.2.20;host=browser.example:9443;proto=https',
    'X-Forwarded-Host': 'browser.example:9443',
    'X-Forwarded-Proto': 'https',
}
CASES = [
    {'Host': '192.168.1.20:9080', 'Origin': 'http://192.168.1.20:9080'},
    {'Host': '[fd00::20]:9080', 'Origin': 'http://[fd00::20]:9080'},
    {'Host': 'browser.example:9443', 'Origin': 'https://browser.example:9443'},
    PROXY,
    {'Host': 'gateway:8080', 'Origin': 'https://public.example', 'Sec-Fetch-Site': 'same-origin'},
    {'Host': 'browser.example:9443', 'Origin': 'null', 'Sec-Fetch-Site': 'cross-site'},
    {'Host': 'browser.example:9443'},
]


class Client:
    def __init__(self):
        self.cookies = {}
        self.token = ''

    def send(self, path, method='GET', body=None, headers=None, authenticated=True):
        outgoing = dict(PROXY if headers is None else headers)
        if body is not None:
            outgoing.setdefault('Content-Type', 'application/json')
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
        if authenticated:
            outgoing.setdefault('Cookie', '; '.join(f'{k}={v}' for k, v in self.cookies.items()))
            outgoing.setdefault('X-CSRF-Token', self.token)
        connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=5)
        try:
            connection.request(method, path, body=body, headers=outgoing)
            response = connection.getresponse()
            status = response.status
            result_headers = dict((k.lower(), v) for k, v in response.getheaders())
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    cookie = SimpleCookie(value)
                    self.cookies.update((key, morsel.value) for key, morsel in cookie.items())
            content = b'' if status == 101 else response.read()
            assert 'access-control-allow-origin' not in result_headers
            assert 'access-control-allow-credentials' not in result_headers
            return status, result_headers, content
        finally:
            connection.close()

    def expect(self, status, path, **kwargs):
        actual, headers, content = self.send(path, **kwargs)
        assert actual == status, (path, actual, content)
        return headers, content

    def websocket(self, path, headers, authenticated=True, expected=101):
        nonce = base64.b64encode(os.urandom(16)).decode()
        headers = dict(headers, Upgrade='websocket', Connection='Upgrade')
        headers['Sec-WebSocket-Version'] = '13'
        headers['Sec-WebSocket-Key'] = nonce
        response, _ = self.expect(expected, path, headers=headers, authenticated=authenticated)
        if expected == 101:
            accept = base64.b64encode(hashlib.sha1((nonce + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            assert response['sec-websocket-accept'] == accept


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend-binary', type=Path, default=ROOT / 'target/release/webauthn-browser')
    binary = parser.parse_args().backend_binary.resolve()
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1', 8080)) == 0:
            raise RuntimeError('Port 8080 is occupied; stop the other backend/smoke first')
    with tempfile.TemporaryDirectory(prefix='gateway-admission-') as temp:
        env = dict(os.environ, AUTH_BROWSER_STORE=f'{temp}/store.json',
                   AUTH_BROWSER_PROXY_SOCKET=f'{temp}/proxy.sock',
                   AUTH_BROWSER_CLIPBOARD_SOCKET=f'{temp}/absent-clipboard.sock')
        env.pop('AUTH_BROWSER_ALLOWED_HOSTS', None)
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen([str(binary)], cwd=ROOT, env=env,
                                       stdout=subprocess.DEVNULL, stderr=log)
            try:
                client = Client()
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read().decode(errors='replace'))
                    try:
                        _, content = client.expect(200, '/api/status')
                        client.token = json.loads(content)['csrf_token']
                        break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('Backend did not start')
                for headers in CASES:
                    client.expect(200, '/api/status', headers=headers)
                    client.expect(200, '/healthz', headers=headers)
                    client.expect(200, '/api/logout', method='POST', body={'scope': 'settings'}, headers=headers)
                    for path in ('/ws', '/api/clipboard/ws'):
                        client.websocket(path, headers)
                client.expect(403, '/api/logout', method='POST', body={'scope': 'settings'}, authenticated=False)
                client.expect(403, '/api/logout', method='POST', body={'scope': 'settings'}, headers=dict(PROXY, **{'X-CSRF-Token': 'wrong'}))
                client.expect(415, '/api/logout', method='POST', body=b'{}', headers=dict(PROXY, **{'Content-Type': 'text/plain'}))
                client.expect(400, '/api/logout', method='POST', body=b'{')
                for scope in ('vnc', 'settings'):
                    client.expect(200, '/api/security', method='PUT', body={'scope': scope, 'password': f'synthetic-{scope}-password'})
                for path in ('/api/keys', '/api/requests', '/api/downloads'):
                    client.expect(401, path)
                for path in ('/ws', '/api/clipboard/ws'):
                    client.websocket(path, PROXY, expected=401)
                client.expect(401, '/api/login', method='POST', body={'scope': 'settings', 'password': 'incorrect'})
                client.expect(200, '/api/login', method='POST', body={'scope': 'settings', 'password': 'synthetic-settings-password'})
                client.expect(200, '/api/keys')
                client.expect(401, '/api/requests')
                client.expect(200, '/api/login', method='POST', body={'scope': 'vnc', 'password': 'synthetic-vnc-password'})
                client.expect(200, '/api/requests')
                for headers in CASES:
                    for path in ('/ws', '/api/clipboard/ws'):
                        client.websocket(path, headers)
                        client.websocket(path, headers, authenticated=False, expected=401)
                client.expect(200, '/api/logout', method='POST', body={'scope': 'vnc'})
                client.expect(401, '/api/requests')
                client.expect(200, '/api/keys')
                print('PASS: real HTTP/WS LAN/domain/port/reverse-proxy admission without Host config; separate passwords/session revocation, CSRF/JSON, and no added CORS grants')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    main()
