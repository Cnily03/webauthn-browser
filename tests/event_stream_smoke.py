"""Real HTTP/SSE smoke without Chromium; requires target/release/webauthn-browser and free 8080."""
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
    with tempfile.TemporaryDirectory(prefix='webauthn-browser-events-') as temp:
        env = dict(os.environ, AUTH_BROWSER_STORE=f'{temp}/store.json',
                   AUTH_BROWSER_PROXY_SOCKET=f'{temp}/run/proxy.sock')
        process = subprocess.Popen([str(ROOT / 'target/release/webauthn-browser')], cwd=ROOT,
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        token = ''
        def send(path, body=None, method=None, csrf=True):
            headers = {'Content-Type': 'application/json'}
            if csrf: headers['X-CSRF-Token'] = token
            return client.open(urllib.request.Request('http://127.0.0.1:8080' + path,
                data=None if body is None else json.dumps(body).encode(),
                headers=headers, method=method), timeout=5)
        def frame(stream):
            lines = []
            while True:
                line = stream.readline()
                if not line: return None
                if line == b'\n': break
                lines.append(line.decode().strip())
            assert 'event: snapshot' in lines
            return json.loads(next(line[6:] for line in lines if line.startswith('data: ')))
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    with send('/api/status') as response: token = json.load(response)['csrf_token']
                    break
                except (OSError, urllib.error.URLError): time.sleep(.05)
            else: raise RuntimeError('backend did not start')
            try:
                send('/api/requests/events', csrf=False)
                raise AssertionError('stream admitted without CSRF')
            except urllib.error.HTTPError as error: assert error.code == 403
            with send('/api/requests/events') as stream:
                assert stream.headers['Content-Type'] == 'text/event-stream'
                first = frame(stream)
                assert first['requests'] == [] and first['connected'] is False and first['resync'] is True
                with send('/api/security', {'scope':'vnc','password':'stream-password'}, 'PUT') as response:
                    assert json.load(response)['ok']
                assert frame(stream) is None, 'password rotation must terminate live stream'
            try:
                send('/api/requests/events')
                raise AssertionError('stream admitted without VNC session')
            except urllib.error.HTTPError as error: assert error.code == 401
            with send('/api/login', {'scope':'vnc','password':'stream-password'}, 'POST') as response:
                assert json.load(response)['ok']
            with send('/api/requests/events') as stream:
                assert frame(stream)['requests'] == []
                with send('/api/logout', {'scope':'vnc'}, 'POST') as response:
                    assert json.load(response)['ok']
                assert frame(stream) is None, 'logout must terminate stream'
            print('PASS: real HTTP SSE headers, initial snapshot, CSRF/VNC gates, password rotation and logout EOF')
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()

if __name__ == '__main__': main()
