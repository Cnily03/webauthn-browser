#!/usr/bin/env python3
"""Opt-in real Chromium → WebAuthenticationProxy → Rust signer integration.

On a host permitting localhost/Unix sockets, install tests/requirements.txt, build
Rust, then run (as a normal unprivileged user, with DISPLAY or Chromium headless):
  python3 tests/live_webauthn.py --backend-binary target/debug/webauthn-browser \
      --chromium /usr/bin/chromium --headless
This launches an isolated Chromium profile, extension and native-host manifest;
never uses real accounts. Chromium's sandbox is retained. No WebAuthn CDP domain,
virtual authenticator or JavaScript request shim is used. CDP only drives the RP.
Alternatively omit --chromium and connect --cdp to a separately configured test
browser with extension/manifest and the same AUTH_BROWSER_PROXY_SOCKET path.
Pass --proxy-socket explicitly in that mode.
Validation here: offline verifier/launcher tests and backend persistence pass;
live Chromium was blocked by socket() EPERM in process_singleton_posix.cc.
Do not bypass that sandbox restriction; repeat on a permitted test host. Port 8080 must be free for a managed
backend. External test backends must be passwordless and contain no other keys.
"""
import argparse
import asyncio
import base64
import hashlib
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.asyncio.client import connect

ROOT = Path(__file__).resolve().parents[1]
PIN = 'integration-only-password'


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def unb64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


class Api:
    def __init__(self, origin):
        self.origin = origin.rstrip('/')
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}))

    def request(self, path, body=None, method='GET'):
        headers = {'Origin': self.origin}
        if self.token:
            headers['X-CSRF-Token'] = self.token
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.origin + path,
            None if body is None else json.dumps(body).encode(), headers, method=method)
        with self.opener.open(request, timeout=20) as response:
            return json.load(response)

    def refresh(self):
        self.token = self.request('/api/status')['csrf_token']

    def decision(self, request, body, expected=200):
        try:
            result = self.request('/api/requests/' + request['id'] + '/decision', body, 'POST')
        except urllib.error.HTTPError as error:
            assert error.code == expected, (error.code, error.read())
            return
        assert expected == 200, (expected, result)
        return result


class Rpc:
    def __init__(self, ws):
        self.ws, self.ident = ws, 0

    async def call(self, method, params=None):
        self.ident += 1
        ident = self.ident
        await self.ws.send(json.dumps({'id': ident, 'method': method, 'params': params or {}}))
        async with asyncio.timeout(30):
            while True:
                result = json.loads(await self.ws.recv())
                if result.get('id') == ident:
                    if 'error' in result:
                        raise RuntimeError(result['error'])
                    return result.get('result', {})

    async def evaluate(self, expression):
        result = await self.call('Runtime.evaluate', {
            'expression': expression, 'awaitPromise': True, 'returnByValue': True})
        if 'exceptionDetails' in result:
            raise RuntimeError(result['exceptionDetails'])
        return result['result'].get('value')


class Rp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><title>Isolated local WebAuthn RP</title><p>Integration test</p>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


JS_HELPERS = r"""const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)); const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');"""


async def begin(page, kind, credential=None, uv='required', attachment=None):
    challenge = b64(os.urandom(32))
    options = {'challenge': challenge, 'timeout': 60000}
    if kind == 'create':
        options.update(rp={'id': 'localhost', 'name': 'Isolated test'},
            user={'id': b64(os.urandom(16)), 'name': uuid.uuid4().hex, 'displayName': 'Test account'},
            pubKeyCredParams=[{'type': 'public-key', 'alg': -7}], attestation='none',
            authenticatorSelection={'residentKey': 'required', 'userVerification': uv})
        if attachment:
            options['authenticatorSelection']['authenticatorAttachment'] = attachment
    else:
        options.update(rpId='localhost', userVerification=uv)
        if credential:
            options['allowCredentials'] = [{'type': 'public-key', 'id': credential['id']}]
    # Start, but do not await the browser ceremony. Polling allows cancellation
    # through the same CDP connection without concurrent websocket receivers.
    expression = f"""(()=>{{{JS_HELPERS}
const p={json.dumps(options)}; p.challenge=decode(p.challenge);
if(p.user)p.user.id=decode(p.user.id);
if(p.allowCredentials)p.allowCredentials.forEach(c=>c.id=decode(c.id));
window.testResult=null; window.testAbort=new AbortController();
navigator.credentials.{kind}({{publicKey:p,signal:window.testAbort.signal}}).then(c=>{{
window.testResult={{id:encode(c.rawId),client:encode(c.response.clientDataJSON),
authData:encode(c.response.authenticatorData||c.response.getAuthenticatorData()),
publicKey:c.response.getPublicKey?encode(c.response.getPublicKey()):null,
signature:c.response.signature?encode(c.response.signature):null,
userHandle:c.response.userHandle?encode(c.response.userHandle):null}};
}},e=>{{window.testResult={{error:e.name,message:e.message}};}});return true;}})()"""
    assert await page.evaluate(expression)
    return challenge


async def pending(api, origin, kind, uv):
    async with asyncio.timeout(15):
        while True:
            state = api.request('/api/requests')
            matches = [r for r in state['requests'] if r['origin'] == origin]
            if matches:
                assert len(matches) == 1, matches
                request = matches[0]
                assert request['kind'] == kind and request['rp_id'] == 'localhost' and request['uv'] == uv
                return request
            await asyncio.sleep(.1)


async def result(page, error=None):
    async with asyncio.timeout(20):
        while True:
            value = await page.evaluate('window.testResult')
            if value is not None:
                if error:
                    assert value.get('error') in error, value
                else:
                    assert 'error' not in value, value
                return value
            await asyncio.sleep(.1)


def approve(api, request, key, credential=None, password=PIN):
    candidate = next(c for c in request['candidates'] if c['key_id'] == key and
        (credential is None or unb64(c['credential_id']) == unb64(credential['id'])))
    assert isinstance(candidate['pin_required'], bool) and isinstance(candidate['pin_setup'], bool)
    result = api.decision(request, {'action': 'select', 'key_id': key, 'credential_id': candidate['credential_id']})
    assert result['stage'] == ('setup_password' if candidate['pin_setup'] else 'verify_password' if candidate['pin_required'] else 'touch')
    if candidate['pin_setup']:
        assert api.decision(request, {'action': 'setup_password', 'password': password, 'password_confirmation': password})['stage'] == 'verify_password'
    if candidate['pin_required']:
        assert api.decision(request, {'action': 'verify_password', 'password': password})['stage'] == 'touch'
    body = {'action': 'touch'}
    assert api.decision(request, body)['stage'] == 'completed'
    return body


def verify(value, challenge, origin, kind, uv, credential=None):
    client_bytes = unb64(value['client'])
    client = json.loads(client_bytes)
    assert client['type'] == 'webauthn.' + kind and client['challenge'] == challenge
    assert client['origin'] == origin and client.get('crossOrigin', False) is False
    auth = unb64(value['authData'])
    assert auth[:32] == hashlib.sha256(b'localhost').digest()
    assert auth[32] & 1, 'UP missing'
    assert bool(auth[32] & 4) == (uv != 'discouraged'), 'UV flag mismatch'
    if credential:
        assert value['id'] == credential['id'], 'Wrong account signed'
        public = serialization.load_der_public_key(unb64(credential['publicKey']))
        public.verify(unb64(value['signature']), auth + hashlib.sha256(client_bytes).digest(), ec.ECDSA(hashes.SHA256()))
    return int.from_bytes(auth[33:37], 'big')


async def ceremony(page, api, origin, kind, key, credential=None, uv='required', discover=False):
    challenge = await begin(page, kind, None if discover else credential, uv)
    request = await pending(api, origin, kind, uv)
    approve(api, request, key, credential, None if uv == 'discouraged' else PIN)
    value = await result(page)
    count = verify(value, challenge, origin, kind, uv, credential)
    api.decision(request, {'action': 'deny'}, expected=409)
    return value, count, request


def stop(process):
    if process:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def start_backend(args, directory, socket):
    process = subprocess.Popen([str(Path(args.backend_binary).resolve())], cwd=ROOT,
        env=dict(os.environ, AUTH_BROWSER_STORE=str(directory / 'state.json'), AUTH_BROWSER_PROXY_SOCKET=str(socket)))
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('Backend exited before readiness; see stderr')
            try:
                Api(args.base).refresh()
                return process
            except OSError:
                time.sleep(.1)
        raise RuntimeError('Backend readiness timed out')
    except BaseException:
        stop(process)
        raise


def start_chromium(args, directory, socket):
    if not args.backend_binary:
        raise ValueError('--chromium requires --backend-binary for the native host')
    home = directory / 'home'
    config = home / '.config'
    manifest = json.loads((ROOT / 'runtime/com.auth_browser.proxy.json').read_text())
    wrapper = directory / 'native-host'
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(Path(args.backend_binary).resolve())) + ' --native-proxy "$@"\n')
    wrapper.chmod(0o700)
    manifest['path'] = str(wrapper)
    for product in ('chromium', 'google-chrome', 'google-chrome-for-testing'):
        target = config / product / 'NativeMessagingHosts'
        target.mkdir(parents=True)
        (target / 'com.auth_browser.proxy.json').write_text(json.dumps(manifest))
    flags = [args.chromium, '--user-data-dir=' + str(directory / 'profile'),
        '--load-extension=' + str(ROOT / 'extension'), '--disable-extensions-except=' + str(ROOT / 'extension'),
        '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222', '--no-first-run', '--no-default-browser-check']
    if args.headless:
        flags.append('--headless=new')
    return subprocess.Popen(flags + ['about:blank'], env=dict(os.environ, HOME=str(home),
        XDG_CONFIG_HOME=str(config), AUTH_BROWSER_PROXY_SOCKET=str(socket)))


async def main(args):
    backend = chromium = server = None
    with tempfile.TemporaryDirectory(prefix='webauthn-browser-e2e-') as temp:
        directory = Path(temp)
        socket = Path(args.proxy_socket) if args.proxy_socket else directory / 'run' / 'proxy.sock'
        try:
            if args.backend_binary:
                backend = start_backend(args, directory, socket)
            if args.chromium:
                chromium = start_chromium(args, directory, socket)
            api = Api(args.base)
            api.refresh()
            assert not api.request('/api/keys')['keys'], 'Use an empty isolated backend'
            async with asyncio.timeout(30):
                while not api.request('/api/requests')['connected']:
                    if chromium and chromium.poll() is not None:
                        raise RuntimeError('Chromium exited; use a sandbox-capable unprivileged host')
                    await asyncio.sleep(.2)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Rp)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            origin = f'http://localhost:{server.server_port}'
            with urllib.request.urlopen(args.cdp + '/json/version') as response:
                browser_url = json.load(response)['webSocketDebuggerUrl']
            async with connect(browser_url, max_size=2**24) as ws:
                browser = Rpc(ws)
                target = (await browser.call('Target.createTarget', {'url': origin}))['targetId']
                with urllib.request.urlopen(args.cdp + '/json/list') as response:
                    page_url = next(t['webSocketDebuggerUrl'] for t in json.load(response) if t['id'] == target)
                keys = []
                try:
                    for attachment in ('platform', 'cross-platform'):
                        key = api.request('/api/keys', {'name': 'Isolated ' + attachment, 'attachment': attachment}, 'POST')
                        keys.append(key.get('id') or key['key']['id'])
                    async with connect(page_url, max_size=2**24) as pws:
                        page = Rpc(pws)
                        while await page.evaluate('document.readyState') != 'complete':
                            await asyncio.sleep(.1)
                        credentials = []
                        # Two accounts on one key, another on the second key.
                        for index, key in enumerate((keys[0], keys[0], keys[1])):
                            credential, _, request = await ceremony(page, api, origin, 'create', key)
                            assert {c['key_id'] for c in request['candidates']} == set(keys)
                            selected = next(c for c in request['candidates'] if c['key_id'] == key)
                            assert selected['pin_setup'] == (index != 1)
                            assert selected['pin_required'] is True
                            credentials.append((key, credential))
                        for key, credential in credentials:
                            _, first, _ = await ceremony(page, api, origin, 'get', key, credential)
                            _, second, request = await ceremony(page, api, origin, 'get', key, credential, discover=True)
                            assert len(request['candidates']) == 3 and second > first
                        key, credential = credentials[0]
                        _, previous, _ = await ceremony(page, api, origin, 'get', key, credential, uv='discouraged')
                        # Wrong PIN consumes only that request; no signature or counter increment.
                        await begin(page, 'get', credential)
                        request = await pending(api, origin, 'get', 'required')
                        candidate = request['candidates'][0]
                        api.decision(request, {'action': 'select', 'key_id': key, 'credential_id': candidate['credential_id']})
                        body = {'action': 'verify_password', 'password': 'wrong-password'}
                        api.decision(request, body, expected=400)
                        await result(page, ('NotAllowedError',))
                        api.decision(request, body, expected=409)
                        _, after, _ = await ceremony(page, api, origin, 'get', key, credential)
                        assert after == previous + 1
                        # Explicit denial and browser AbortController cancellation both go stale.
                        for cancel in (False, True):
                            await begin(page, 'get', credential)
                            request = await pending(api, origin, 'get', 'required')
                            if cancel:
                                await page.evaluate('window.testAbort.abort(); true')
                                async with asyncio.timeout(10):
                                    while any(r['id'] == request['id'] for r in api.request('/api/requests')['requests']):
                                        await asyncio.sleep(.1)
                            else:
                                api.decision(request, {'action': 'deny'})
                            await result(page, ('AbortError', 'NotAllowedError'))
                            api.decision(request, body, expected=409)
                        await page.evaluate('window.beforeReload = true')
                        await page.call('Page.reload')
                        async with asyncio.timeout(15):
                            while True:
                                try:
                                    if await page.evaluate('document.readyState === \"complete\" && window.beforeReload === undefined'):
                                        break
                                except RuntimeError:
                                    pass  # Reload destroys the prior execution context.
                                await asyncio.sleep(.1)
                        _, reloaded, _ = await ceremony(page, api, origin, 'get', key, credential)
                        assert reloaded == after + 1
                        if backend:
                            stop(backend)
                            backend = start_backend(args, directory, socket)
                            api = Api(args.base)
                            api.refresh()
                            async with asyncio.timeout(40):
                                while not api.request('/api/requests')['connected']:
                                    await asyncio.sleep(.2)
                            _, restarted, _ = await ceremony(page, api, origin, 'get', key, credential)
                            assert restarted == reloaded + 1
                            assert (directory / 'state.json').stat().st_mode & 0o777 == 0o600
                            print('PASS: restart preserves private key, key PIN, accounts and counter')
                        print('PASS: real browser create/get, ES256, origin/challenge/RP, UP/UV, key/account choice, PIN rejection, deny/cancel/stale decisions, reload')
                finally:
                    for key in keys:
                        try:
                            api.request('/api/keys/' + key, {}, 'DELETE')
                        except Exception:
                            pass
                    await browser.call('Target.closeTarget', {'targetId': target})
        finally:
            if server:
                server.shutdown()
                server.server_close()
            stop(chromium)
            stop(backend)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base', default='http://127.0.0.1:8080')
    parser.add_argument('--cdp', default='http://127.0.0.1:9222')
    parser.add_argument('--backend-binary')
    parser.add_argument('--chromium', help='Launch isolated Chromium with the official extension and native host')
    parser.add_argument('--headless', action='store_true')
    parser.add_argument('--proxy-socket', default=os.environ.get('AUTH_BROWSER_PROXY_SOCKET'))
    args = parser.parse_args()
    if not args.chromium and not args.proxy_socket:
        parser.error('--proxy-socket is required when using an externally configured Chromium')
    if args.chromium and args.cdp != 'http://127.0.0.1:9222':
        parser.error('managed Chromium uses --cdp http://127.0.0.1:9222')
    asyncio.run(main(args))
