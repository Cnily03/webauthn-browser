"""Real gateway WebSocket / private-socket smoke; no X server or Chromium.

Uses only synthetic data. Requires tests/requirements.txt and release backend.
A Unix-socket policy denial is an explicit environment blocker, not a pass.
"""
import asyncio
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://127.0.0.1:8080'

async def exercise(temp, process):
    queue = asyncio.Queue()
    server = await asyncio.start_unix_server(lambda reader, writer: queue.put_nowait((reader, writer)), f'{temp}/clipboard.sock')
    jar = http.cookiejar.CookieJar()
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    token = ''
    def request(path, body=None, method=None):
        with http.open(urllib.request.Request(ORIGIN + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Content-Type': 'application/json', 'X-CSRF-Token': token}), timeout=5) as response:
            return json.load(response)
    def cookies(): return '; '.join(f'{cookie.name}={cookie.value}' for cookie in jar)
    try:
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('backend startup failed')
            try: token = request('/api/status')['csrf_token']; break
            except (OSError, urllib.error.URLError): await asyncio.sleep(.05)
        else: raise RuntimeError('backend did not start')
        for origin in (None, 'https://proxy.example:9443'):
            async with connect('ws://127.0.0.1:8080/api/clipboard/ws', origin=origin, proxy=None):
                reader, writer = await asyncio.wait_for(queue.get(), 2)
            assert await asyncio.wait_for(reader.read(), 2) == b''
            writer.close(); await writer.wait_closed()
        async with connect('ws://127.0.0.1:8080/api/clipboard/ws', origin=ORIGIN, proxy=None) as ws:
            reader, writer = await asyncio.wait_for(queue.get(), 2)
            for frame in ({'type': 'read', 'id': 'first'}, {'type': 'copy', 'id': 'second', 'text': '中文🎉\nline'}, {'type': 'copy_failed', 'id': 'third', 'error': 'too_large'}):
                writer.write(json.dumps(frame).encode() + b'\n'); await writer.drain()
                assert json.loads(await ws.recv()) == frame
            await ws.send(json.dumps({'type': 'read_result', 'id': 'first', 'text': 'current'}, indent=2))
            assert json.loads(await asyncio.wait_for(reader.readline(), 2)) == {'type': 'read_result', 'id': 'first', 'text': 'current'}
            request('/api/security', {'scope': 'vnc', 'password': 'synthetic-clipboard-password'}, 'PUT')
            try: await asyncio.wait_for(ws.recv(), 2); raise AssertionError('revoked connection remained open')
            except ConnectionClosed: pass
            assert await asyncio.wait_for(reader.read(), 2) == b''
            writer.close(); await writer.wait_closed()
        try:
            async with connect('ws://127.0.0.1:8080/api/clipboard/ws', origin=ORIGIN, proxy=None):
                raise AssertionError('locked VNC admitted clipboard')
        except InvalidStatus as error: assert error.response.status_code == 401
        request('/api/login', {'scope': 'vnc', 'password': 'synthetic-clipboard-password'}, 'POST')
        async with connect('ws://127.0.0.1:8080/api/clipboard/ws', origin=ORIGIN,
                           additional_headers={'Cookie': cookies()}, proxy=None) as ws:
            reader, writer = await asyncio.wait_for(queue.get(), 2)
            await ws.send(json.dumps({'type': 'read_result', 'id': 'x', 'text': 'one', 'error': 'denied'}))
            try: await asyncio.wait_for(ws.recv(), 2); raise AssertionError('invalid frame kept open')
            except ConnectionClosed: pass
            assert await asyncio.wait_for(reader.read(), 2) == b''
            writer.close(); await writer.wait_closed()
        print('PASS: real clipboard WS arbitrary-Origin admission, VNC authentication, UTF-8, framing, copy errors, revocation, invalid-frame fail-closed')
    finally:
        server.close(); await server.wait_closed()

def main():
    with tempfile.TemporaryDirectory(prefix='webauthn-browser-clipboard-') as temp:
        env = dict(os.environ, AUTH_BROWSER_STORE=f'{temp}/store.json',
                   AUTH_BROWSER_PROXY_SOCKET=f'{temp}/proxy.sock', AUTH_BROWSER_CLIPBOARD_SOCKET=f'{temp}/clipboard.sock')
        process = subprocess.Popen([str(ROOT / 'target/release/webauthn-browser')], cwd=ROOT, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try: asyncio.run(exercise(temp, process))
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()

if __name__ == '__main__': main()
