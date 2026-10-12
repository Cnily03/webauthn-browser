"""Actual backend restart test without Chromium; requires a built release binary and free 8080."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def cycle(store, create, binary):
    env = dict(os.environ, AUTH_BROWSER_STORE=str(store), AUTH_BROWSER_PROXY_SOCKET=str(store.parent / "run" / "proxy.sock"))
    process = subprocess.Popen([str(binary)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    token = ""
    def request(path, body=None, method=None):
        headers = {"X-CSRF-Token": token, "Content-Type": "application/json"}
        req = urllib.request.Request("http://127.0.0.1:8080" + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        with client.open(req, timeout=12) as response:
            return json.load(response)
    try:
        for _ in range(60):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                status = request("/api/status")
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("backend did not become available")
        token = status["csrf_token"]
        if create:
            request("/api/keys", {"name":"persistent test key", "attachment":"platform", "enabled":True, "automatic_presence":False, "simulated_uv":False})
            request("/api/security", {"scope":"vnc", "password":"test-vnc-password"}, "PUT")
            request("/api/security", {"scope":"settings", "password":"test-settings-password"}, "PUT")
        else:
            assert status["settings_password_enabled"] and status["vnc_password_enabled"]
            assert not status["settings_authenticated"] and not status["vnc_authenticated"]
            request("/api/login", {"scope":"settings", "password":"test-settings-password"})
            keys = request("/api/keys")["keys"]
            assert len(keys) == 1 and keys[0]["name"] == "persistent test key"
            assert keys[0]["pin_configured"] is False
            assert keys[0]["simulated_uv"] is False
            request("/api/login", {"scope":"vnc", "password":"test-vnc-password"})
            pending = request("/api/requests")
            assert pending["requests"] == [] and pending["connected"] is False
            backup = request("/api/backup")
            assert len(backup["keys"]) == 1
    finally:
        process.terminate()
        try:
            process.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-binary", type=Path, default=ROOT / "target/release/webauthn-browser")
    binary = parser.parse_args().backend_binary.resolve()
    with tempfile.TemporaryDirectory() as temp:
        store = Path(temp) / "auth-browser.json"
        cycle(store, True, binary)
        cycle(store, False, binary)
        assert store.stat().st_mode & 0o777 == 0o600
    print("PASS: actual backend restart preserves key, both password configurations, authentication and protected backup")
