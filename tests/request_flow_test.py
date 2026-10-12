"""Offline checks of the live-test verifier and native-host launcher, not E2E proof."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import live_webauthn as live


class RequestFlowHarnessTest(unittest.TestCase):
    def test_approval_harness_keeps_selection_password_and_touch_separate(self):
        for setup, required in [(True, True), (False, True), (False, False)]:
            calls = []
            def decision(request, body):
                calls.append(body)
                action = body['action']
                return {'stage': {'select': 'setup_password' if setup else 'verify_password' if required else 'touch',
                    'setup_password': 'verify_password', 'verify_password': 'touch', 'touch': 'completed'}[action]}
            api = types.SimpleNamespace(decision=decision)
            request = {'id': 'request', 'candidates': [{'key_id': 'key', 'credential_id': None,
                'pin_setup': setup, 'pin_required': required}]}
            live.approve(api, request, 'key', password=live.PIN if required else None)
            expected = ['select'] + (['setup_password'] if setup else []) + (['verify_password'] if required else []) + ['touch']
            self.assertEqual([body['action'] for body in calls], expected)
            self.assertEqual(calls[-1], {'action': 'touch'})
            self.assertNotIn('password', calls[0])
            self.assertTrue(all('approve' not in body for body in calls))

    def test_verifier_checks_real_signature_origin_and_uv(self):
        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        credential = {'id': live.b64(b'credential'), 'publicKey': live.b64(public)}
        client = json.dumps({'type': 'webauthn.get', 'challenge': 'test',
            'origin': 'http://localhost:1234', 'crossOrigin': False}).encode()
        auth = hashlib.sha256(b'localhost').digest() + b'\x05' + (3).to_bytes(4, 'big')
        signature = private.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        value = {'id': credential['id'], 'client': live.b64(client),
            'authData': live.b64(auth), 'signature': live.b64(signature)}
        self.assertEqual(live.verify(value, 'test', 'http://localhost:1234',
            'get', 'required', credential), 3)
        with self.assertRaises(AssertionError):
            live.verify(value, 'test', 'http://localhost:1234', 'get', 'discouraged', credential)
        with self.assertRaises(AssertionError):
            live.verify(value, 'test', 'http://localhost:9999', 'get', 'required', credential)
        value['signature'] = live.b64(b'invalid')
        with self.assertRaises(Exception):
            live.verify(value, 'test', 'http://localhost:1234', 'get', 'required', credential)

    def test_launcher_isolates_manifest_profile_and_socket_without_disabling_sandbox(self):
        args = types.SimpleNamespace(backend_binary='/tmp/test-backend',
            chromium='/usr/bin/chromium', headless=True)
        with tempfile.TemporaryDirectory() as directory, patch.object(live.subprocess, 'Popen') as spawn:
            root = Path(directory)
            socket = root / 'run/proxy.sock'
            live.start_chromium(args, root, socket)
            argv = spawn.call_args.args[0]
            self.assertNotIn('--no-sandbox', argv)
            self.assertIn('--load-extension=' + str(live.ROOT / 'extension'), argv)
            self.assertEqual(spawn.call_args.kwargs['env']['AUTH_BROWSER_PROXY_SOCKET'], str(socket))
            manifest = json.loads((root / 'home/.config/chromium/NativeMessagingHosts/com.auth_browser.proxy.json').read_text())
            self.assertEqual(manifest['name'], 'com.auth_browser.proxy')
            self.assertIn('--native-proxy "$@"', Path(manifest['path']).read_text())
            self.assertEqual(Path(manifest['path']).stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
