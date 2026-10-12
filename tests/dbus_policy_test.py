"""Real dbus-daemon parser and private-bus startup regressions.

Never uses the host bus. The container account is mapped to the current UID
only in temporary fixtures: absent user names make dbus-daemon ignore policies,
which can mask semantic errors before a socket-restricted runner reports EPERM.
"""
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'runtime/dbus-system.conf'


class PrivateBusPolicyTests(unittest.TestCase):
    def test_admission_is_global_and_message_permissions_are_user_scoped(self):
        root = ET.fromstring(CONFIG.read_text())
        default = root.find("policy[@context='default']")
        self.assertIsNotNone(default)
        self.assertEqual([e.attrib for e in default if 'user' in e.attrib],
                         [{'user': '*'}, {'user': 'authbrowser'}])
        self.assertEqual([e.tag for e in default if 'user' in e.attrib], ['deny', 'allow'])
        user = root.find("policy[@user='authbrowser']")
        self.assertIsNotNone(user)
        self.assertFalse(any('user' in e.attrib or 'group' in e.attrib for e in user))
        self.assertEqual([e.attrib for e in user.findall('allow')], [
            {'own': 'org.bluez'}, {'send_destination': '*'}, {'receive_sender': '*'}])
        self.assertEqual(root.findtext('auth'), 'EXTERNAL')
        self.assertEqual(root.findtext('listen'), 'unix:path=/data/run/dbus-system.sock')
        self.assertFalse(root.findall('include') + root.findall('includedir'))


@unittest.skipUnless(shutil.which('dbus-daemon'), 'dbus-daemon not installed')
class RealDaemonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='private-dbus-test-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.config = self.path / 'bus.conf'
        self.source = CONFIG.read_text().replace('user="authbrowser"', f'user="{os.getuid()}"')
        self.config.write_text(self.source)
        self.env = dict(os.environ, LC_ALL='C')

    def command(self, address):
        return ['dbus-daemon', '--nofork', '--nopidfile', '--nosyslog',
                f'--config-file={self.config}', f'--address={address}', '--print-address=1']

    def test_real_parser_accepts_policy_before_transport_initialization(self):
        # Deliberately unsupported transport is a deterministic post-parse
        # sentinel, with no socket creation and no security-policy workaround.
        result = subprocess.run(self.command('authbrowser-parse-probe:'),
                                capture_output=True, text=True, timeout=5, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown address type', result.stderr)
        self.assertIn('authbrowser-parse-probe', result.stderr)
        self.assertNotIn('Unknown username', result.stderr)
        self.assertNotIn('bus-global semantics', result.stderr)

    def test_real_parser_rejects_original_per_user_admission_bug(self):
        rule = f'    <allow user="{os.getuid()}"/>\n'
        broken = self.source.replace(rule, '')
        broken = broken.replace(f'  <policy user="{os.getuid()}">\n',
                                f'  <policy user="{os.getuid()}">\n' + rule)
        self.config.write_text(broken)
        result = subprocess.run(self.command('authbrowser-parse-probe:'),
                                capture_output=True, text=True, timeout=5, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rule cannot be per-user because it has bus-global semantics', result.stderr)
        self.assertNotIn('Unknown address type', result.stderr)

    @unittest.skipUnless(shutil.which('dbus-send'), 'dbus-send not installed')
    def test_real_private_bus_startup_readiness_and_name_ownership(self):
        address = f'unix:path={self.path}/bus.sock'
        process = subprocess.Popen(self.command(address), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=self.env)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5), 'daemon did not announce startup')
                announced = process.stdout.readline().strip()
            if not announced:
                _, error = process.communicate(timeout=5)
                if ('Failed to open socket: Operation not permitted' in error
                        and 'bus-global semantics' not in error
                        and 'Unknown username' not in error):
                    self.skipTest('real daemon policy parsed; AF_UNIX socket creation denied (EPERM)')
                self.fail(f'private bus failed to start: {error}')
            self.assertTrue(announced.startswith(address), announced)
            env = dict(self.env, DBUS_SYSTEM_BUS_ADDRESS=announced)
            base = ['dbus-send', '--system', '--print-reply', '--reply-timeout=1000',
                    '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus']
            ready = subprocess.run(base + ['org.freedesktop.DBus.GetId'],
                                   capture_output=True, text=True, timeout=3, env=env)
            self.assertEqual(ready.returncode, 0, ready.stderr)
            allowed = subprocess.run(base + ['org.freedesktop.DBus.RequestName',
                                            'string:org.bluez', 'uint32:0'],
                                     capture_output=True, text=True, timeout=3, env=env)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            self.assertIn('uint32 1', allowed.stdout)
            denied = subprocess.run(base + ['org.freedesktop.DBus.RequestName',
                                           'string:org.authbrowser.Unrelated', 'uint32:0'],
                                    capture_output=True, text=True, timeout=3, env=env)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn('AccessDenied', denied.stderr)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


if __name__ == '__main__':
    unittest.main(verbosity=2)
