"""Real subprocess tests of private Chromium pipe ABI; no browser is launched."""
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("browser_cdp_under_test", ROOT / "runtime/browser_cdp.py")
cdp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdp)

CHILD = r'''
import json, os, time
mode = os.environ.get('FIXTURE_MODE', '')
if mode == 'eof':
    os.close(4)
    time.sleep(0.4)
    raise SystemExit(0)
if mode == 'timeout':
    time.sleep(0.25)
    # Parent timeout must not close the request pipe or change child ownership.
    os.set_blocking(3, False)
    try:
        content = os.read(3, 4096)
    except BlockingIOError:
        content = b'x'
    if not content:
        raise SystemExit(31)
    time.sleep(0.2)
    raise SystemExit(0)
if mode == 'overflow':
    os.read(3, 4096)
    os.write(4, b'x' * 65537)
    time.sleep(0.2)
    raise SystemExit(0)
cap = os.environ.get('UHF_CONTROL_FD')
if cap:
    assert int(cap) >= 64
    assert os.read(int(cap), 4) == b'FIDO'
extra = os.environ.get('EXTRA_FD')
if extra:
    try:
        os.fstat(int(extra))
    except OSError:
        pass
    else:
        raise SystemExit(32)
buffer = b''
while True:
    part = os.read(3, 4096)
    if not part:
        raise SystemExit(33)
    buffer += part
    while b'\0' in buffer:
        raw, buffer = buffer.split(b'\0', 1)
        request = json.loads(raw)
        assert set(request) == {'id', 'method'}
        assert request['method'] in ('Browser.getVersion', 'Browser.close')
        result = {'product': 'Fixture/1'} if request['method'] == 'Browser.getVersion' else {}
        response = json.dumps({'id': request['id'], 'result': result}).encode() + b'\0'
        if mode == 'close-timeout' and request['method'] == 'Browser.close':
            time.sleep(0.2)
        if mode == 'error':
            response = json.dumps({'id': request['id'], 'error': {'message': 'SECRET'}}).encode() + b'\0'
        if mode == 'bad-json':
            response = b'not-json\0'
        if mode == 'fragmented':
            response = b'{"method":"event","params":{}}\0' + response
            for byte in response:
                os.write(4, bytes([byte]))
        elif mode == 'late':
            if request['id'] == 1:
                time.sleep(0.12)
            os.write(4, response)
        else:
            os.write(4, response)
        if request['method'] == 'Browser.close':
            raise SystemExit(0)
'''


class BrowserPipeTests(unittest.TestCase):
    def fixture(self, mode='', inherited=None, extra=None):
        env = dict(os.environ, FIXTURE_MODE=mode)
        if extra is not None:
            env['EXTRA_FD'] = str(extra)
        process, controller = cdp.spawn([sys.executable, '-c', CHILD], env, inherited)
        self.addCleanup(self.cleanup, process, controller)
        return process, controller

    @staticmethod
    def cleanup(process, controller):
        if process.poll() is None:
            process.terminate()  # Disposable fixture only, never production restart.
        process.wait(timeout=3)
        controller.dispose_after_exit()

    def test_fixed_version_close_and_idempotent_disposal(self):
        process, controller = self.fixture()
        self.assertEqual(os.getpgid(process.pid), process.pid)
        self.assertNotEqual(os.getpgid(process.pid), os.getpgrp())
        self.assertEqual(controller.get_version(), {'product': 'Fixture/1'})
        self.assertEqual(controller.close_browser(), {})
        self.assertEqual(process.wait(timeout=2), 0)
        controller.dispose_after_exit()
        controller.dispose_after_exit()
        with self.assertRaises(cdp.BrowserPipeError):
            controller.get_version()
        with self.assertRaises(cdp.BrowserPipeError):
            controller.close_browser()

    def test_parent_pipe_above_select_fd_limit(self):
        process, controller = self.fixture()
        for name in ('_request', '_response'):
            old = getattr(controller, name)
            high = fcntl.fcntl(old, fcntl.F_DUPFD_CLOEXEC, 2048)
            setattr(controller, name, high)
            os.close(old)
        self.assertEqual(controller.get_version()['product'], 'Fixture/1')
        controller.close_browser()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_fragmented_and_coalesced_messages(self):
        process, controller = self.fixture('fragmented')
        self.assertEqual(controller.get_version()['product'], 'Fixture/1')
        controller.close_browser()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_timeout_preserves_live_pipe_and_process(self):
        process, controller = self.fixture('timeout')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'timed out'):
            controller.get_version(timeout=0.05)
        self.assertIsNone(process.poll())
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'live browser'):
            controller.dispose_after_exit()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_close_timeout_keeps_pipe_and_does_not_replay_close(self):
        process, controller = self.fixture('close-timeout')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'timed out'):
            controller.close_browser(timeout=0.05)
        self.assertIsNone(process.poll())
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'already requested'):
            controller.close_browser()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_late_response_cannot_satisfy_new_request(self):
        process, controller = self.fixture('late')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'timed out'):
            controller.get_version(timeout=0.05)
        self.assertEqual(controller.get_version(timeout=1)['product'], 'Fixture/1')
        controller.close_browser()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_eof_does_not_reap_or_terminate_live_child(self):
        process, controller = self.fixture('eof')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'closed'):
            controller.get_version()
        self.assertIsNone(process.poll())
        self.assertEqual(process.wait(timeout=2), 0)

    def test_message_bound(self):
        process, controller = self.fixture('overflow')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'limit'):
            controller.get_version()
        self.assertIsNone(process.poll())

    def test_remote_error_payload_never_appears_in_exception(self):
        _, controller = self.fixture('error')
        with self.assertRaises(cdp.BrowserPipeError) as caught:
            controller.get_version()
        self.assertNotIn('SECRET', str(caught.exception))

    def test_invalid_json_fails_without_payload(self):
        _, controller = self.fixture('bad-json')
        with self.assertRaisesRegex(cdp.BrowserPipeError, 'invalid'):
            controller.get_version()

    def test_explicit_capability_kept_other_inheritable_fd_closed(self):
        read, write = os.pipe()
        extra = os.open('/dev/null', os.O_RDONLY)
        os.set_inheritable(extra, True)
        self.addCleanup(os.close, extra)
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        os.write(write, b'FIDO')
        process, controller = self.fixture(inherited={'UHF_CONTROL_FD': read}, extra=extra)
        controller.get_version()
        controller.close_browser()
        self.assertEqual(process.wait(timeout=2), 0)
        os.fstat(read)
        os.fstat(extra)

    def test_parent_fixed_fds_unchanged_with_capability_collision(self):
        # Isolate fd3/fd4 changes in a test subprocess, never the test runner.
        script = '''
import importlib.util, os, sys
spec=importlib.util.spec_from_file_location('cdp', sys.argv[1]); cdp=importlib.util.module_from_spec(spec); spec.loader.exec_module(cdp)
r,w=os.pipe(); os.write(w,b'FIDO'); saved=os.dup(r); os.dup2(saved,3); os.dup2(saved,4); os.close(saved)
before=(os.fstat(3),os.fstat(4))
p,c=cdp.spawn([sys.executable,'-c',sys.argv[2]],dict(os.environ),{'UHF_CONTROL_FD':int(sys.argv[3])})
assert before==(os.fstat(3),os.fstat(4))
assert c.get_version()['product']=='Fixture/1'
c.close_browser(); assert p.wait(timeout=2)==0; c.dispose_after_exit()
assert before==(os.fstat(3),os.fstat(4))
'''
        for capability_fd in ('3', '4'):
            with self.subTest(capability_fd=capability_fd):
                result = subprocess.run([sys.executable, '-c', script, str(ROOT / 'runtime/browser_cdp.py'), CHILD, capability_fd], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_spawn_failure_closes_only_new_fds(self):
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaises(FileNotFoundError):
            cdp.spawn(['/missing/chromium'], dict(os.environ))
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_unknown_capability_and_relative_command_rejected(self):
        for command, capabilities in [(['chromium'], {}), ([sys.executable], {'SECRET_FD': 0})]:
            with self.assertRaises(ValueError):
                cdp.spawn(command, dict(os.environ), capabilities)


if __name__ == '__main__':
    unittest.main()
