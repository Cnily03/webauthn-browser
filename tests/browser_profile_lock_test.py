import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('browser_profile_lock', Path(__file__).resolve().parents[1] / 'runtime/browser_profile_lock.py')
locks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(locks)


class BrowserProfileLockTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.profile = Path(self.temp.name) / 'chromium'
        self.profile.mkdir(mode=0o700)
        self.socket_patch = patch.object(locks.socket, 'socket')
        self.probe = self.socket_patch.start().return_value.__enter__.return_value
        self.probe.connect.side_effect = ConnectionRefusedError()
        self.addCleanup(self.socket_patch.stop)
        self.payload = self.profile / 'Default'
        self.payload.mkdir()
        (self.payload / 'Preferences').write_bytes(b'cookies-history-extensions-credentials')

    def stale(self):
        os.symlink('previous-container-149', self.profile / 'SingletonLock')
        os.symlink(str(Path(self.temp.name) / 'gone-socket'), self.profile / 'SingletonSocket')
        os.symlink('123456789', self.profile / 'SingletonCookie')

    def test_recreated_container_keeps_profile_data_and_removes_only_links(self):
        self.stale()
        self.assertEqual(locks.recover(self.profile, confirmed_exclusive=True), 3)
        self.assertEqual((self.payload / 'Preferences').read_bytes(), b'cookies-history-extensions-credentials')
        self.assertTrue((self.profile / locks.GUARD).is_file())
        self.assertEqual(locks.recover(self.profile, confirmed_exclusive=True), 0)

    def test_default_does_not_infer_foreign_container_is_dead(self):
        self.stale()
        with self.assertRaises(locks.ProfileLockError):
            locks.recover(self.profile)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_lifetime_guard_excludes_second_owner(self):
        directory, guard = locks.acquire(self.profile)
        try:
            with self.assertRaisesRegex(locks.ProfileLockError, 'already owned'):
                locks.acquire(self.profile)
            with self.assertRaisesRegex(locks.ProfileLockError, 'already owned'):
                locks.recover(self.profile, confirmed_exclusive=True)
        finally:
            os.close(guard)
            os.close(directory)
        directory, guard = locks.acquire(self.profile)
        os.close(guard)
        os.close(directory)

    def test_live_same_hostname_pid_is_never_removed(self):
        os.symlink(f'{socket.gethostname()}-{os.getpid()}', self.profile / 'SingletonLock')
        with self.assertRaisesRegex(locks.ProfileLockError, 'still present'):
            locks.recover(self.profile, confirmed_exclusive=True)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_live_socket_is_never_removed_even_with_foreign_hostname(self):
        self.stale()
        self.probe.connect.side_effect = None
        with self.assertRaisesRegex(locks.ProfileLockError, 'socket is active'):
            locks.recover(self.profile, confirmed_exclusive=True)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_regular_file_and_symlink_profile_are_refused(self):
        (self.profile / 'SingletonLock').write_text('previous-container-149')
        with self.assertRaises(locks.ProfileLockError):
            locks.recover(self.profile, confirmed_exclusive=True)
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.profile)
        with self.assertRaises(OSError):
            locks.recover(alias, confirmed_exclusive=True)

    def test_changed_evidence_is_not_removed(self):
        self.stale()
        original = locks.snapshot
        count = 0
        def changed(directory):
            nonlocal count
            count += 1
            if count == 2:
                (self.profile / 'SingletonCookie').unlink()
                (self.profile / 'SingletonCookie').symlink_to('replacement')
            return original(directory)
        with patch.object(locks, 'snapshot', side_effect=changed):
            with self.assertRaisesRegex(locks.ProfileLockError, 'changed'):
                locks.recover(self.profile, confirmed_exclusive=True)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_malformed_lock_and_missing_lock_are_refused(self):
        (self.profile / 'SingletonLock').symlink_to('malformed')
        with self.assertRaisesRegex(locks.ProfileLockError, 'Malformed'):
            locks.recover(self.profile, confirmed_exclusive=True)
        (self.profile / 'SingletonLock').unlink()
        (self.profile / 'SingletonCookie').symlink_to('123')
        with self.assertRaisesRegex(locks.ProfileLockError, 'Missing'):
            locks.recover(self.profile, confirmed_exclusive=True)

    def test_interrupted_cleanup_retains_lock_for_safe_retry(self):
        self.stale()
        original = os.unlink
        def interrupted(name, *args, **kwargs):
            if name == 'SingletonCookie':
                raise OSError('interrupted')
            return original(name, *args, **kwargs)
        with patch.object(locks.os, 'unlink', side_effect=interrupted):
            with self.assertRaises(OSError):
                locks.recover(self.profile, confirmed_exclusive=True)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())
        self.assertEqual(locks.recover(self.profile, confirmed_exclusive=True), 2)

    def test_relative_socket_target_is_refused(self):
        self.stale()
        (self.profile / 'SingletonSocket').unlink()
        (self.profile / 'SingletonSocket').symlink_to('relative-socket')
        with self.assertRaisesRegex(locks.ProfileLockError, 'must be absolute'):
            locks.recover(self.profile, confirmed_exclusive=True)
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_visible_profile_process_blocks_even_foreign_hostname(self):
        self.stale()
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)',
                                    '--user-data-dir=' + str(self.profile)])
        try:
            with self.assertRaisesRegex(locks.ProfileLockError, 'local process'):
                locks.recover(self.profile, confirmed_exclusive=True)
        finally:
            process.terminate()
            process.wait()
        self.assertTrue((self.profile / 'SingletonLock').is_symlink())

    def test_supervisor_recovers_before_launch_and_retains_guard(self):
        supervisor_spec = importlib.util.spec_from_file_location('singleton_supervisor_test',
            Path(__file__).resolve().parents[1] / 'runtime/supervisor.py')
        supervisor = importlib.util.module_from_spec(supervisor_spec)
        supervisor_spec.loader.exec_module(supervisor)
        self.stale()
        with patch.object(supervisor._fido_control.FidoController, 'from_environment', return_value=None):
            model = supervisor.Supervisor()
        directory, guard = locks.acquire(self.profile)
        model.profile_guard = (directory, guard)
        try:
            with patch.dict(os.environ, {'AUTH_BROWSER_EXCLUSIVE_PROFILE': 'true'}), \
                 patch.object(supervisor, 'PROFILE_PATH', self.profile), \
                 patch.object(model, 'spawn') as spawn:
                model.start_browser()
                spawn.assert_called_once()
                self.assertFalse((self.profile / 'SingletonLock').is_symlink())
                with self.assertRaisesRegex(locks.ProfileLockError, 'already owned'):
                    locks.acquire(self.profile)
        finally:
            os.close(guard)
            os.close(directory)

    def test_cookie_target_is_never_touched(self):
        self.stale()
        target = self.profile / '123456789'
        target.write_text('preserve')
        locks.recover(self.profile, confirmed_exclusive=True)
        self.assertEqual(target.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
