"""Clipboard child recovery with fake time/processes; no real X/Chrome claims."""
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "clipboard_supervisor_tests", Path(__file__).resolve().parents[1] / "runtime/supervisor.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class ClipboardSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.fido = patch.object(runtime._fido_control.FidoController, "from_environment", return_value=None)
        self.fido.start()
        self.addCleanup(self.fido.stop)
        self.socket = patch.object(runtime.Path, "is_socket", return_value=True)
        self.socket.start()
        self.addCleanup(self.socket.stop)
        self.log = patch("sys.stderr", new_callable=io.StringIO)
        self.log.start()
        self.addCleanup(self.log.stop)

    def fixture(self, result=1):
        supervisor = runtime.Supervisor()
        failed = Mock(pid=411, poll=Mock(return_value=result))
        browser = Mock(pid=412, poll=Mock(return_value=None))
        desktop = Mock(pid=413, poll=Mock(return_value=None))
        gateway = Mock(pid=414, poll=Mock(return_value=None))
        supervisor.children = [("gateway", gateway), ("Chromium", browser),
                               ("Xvfb", desktop), ("clipboard bridge", failed)]
        supervisor.clipboard_started = True
        supervisor.write_status = Mock()
        supervisor.browser_pipe = Mock()
        supervisor.browser_pipe_process = browser
        supervisor.profile_gateway_token = "a" * 64
        supervisor.browser_operations = {"owned-request": {"ok": True}}
        created = []

        def spawn(name, command):
            child = Mock(pid=415 + len(created), poll=Mock(return_value=None))
            created.append(child)
            supervisor.children.append((name, child))
            return child

        supervisor.spawn = Mock(side_effect=spawn)
        return supervisor, failed, browser, desktop, created

    def test_unexpected_exit_replaces_only_clipboard_and_preserves_owned_state(self):
        for result in (0, 1, -9):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                supervisor, failed, browser, desktop, created = self.fixture(result)
                profile = Path(directory)
                (profile / "History").write_bytes(b"persistent history fixture")
                (profile / "Cookies").write_bytes(b"persistent cookie fixture")
                before_files = {item.name: item.read_bytes() for item in profile.iterdir()}
                state = (supervisor.profile_epoch, supervisor.browser_epoch,
                         supervisor.profile_gateway_token, supervisor.browser_operations.copy())
                pipe = supervisor.browser_pipe
                supervisor.fido_control = Mock()

                with patch.object(runtime.time, "monotonic", return_value=10) as clock, \
                        patch.object(runtime.os, "killpg") as kill, \
                        patch.object(runtime, "PROFILE_PATH", profile):
                    supervisor.check_children(require_browser=False)
                    supervisor.spawn.assert_not_called()
                    kill.assert_not_called()
                    failed.wait.assert_called_once()
                    self.assertEqual(supervisor.clipboard_retry_at, 11)
                    clock.return_value = 11
                    supervisor.check_children(require_browser=False)
                    supervisor.check_children(require_browser=False)
                    kill.assert_not_called()
                    supervisor.spawn.assert_called_once_with(
                        "clipboard bridge", [sys.executable, "/opt/webauthn-browser/runtime/clipboard_bridge.py"])

                self.assertEqual(len(created), 1)
                self.assertIn(("Chromium", browser), supervisor.children)
                self.assertIn(("Xvfb", desktop), supervisor.children)
                self.assertEqual((supervisor.profile_epoch, supervisor.browser_epoch,
                                  supervisor.profile_gateway_token, supervisor.browser_operations), state)
                self.assertIs(supervisor.browser_pipe, pipe)
                pipe.assert_not_called()
                pipe.close_browser.assert_not_called()
                pipe.dispose_after_exit.assert_not_called()
                supervisor.fido_control.retire.assert_not_called()
                supervisor.fido_control.close.assert_not_called()
                supervisor.write_status.assert_not_called()
                self.assertEqual({item.name: item.read_bytes() for item in profile.iterdir()}, before_files)

    def test_crash_loop_delay_is_capped_and_resets_only_after_healthy_minute(self):
        supervisor, _, _, _, created = self.fixture()
        now = 0
        delays = []
        with patch.object(runtime.time, "monotonic") as clock, patch.object(runtime.os, "killpg"):
            for _ in range(8):
                clock.return_value = now
                supervisor.maintain_clipboard()
                delay = supervisor.clipboard_retry_at - now
                delays.append(delay)
                now += delay
                clock.return_value = now
                supervisor.maintain_clipboard()
                created[-1].poll.return_value = 1
            self.assertEqual(delays, [1, 2, 4, 8, 16, 30, 30, 30])
            created[-1].poll.return_value = None
            clock.return_value = now + 59
            supervisor.maintain_clipboard()
            self.assertEqual(supervisor.clipboard_backoff, 30)
            clock.return_value = now + 60
            supervisor.maintain_clipboard()
            self.assertEqual(supervisor.clipboard_backoff, 1)

    def test_missing_socket_does_not_reset_backoff_or_replace_live_child(self):
        supervisor, child, _, _, _ = self.fixture(result=None)
        supervisor.clipboard_backoff = 30
        with patch.object(runtime.time, "monotonic", return_value=1000), \
                patch.object(runtime.Path, "is_socket", return_value=False), \
                patch.object(runtime.os, "killpg") as kill:
            supervisor.maintain_clipboard()
        supervisor.spawn.assert_not_called()
        kill.assert_not_called()
        child.wait.assert_not_called()
        self.assertEqual(supervisor.clipboard_backoff, 30)
        self.assertIsNone(supervisor.clipboard_healthy_since)

    def test_failed_spawn_remains_recoverable_without_other_service_changes(self):
        supervisor, _, browser, desktop, created = self.fixture()
        spawn = supervisor.spawn.side_effect
        with patch.object(runtime.time, "monotonic", return_value=0) as clock, \
                patch.object(runtime.os, "killpg"):
            supervisor.check_children(require_browser=False)
            clock.return_value = 1
            supervisor.spawn.side_effect = OSError("temporary exec failure")
            supervisor.check_children(require_browser=False)
            self.assertEqual(supervisor.clipboard_retry_at, 3)
            self.assertEqual(supervisor.clipboard_backoff, 4)
            self.assertEqual(created, [])
            supervisor.spawn.side_effect = spawn
            clock.return_value = 3
            supervisor.check_children(require_browser=False)
        self.assertEqual(len(created), 1)
        self.assertIn(("Chromium", browser), supervisor.children)
        self.assertIn(("Xvfb", desktop), supervisor.children)

    def test_stopped_inactive_or_expired_startup_never_restarts_when_due(self):
        for reason in ("stopping", "inactive", "deadline"):
            with self.subTest(reason=reason):
                supervisor, _, _, _, _ = self.fixture()
                supervisor.clipboard_retry_at = 0
                if reason == "stopping":
                    supervisor.request_stop(None, None)
                elif reason == "inactive":
                    supervisor.clipboard_started = False
                else:
                    supervisor.profile_deadline = 10
                with patch.object(runtime.time, "monotonic", return_value=10), \
                        patch.object(runtime.os, "killpg") as kill:
                    supervisor.maintain_clipboard()
                    supervisor.spawn.assert_not_called()
                    kill.assert_not_called()
                    if reason != "inactive":
                        with self.assertRaises(InterruptedError if reason == "stopping" else runtime.BrowserUnavailable):
                            supervisor.check_children(require_browser=False)

    def test_profile_control_cancellation_is_processed_before_due_retry(self):
        supervisor, _, _, _, _ = self.fixture()
        supervisor.profile_control = Mock()
        supervisor.serve_profile_control = Mock(side_effect=lambda: supervisor.request_stop(None, None))
        supervisor.clipboard_retry_at = 0
        with patch.object(runtime.os, "killpg") as kill:
            with self.assertRaises(InterruptedError):
                supervisor.check_children(require_browser=False)
        supervisor.serve_profile_control.assert_called_once()
        supervisor.spawn.assert_not_called()
        kill.assert_not_called()

    def test_cancellation_is_rechecked_immediately_before_replacement(self):
        supervisor, _, _, _, _ = self.fixture()
        supervisor.children = [(name, child) for name, child in supervisor.children if name != "clipboard bridge"]
        supervisor.clipboard_retry_at = 0
        with patch.object(supervisor, "clipboard_recovery_allowed", side_effect=[True, False]):
            supervisor.maintain_clipboard()
        supervisor.spawn.assert_not_called()

    def test_signal_during_failed_child_reaping_prevents_any_replacement(self):
        supervisor, failed, _, _, _ = self.fixture()
        failed.wait.side_effect = lambda: supervisor.request_stop(None, None)
        with patch.object(runtime.time, "monotonic", return_value=0) as clock, \
                patch.object(runtime.os, "killpg"):
            with self.assertRaises(InterruptedError):
                supervisor.check_children(require_browser=False)
            clock.return_value = 100
            supervisor.maintain_clipboard()
        supervisor.spawn.assert_not_called()

    def test_shutdown_clears_recovery_for_both_full_and_desktop_only_teardown(self):
        for desktop_only in (False, True):
            with self.subTest(desktop_only=desktop_only):
                supervisor, _, _, _, _ = self.fixture()
                supervisor.clipboard_retry_at = 0

                def stopped_group(pid, _signal):
                    for _, child in supervisor.children:
                        if child.pid == pid:
                            child.poll.return_value = 0

                with patch.object(runtime.os, "killpg", side_effect=stopped_group):
                    supervisor.shutdown(desktop_only=desktop_only)
                    supervisor.maintain_clipboard()
                self.assertFalse(supervisor.clipboard_started)
                self.assertIsNone(supervisor.clipboard_retry_at)
                self.assertIsNone(supervisor.clipboard_healthy_since)
                supervisor.spawn.assert_not_called()
                self.assertEqual(supervisor.stopping, not desktop_only)

    def test_actual_desktop_death_keeps_existing_fatal_path(self):
        for failed_name in ("Xvfb", "Openbox", "x11vnc"):
            with self.subTest(failed_name=failed_name):
                supervisor, _, _, desktop, _ = self.fixture()
                supervisor.clipboard_retry_at = 0
                if failed_name == "Xvfb":
                    desktop.poll.return_value = 1
                else:
                    supervisor.children.append((failed_name, Mock(poll=Mock(return_value=1))))
                with patch.object(runtime.os, "killpg") as kill:
                    with self.assertRaisesRegex(RuntimeError, f"{failed_name} exited"):
                        supervisor.check_children(require_browser=False)
                supervisor.spawn.assert_not_called()
                kill.assert_not_called()

    def test_absent_display_suppresses_direct_maintenance(self):
        supervisor, _, _, _, _ = self.fixture()
        supervisor.children = [(name, child) for name, child in supervisor.children if name != "Xvfb"]
        supervisor.clipboard_retry_at = 0
        with patch.object(runtime.os, "killpg") as kill:
            supervisor.maintain_clipboard()
        supervisor.spawn.assert_not_called()
        kill.assert_not_called()

    def test_stale_socket_alone_is_not_startup_readiness(self):
        supervisor, failed, _, _, _ = self.fixture()
        self.assertFalse(supervisor.clipboard_ready())
        supervisor.children = [(name, child) for name, child in supervisor.children if child is not failed]
        self.assertFalse(supervisor.clipboard_ready())


if __name__ == "__main__":
    unittest.main()
