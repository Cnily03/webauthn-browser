"""Owned-child recovery with fake monotonic time; no Chrome/Docker claims."""
import importlib.util
from pathlib import Path
import signal
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("engine_runtime", Path(__file__).resolve().parents[1] / "runtime/supervisor.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class EngineRecoveryTests(unittest.TestCase):
    def fixture(self):
        supervisor = runtime.Supervisor()
        supervisor.gateway_started = True
        failed = Mock(pid=411, poll=Mock(return_value=1))
        browser = Mock(pid=412, poll=Mock(return_value=None))
        desktop = Mock(pid=413, poll=Mock(return_value=None))
        supervisor.children = [("gateway", failed), ("Chromium", browser), ("Xvfb", desktop)]
        supervisor.write_status = Mock()
        supervisor.proxy_ready = Mock(return_value=False)
        supervisor.browser_windows = Mock(return_value=[])
        created = []
        def spawn(name, command):
            child = Mock(pid=414 + len(created), poll=Mock(return_value=None))
            created.append(child)
            supervisor.children.append((name, child))
            return child
        supervisor.spawn = Mock(side_effect=spawn)
        return supervisor, failed, browser, created

    def test_gateway_exit_restarts_only_owned_child_after_delay(self):
        supervisor, failed, browser, created = self.fixture()
        with patch.object(runtime.time, "monotonic", return_value=10) as clock, patch.object(runtime.os, "killpg") as kill:
            supervisor.maintain_gateway()
            supervisor.spawn.assert_not_called()
            kill.assert_called_once_with(failed.pid, signal.SIGKILL)
            failed.wait.assert_called_once()
            self.assertEqual(supervisor.gateway_retry_at, 11)
            clock.return_value = 11
            supervisor.maintain_gateway()
            supervisor.maintain_gateway()
            supervisor.spawn.assert_called_once_with("gateway", ["/usr/local/bin/webauthn-browser"])
        self.assertIn(("Chromium", browser), supervisor.children)
        self.assertEqual(len(created), 1)
        self.assertEqual(supervisor.write_status.call_args.args[0], "recovering")

    def test_crash_loop_backoff_capped_and_reset_only_after_healthy_minute(self):
        supervisor, _, _, created = self.fixture()
        now = 0
        delays = []
        with patch.object(runtime.time, "monotonic") as clock, patch.object(runtime.os, "killpg"):
            for _ in range(8):
                clock.return_value = now
                supervisor.maintain_gateway()
                delay = supervisor.gateway_retry_at - now
                delays.append(delay)
                now += delay
                clock.return_value = now
                supervisor.maintain_gateway()
                created[-1].poll.return_value = 1
            self.assertEqual(delays, [1, 2, 4, 8, 16, 30, 30, 30])
            created[-1].poll.return_value = None
            supervisor.proxy_ready.return_value = True
            clock.return_value = now + 2
            supervisor.maintain_gateway()
            self.assertEqual(supervisor.gateway_backoff, 30)
            clock.return_value = now + 62
            supervisor.maintain_gateway()
            self.assertEqual(supervisor.gateway_backoff, 1)
            self.assertEqual(supervisor.write_status.call_args.args[0], "ready")

    def test_shutdown_suppresses_restart_even_when_due(self):
        supervisor, _, _, _ = self.fixture()
        supervisor.stopping = True
        supervisor.gateway_retry_at = 0
        with patch.object(runtime.os, "killpg") as kill:
            supervisor.maintain_gateway()
            supervisor.spawn.assert_not_called()
            kill.assert_not_called()
        with self.assertRaises(InterruptedError):
            supervisor.check_children()

    def test_unhealthy_native_transport_does_not_restart_live_gateway_or_browser(self):
        supervisor, child, browser, _ = self.fixture()
        child.poll.return_value = None
        with patch.object(runtime.os, "killpg") as kill:
            supervisor.maintain_gateway()
            supervisor.spawn.assert_not_called()
            kill.assert_not_called()
        self.assertIn(("Chromium", browser), supervisor.children)

    def test_failed_spawn_remains_recoverable(self):
        supervisor, _, _, _ = self.fixture()
        with patch.object(runtime.time, "monotonic", return_value=0) as clock, patch.object(runtime.os, "killpg"):
            supervisor.maintain_gateway()
            clock.return_value = 1
            supervisor.spawn.side_effect = OSError("temporary exec failure")
            supervisor.maintain_gateway()
            self.assertEqual(supervisor.gateway_retry_at, 3)
            self.assertEqual(supervisor.gateway_backoff, 4)
            self.assertEqual(supervisor.write_status.call_args.args[0], "recovering")

    def test_browser_crash_retries_but_normal_close_and_shutdown_do_not(self):
        supervisor, gateway, browser, _ = self.fixture()
        gateway.poll.return_value = None
        browser.poll.return_value = -11
        supervisor.reconnect = Mock()
        with patch.object(runtime.time, "monotonic", return_value=0) as clock:
            supervisor.maintain_browser()
            supervisor.reconnect.assert_not_called()
            clock.return_value = 1
            supervisor.maintain_browser()
            supervisor.reconnect.assert_called_once()
            supervisor.maintain_browser()
            self.assertEqual(supervisor.browser_retry_at, 3)
            clock.return_value = 3
            supervisor.maintain_browser()
            self.assertEqual(supervisor.reconnect.call_count, 2)
            browser.poll.return_value = 0
            supervisor.maintain_browser()
            clock.return_value = 100
            supervisor.maintain_browser()
            self.assertEqual(supervisor.reconnect.call_count, 2)
            browser.poll.return_value = -9
            supervisor.stopping = True
            supervisor.maintain_browser()
            self.assertEqual(supervisor.reconnect.call_count, 2)

    def test_browser_recovery_keeps_live_browser_when_only_proxy_missing(self):
        supervisor, _, browser, _ = self.fixture()
        supervisor.reconnect = Mock()
        supervisor.proxy_ready.return_value = False
        supervisor.maintain_browser()
        supervisor.reconnect.assert_not_called()
        self.assertIsNone(browser.poll())

    def test_browser_restart_failure_does_not_exit_supervisor(self):
        supervisor, _, browser, _ = self.fixture()
        browser.poll.return_value = 1
        supervisor.reconnect = Mock(side_effect=runtime.BrowserUnavailable("failed startup"))
        with patch.object(runtime.time, "monotonic", return_value=0) as clock:
            supervisor.maintain_browser()
            clock.return_value = 1
            supervisor.maintain_browser()
            self.assertEqual(supervisor.write_status.call_args.args, ("failed", "failed startup"))
            supervisor.maintain_browser()
            self.assertEqual(supervisor.browser_retry_at, 3)

    def test_browser_failed_exec_without_child_is_retried(self):
        supervisor, _, _, _ = self.fixture()
        supervisor.children = [(name, child) for name, child in supervisor.children if name != "Chromium"]
        supervisor.browser_crash_recovery = True
        supervisor.reconnect = Mock()
        with patch.object(runtime.time, "monotonic", return_value=0) as clock:
            supervisor.maintain_browser()
            clock.return_value = 1
            supervisor.maintain_browser()
            supervisor.reconnect.assert_called_once()

    def test_browser_delayed_proxy_recovery_restores_truthful_ready_status(self):
        supervisor, _, _, _ = self.fixture()
        supervisor.browser_crash_recovery = True
        supervisor.browser_closed_reported = True
        with patch.object(runtime.time, "monotonic", return_value=0) as clock:
            supervisor.maintain_browser()
            supervisor.write_status.assert_not_called()
            supervisor.proxy_ready.return_value = True
            clock.return_value = 2
            supervisor.maintain_browser()
            self.assertEqual(supervisor.write_status.call_args.args[0], "ready")
            self.assertFalse(supervisor.browser_closed_reported)
            self.assertFalse(supervisor.browser_crash_recovery)

    def test_private_session_bus_is_explicit_and_probed(self):
        supervisor = runtime.Supervisor()
        supervisor.spawn = Mock()
        supervisor.wait_ready = Mock()
        with patch.object(runtime, "prepare_x_socket_dir"):
            supervisor.start_desktop()
        calls = supervisor.spawn.call_args_list
        self.assertEqual(calls[0].args[0], "private session D-Bus")
        self.assertIn("--address=unix:path=/data/run/dbus-session.sock", calls[0].args[1])
        with patch.object(runtime.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertTrue(supervisor.session_dbus_ready())
            self.assertIn("--session", run.call_args.args[0])
        supervisor.open_control = Mock()
        supervisor.start_desktop = Mock(side_effect=InterruptedError())
        supervisor.write_status = Mock()
        with patch.object(runtime.os, "getuid", return_value=10001), patch.object(runtime.os, "umask"), patch.object(runtime.Path, "mkdir"), patch.object(runtime, "prepare_cache_dir"), patch.dict(runtime.os.environ, {"DBUS_SESSION_BUS_ADDRESS": "disabled:"}):
            with self.assertRaises(InterruptedError):
                supervisor.run()
            self.assertEqual(runtime.os.environ["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/data/run/dbus-session.sock")


class RealOwnedProcessTests(unittest.TestCase):
    def test_real_owned_gateway_exit_is_reaped_then_replaced_once(self):
        supervisor = runtime.Supervisor()
        supervisor.write_status = Mock()
        supervisor.proxy_ready = Mock(return_value=False)
        failed = supervisor.spawn("gateway", [sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(failed.wait(timeout=5), 7)
        supervisor.gateway_started = True
        original_spawn = supervisor.spawn
        spawned = []
        def replacement(name, command):
            self.assertEqual(command, ["/usr/local/bin/webauthn-browser"])
            child = original_spawn(name, [sys.executable, "-c", "import time; time.sleep(30)"])
            spawned.append(child)
            return child
        supervisor.spawn = replacement
        try:
            with patch.object(runtime.time, "monotonic", return_value=0) as clock:
                supervisor.maintain_gateway()
                self.assertEqual(spawned, [])
                clock.return_value = 1
                supervisor.maintain_gateway()
                supervisor.maintain_gateway()
                self.assertEqual(len(spawned), 1)
                self.assertIsNone(spawned[0].poll())
                self.assertEqual(supervisor.children, [("gateway", spawned[0])])
        finally:
            supervisor.shutdown()
        self.assertIsNotNone(spawned[0].poll())


@unittest.skipUnless(shutil.which("dbus-daemon"), "dbus-daemon unavailable")
class SessionBusParserTests(unittest.TestCase):
    def test_actual_session_config_parses_before_transport(self):
        result = subprocess.run(["dbus-daemon", "--session", "--nofork", "--nopidfile",
                                 "--address=authbrowser-parse-probe:"],
                                capture_output=True, text=True, timeout=5, env=dict(os.environ, LC_ALL="C"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown address type", result.stderr)
        self.assertIn("authbrowser-parse-probe", result.stderr)

    @unittest.skipUnless(shutil.which("dbus-send"), "dbus-send unavailable")
    def test_real_private_session_bus_uses_valid_unix_address(self):
        with tempfile.TemporaryDirectory(prefix="private-session-") as directory:
            address = f"unix:path={directory}/session.sock"
            child = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--nopidfile",
                                      f"--address={address}", "--print-address=1"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=dict(os.environ, LC_ALL="C"))
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5))
                    announced = child.stdout.readline().strip()
                if not announced:
                    _, error = child.communicate(timeout=5)
                    if "Failed to open socket: Operation not permitted" in error:
                        self.skipTest("session config parsed; AF_UNIX socket creation denied (EPERM)")
                    self.fail(error)
                self.assertTrue(announced.startswith(address))
                result = subprocess.run(["dbus-send", "--session", "--print-reply", "--reply-timeout=1000",
                                         "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.GetId"],
                                        capture_output=True, text=True, timeout=3,
                                        env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=announced))
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()


if __name__ == "__main__":
    unittest.main()
