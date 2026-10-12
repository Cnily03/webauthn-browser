"""Mock-only reconnect contracts; no real browser/socket/sandbox claims."""
import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
import time
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_reconnect", ROOT / "runtime/supervisor.py")
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)


class ReconnectTests(unittest.TestCase):
    def ready_runtime(self, closed=False):
        runtime = supervisor.Supervisor()
        browser = Mock(pid=456, poll=Mock(return_value=0 if closed else None))
        runtime.children = [(name, Mock(poll=Mock(return_value=None))) for name in ("gateway", "Xvfb", "Openbox", "x11vnc")]
        runtime.children.append(("Chromium", browser))
        runtime.display_ready = Mock(return_value=True)
        runtime.vnc_ready = Mock(return_value=True)
        runtime.proxy_ready = Mock(return_value=True)
        runtime.wait_ready = Mock()
        runtime.restore_browser = Mock()
        runtime.browser_windows = Mock(return_value=["0x04000007"])
        runtime.write_status = Mock()
        return runtime, browser

    def test_live_process_empty_inventory_never_opens_a_new_window(self):
        runtime, _ = self.ready_runtime()
        runtime.browser_windows.return_value = []
        runtime.spawn = Mock()
        with self.assertRaisesRegex(supervisor.BrowserUnavailable, "running"):
            runtime.reconnect()
        runtime.spawn.assert_not_called()
        runtime.restore_browser.assert_not_called()

    def test_unrecognized_class_is_ambiguous_not_an_empty_browser(self):
        runtime = supervisor.Supervisor()
        with patch.object(supervisor.subprocess, "run", return_value=Mock(stdout="0x04000007 -1 custom.Browser desktop Tabs\n")):
            with self.assertRaisesRegex(ValueError, "identify"):
                runtime.browser_windows()

    def test_truncated_window_row_is_ambiguous_not_empty(self):
        runtime = supervisor.Supervisor()
        with patch.object(supervisor.subprocess, "run", return_value=Mock(stdout="0x04000007 -1\n")):
            with self.assertRaises(ValueError):
                runtime.browser_windows()

    def test_empty_wmctrl_needs_empty_ewmh_confirmation(self):
        runtime = supervisor.Supervisor()
        with patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=""), Mock(stdout="_NET_CLIENT_LIST(WINDOW): window id # 0x4000007\n")]):
            with self.assertRaises(ValueError):
                runtime.browser_windows()

    def test_only_explicitly_empty_client_lists_confirm_closed(self):
        runtime = supervisor.Supervisor()
        with patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=""), Mock(stdout="_NET_CLIENT_LIST(WINDOW): window id # \n_NET_CLIENT_LIST_STACKING(WINDOW): window id # \n")]) as run:
            self.assertEqual(runtime.browser_windows(), [])
            self.assertEqual(run.call_args.args[0], ["xprop", "-root", "_NET_CLIENT_LIST", "_NET_CLIENT_LIST_STACKING"])

    def test_unavailable_or_conflicting_client_lists_never_confirm_closed(self):
        empty = "_NET_CLIENT_LIST(WINDOW): window id # \n"
        for value in ("", "_NET_CLIENT_LIST: no such atom on any window.\n", empty,
                      empty + "_NET_CLIENT_LIST_STACKING(WINDOW): window id # 0x4000007\n",
                      "_NET_CLIENT_LIST(WINDOW): window id # 0x4000007\n_NET_CLIENT_LIST_STACKING(WINDOW): window id # \n",
                      empty + "_NET_CLIENT_LIST_STACKING(STRING) = \"\"\n"):
            with self.subTest(value=value), patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=""), Mock(stdout=value)]):
                with self.assertRaises(ValueError):
                    supervisor.Supervisor().browser_windows()
        for error in (OSError("X unavailable"), subprocess.TimeoutExpired("xprop", 2), subprocess.CalledProcessError(1, "xprop")):
            with self.subTest(error=type(error)), patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=""), error]):
                with self.assertRaises(type(error)):
                    supervisor.Supervisor().browser_windows()

    def test_managed_window_inventory_is_conservative_without_title_matching(self):
        for desktop in (-1, 0, 7):
            for cls in ("chromium.Chromium", "CHROMIUM.Chromium", "chromium-browser.Chromium-browser"):
                with self.subTest(desktop=desktop, cls=cls), patch.object(supervisor.subprocess, "run", return_value=Mock(stdout=f"0x04000007 {desktop} {cls} host\n")):
                    self.assertEqual(supervisor.Supervisor().browser_windows(), ["0x04000007"])
        for row in ("0x04000007 0 N/A host Chromium", "0x04000007 0 Other.Other host chromium.Chromium",
                    "0x0 0 chromium.Chromium host", "0x400000700 0 chromium.Chromium host",
                    "bad 0 chromium.Chromium host", "0x04000007 bad chromium.Chromium host",
                    "0x04000007 -2 chromium.Chromium host"):
            with self.subTest(row=row), patch.object(supervisor.subprocess, "run", return_value=Mock(stdout=row)):
                with self.assertRaises(ValueError):
                    supervisor.Supervisor().browser_windows()

    def test_dead_launcher_ambiguous_inventory_never_recovers_on_later_ticks(self):
        runtime, browser = self.ready_runtime(closed=True)
        runtime.browser_windows.side_effect = ValueError("Cannot identify existing browser window.")
        runtime.spawn = Mock()
        with patch.object(supervisor.os, "killpg") as kill:
            for _ in range(3):
                with self.assertRaises(ValueError):
                    runtime.reconnect()
                runtime.maintain_browser()
                runtime.request_extension_upgrade()
            kill.assert_not_called()
        runtime.spawn.assert_not_called()
        self.assertIn(("Chromium", browser), runtime.children)

    def test_extension_upgrade_live_browser_needs_positive_window_evidence(self):
        for inventory in ([], ValueError("unknown"), subprocess.TimeoutExpired("wmctrl", 2)):
            runtime, _ = self.ready_runtime()
            if isinstance(inventory, Exception):
                runtime.browser_windows.side_effect = inventory
            else:
                runtime.browser_windows.return_value = inventory
            runtime.spawn = Mock()
            runtime.request_extension_upgrade()
            runtime.spawn.assert_not_called()
            self.assertEqual(runtime.extension_upgrade_attempts, 0)

    def test_closed_browser_restarts_once_keeps_desktop_and_profile(self):
        runtime, previous = self.ready_runtime(closed=True)
        runtime.browser_windows.return_value = []
        before = runtime.children[:4]
        new = Mock(poll=Mock(return_value=None))
        commands = []
        def spawn(name, command):
            commands.append(command)
            runtime.children.append((name, new))
            runtime.browser_windows.return_value = ["0x04000007"]
        runtime.spawn = spawn
        with patch.object(supervisor.os, "killpg") as kill:
            self.assertEqual(runtime.reconnect(), {"ok": True, "restarted": True, "engine_ready": True})
            self.assertEqual(runtime.reconnect(), {"ok": True, "restarted": False, "engine_ready": True})
        self.assertEqual(runtime.children[:4], before)
        self.assertEqual(len(commands), 1)
        self.assertIn("--user-data-dir=/data/chromium", commands[0])
        self.assertIn("--restore-last-session", commands[0])
        self.assertNotIn("about:blank", commands[0])
        self.assertNotIn("--new-window", commands[0])
        self.assertNotIn("--no-sandbox", commands[0])
        self.assertIn("about:blank", runtime.browser_command())
        self.assertNotIn("--restore-last-session", runtime.browser_command())
        kill.assert_not_called()
        runtime.write_status.assert_called_with("ready", "Desktop is ready.")

    def test_exited_launcher_confirmed_empty_inventory_restores_session_once(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.browser_windows = supervisor.Supervisor.browser_windows.__get__(runtime)
        launched = []
        def inspect(command, **kwargs):
            if command == ["wmctrl", "-lx"]:
                return Mock(stdout="0x04000007 -1 chromium.Chromium host Restored tabs\n" if launched else "")
            self.assertEqual(command, ["xprop", "-root", "_NET_CLIENT_LIST", "_NET_CLIENT_LIST_STACKING"])
            return Mock(stdout="_NET_CLIENT_LIST(WINDOW): window id # \n_NET_CLIENT_LIST_STACKING(WINDOW): window id # \n")
        def spawn(name, command):
            launched.append(command)
            runtime.children.append((name, Mock(poll=Mock(return_value=None))))
        runtime.spawn = spawn
        with patch.object(supervisor.subprocess, "run", side_effect=inspect), patch.object(supervisor.os, "killpg") as kill:
            self.assertTrue(runtime.reconnect()["restarted"])
            self.assertFalse(runtime.reconnect()["restarted"])
            runtime.maintain_browser()
            kill.assert_not_called()
        self.assertEqual(len(launched), 1)
        self.assertIn("--restore-last-session", launched[0])
        self.assertNotIn("about:blank", launched[0])
        self.assertNotIn("--new-window", launched[0])

    def test_dead_launcher_with_live_window_is_restored_without_kill_or_spawn(self):
        runtime, browser = self.ready_runtime(closed=True)
        runtime.spawn = Mock()
        with patch.object(supervisor.os, "killpg") as kill:
            for _ in range(3):
                self.assertFalse(runtime.reconnect()["restarted"])
                runtime.maintain_browser()
            kill.assert_not_called()
        runtime.spawn.assert_not_called()
        self.assertIs(runtime.children[-1][1], browser)
        self.assertEqual(runtime.restore_browser.call_count, 3)

    def test_window_query_failure_never_implies_no_browser(self):
        for error in (OSError("X unavailable"), subprocess.TimeoutExpired("wmctrl", 2)):
            runtime, _ = self.ready_runtime(closed=True)
            runtime.browser_windows.side_effect = error
            runtime.spawn = Mock()
            with patch.object(supervisor.os, "killpg") as kill:
                response = self.control_request(runtime, b'{"command":"reconnect"}\n')
                self.assertFalse(response["ok"])
                runtime.maintain_browser()
                kill.assert_not_called()
            runtime.spawn.assert_not_called()

    def test_transient_window_query_error_recovers_when_existing_window_returns(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.spawn = Mock()
        runtime.browser_windows.side_effect = [OSError("temporary X error"), ["0x04000007"]]
        runtime.maintain_browser()
        self.assertEqual(runtime.write_status.call_args.args[0], "failed")
        runtime.maintain_browser()
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")
        runtime.spawn.assert_not_called()

    def test_missing_engine_does_not_delay_window_restore_or_restart_browser(self):
        runtime, browser = self.ready_runtime()
        runtime.proxy_ready.return_value = False
        runtime.spawn = Mock()
        self.assertEqual(runtime.reconnect(), {"ok": True, "restarted": False, "engine_ready": False})
        runtime.restore_browser.assert_called_once()
        runtime.wait_ready.assert_called_once_with("Chromium", runtime.browser_ready, timeout=25, require_browser=False)
        runtime.spawn.assert_not_called()
        self.assertIsNone(browser.poll())
        self.assertEqual(runtime.write_status.call_args.args[0], "recovering")
        runtime.proxy_ready.return_value = True
        runtime.maintain_browser()
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")

    def test_exited_launcher_live_window_eventual_engine_recovery_never_spawns(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.proxy_ready.return_value = False
        runtime.spawn = Mock()
        self.assertFalse(runtime.reconnect()["engine_ready"])
        with patch.object(supervisor.time, "monotonic", return_value=10) as clock:
            for tick in range(5):
                clock.return_value = 10 + tick * 2
                runtime.maintain_browser()
            runtime.proxy_ready.return_value = True
            clock.return_value = 22
            runtime.maintain_browser()
        runtime.spawn.assert_not_called()
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")

    def test_browser_startup_failure_keeps_existing_desktop_for_reconnect(self):
        runtime = supervisor.Supervisor()
        runtime.open_control = Mock()
        runtime.spawn = Mock()
        runtime.start_desktop = Mock(side_effect=supervisor.BrowserUnavailable("proxy unavailable"))
        runtime.write_status = Mock()
        runtime.shutdown = Mock()
        runtime.check_children = Mock(side_effect=InterruptedError("end test"))
        with patch.object(supervisor.os, "getuid", return_value=10001), patch.object(supervisor.os, "umask"), patch.object(supervisor.Path, "mkdir"), patch.object(supervisor, "prepare_cache_dir"), patch.dict(supervisor.os.environ):
            with self.assertRaises(InterruptedError):
                runtime.run()
        runtime.shutdown.assert_not_called()
        runtime.write_status.assert_called_with("failed", "proxy unavailable")

    def test_existing_browser_keeps_tabs_and_does_not_spawn(self):
        runtime, browser = self.ready_runtime()
        runtime.spawn = Mock()
        self.assertFalse(runtime.reconnect()["restarted"])
        runtime.spawn.assert_not_called()
        runtime.restore_browser.assert_called_once()
        self.assertIs(runtime.children[-1][1], browser)

    def test_repeated_reconnect_without_identified_window_keeps_live_process(self):
        runtime, browser = self.ready_runtime()
        runtime.browser_windows.return_value = []
        runtime.spawn = Mock()
        with patch.object(supervisor.os, "killpg") as kill:
            for _ in range(3):
                with self.assertRaises(supervisor.BrowserUnavailable):
                    runtime.reconnect()
                runtime.maintain_browser()
            kill.assert_not_called()
        runtime.spawn.assert_not_called()
        runtime.wait_ready.assert_not_called()
        self.assertIn(("Chromium", browser), runtime.children)

    def test_pending_window_launcher_is_not_duplicated(self):
        runtime, _ = self.ready_runtime()
        runtime.browser_windows.return_value = []
        launcher = Mock(poll=Mock(return_value=None))
        runtime.children.append(("Chromium window launcher", launcher))
        runtime.spawn = Mock()
        with self.assertRaises(supervisor.BrowserUnavailable):
            runtime.reconnect()
        runtime.spawn.assert_not_called()
        self.assertIn(("Chromium window launcher", launcher), runtime.children)

    def test_singleton_handoff_race_adopts_one_primary(self):
        runtime, browser = self.ready_runtime(closed=True)
        launcher = Mock(poll=Mock(return_value=None))
        runtime.children.append(("Chromium window launcher", launcher))
        runtime.check_children()
        self.assertEqual([child for name, child in runtime.children if name == "Chromium"], [launcher])
        self.assertFalse(any(name == "Chromium window launcher" for name, _ in runtime.children))

    def test_singleton_handoff_during_reconnect_reports_replacement(self):
        runtime, browser = self.ready_runtime()
        launcher = Mock(poll=Mock(return_value=None))
        runtime.children.append(("Chromium window launcher", launcher))
        runtime.spawn = Mock()
        def handoff(*args, **kwargs):
            browser.poll.return_value = 0
            runtime.reap_window_launcher()
        runtime.wait_ready.side_effect = handoff
        self.assertTrue(runtime.reconnect()["restarted"])
        self.assertIn(("Chromium", launcher), runtime.children)
        runtime.spawn.assert_not_called()

    def test_surviving_window_allows_only_bounded_extension_reload(self):
        runtime, browser = self.ready_runtime(closed=True)
        runtime.spawn = Mock()
        with patch.object(supervisor.os, "killpg") as kill:
            runtime.request_extension_upgrade()
            runtime.request_extension_upgrade()
            kill.assert_not_called()
        runtime.spawn.assert_called_once()
        name, command = runtime.spawn.call_args.args
        self.assertEqual(name, "Chromium window launcher")
        self.assertTrue(command[-1].startswith(supervisor.EXTENSION_UPGRADE_URL + "?"))
        self.assertNotIn("about:blank", command)
        self.assertNotIn("--restore-last-session", command)
        self.assertIs(runtime.children[-1][1], browser)

    def test_extension_reload_does_not_launch_after_uncertain_window_query(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.browser_windows.side_effect = subprocess.TimeoutExpired("wmctrl", 2)
        runtime.spawn = Mock()
        runtime.request_extension_upgrade()
        runtime.spawn.assert_not_called()
        self.assertEqual(runtime.extension_upgrade_attempts, 0)

    def test_minimized_and_windowed_windows_restore_and_maximize(self):
        for initial in ("minimized", "windowed", "fullscreen"):
            with self.subTest(initial=initial):
                runtime = supervisor.Supervisor()
                state = {"mode": initial, "active": False, "tabs": ["one", "two"]}
                def run(command, **kwargs):
                    if command == ["wmctrl", "-lx"]:
                        return Mock(stdout="0x04000007  0 chromium.Chromium desktop Account page\n0x05000008 0 other.Other desktop Other\n")
                    self.assertNotIn("shell", kwargs)
                    if command[0] == "xprop":
                        return Mock(stdout=("_NET_WM_STATE(ATOM) = _NET_WM_STATE_MAXIMIZED_VERT, _NET_WM_STATE_MAXIMIZED_HORZ"
                                            if "-id" in command else "_NET_ACTIVE_WINDOW(WINDOW): window id # 0x4000007"))
                    self.assertIn("0x04000007", command)
                    if "add,maximized_vert,maximized_horz" in command:
                        state["mode"] = "maximized"
                    if "-ia" in command:
                        state["active"] = True
                    return Mock(returncode=0)
                with patch.object(supervisor.subprocess, "run", side_effect=run):
                    runtime.restore_browser()
                self.assertEqual(state, {"mode": "maximized", "active": True, "tabs": ["one", "two"]})

    def test_window_state_verification_requires_exact_properties_and_atoms(self):
        runtime = supervisor.Supervisor()
        maximized = "_NET_WM_STATE(ATOM) = _NET_WM_STATE_MAXIMIZED_VERT, _NET_WM_STATE_MAXIMIZED_HORZ"
        focused = "_NET_ACTIVE_WINDOW(WINDOW): window id # 0x4000007"
        with patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=maximized), Mock(stdout=focused)]):
            self.assertTrue(runtime.window_restored("0x04000007"))
        for state, active in ((maximized + ", _NET_WM_STATE_HIDDEN", focused),
                              (maximized + ", _NET_WM_STATE_FULLSCREEN", focused),
                              (maximized.replace("MAXIMIZED_VERT", "MAXIMIZED_VERT_FAKE"), focused),
                              (maximized.replace("(ATOM)", "(STRING)"), focused),
                              (maximized, focused.replace("0x4000007", "0x9999999")),
                              (maximized, "error: old active was 0x4000007"), ("", focused)):
            with self.subTest(state=state, active=active), patch.object(supervisor.subprocess, "run", side_effect=[Mock(stdout=state), Mock(stdout=active)]):
                self.assertFalse(runtime.window_restored("0x04000007"))

    def test_closed_process_is_recoverable_not_desktop_failure(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.check_children(require_browser=False)
        with self.assertRaises(supervisor.BrowserUnavailable):
            runtime.check_children()
        runtime.shutdown = Mock()
        runtime.browser_unavailable(supervisor.BrowserUnavailable("closed"))
        runtime.shutdown.assert_not_called()
        runtime.write_status.assert_called_once_with("failed", "closed")

    def control_request(self, runtime, payload):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv = Mock(return_value=payload)
        runtime.control = Mock()
        runtime.control.accept.return_value = (connection, None)
        runtime.serve_control()
        return json.loads(connection.sendall.call_args.args[0])

    def test_fixed_command_only(self):
        for command in (b'{"command":"exec","args":["id"]}\n', b'{"command":"reconnect","url":"example"}\n', b'not json\n', b'x' * 129):
            runtime = supervisor.Supervisor()
            runtime.reconnect = Mock()
            response = self.control_request(runtime, command)
            self.assertFalse(response["ok"])
            runtime.reconnect.assert_not_called()

    def test_valid_control_command_explicitly_allows_a_bounded_extension_retry(self):
        runtime = supervisor.Supervisor()
        runtime.reconnect = Mock(return_value={"ok": True, "restarted": False, "engine_ready": True})
        response = self.control_request(runtime, b'{"command":"reconnect"}\n')
        self.assertTrue(response["ok"])
        runtime.reconnect.assert_called_once_with(allow_extension_retry=True)

    def test_reconnect_failure_reports_truth_without_killing_desktop(self):
        runtime, _ = self.ready_runtime()
        runtime.shutdown = Mock()
        runtime.wait_ready.side_effect = supervisor.BrowserUnavailable("Window never appeared")
        response = self.control_request(runtime, b'{"command":"reconnect"}\n')
        self.assertEqual(response, {"ok": False, "error": "Window never appeared"})
        runtime.write_status.assert_called_with("failed", "Window never appeared")
        runtime.shutdown.assert_not_called()
        runtime.restore_browser.assert_not_called()

    def test_window_command_failure_is_not_reported_as_success(self):
        runtime, _ = self.ready_runtime()
        runtime.restore_browser.side_effect = subprocess.CalledProcessError(1, ["wmctrl"])
        response = self.control_request(runtime, b'{"command": "reconnect"}\n')
        self.assertFalse(response["ok"])
        self.assertEqual(runtime.write_status.call_args.args[0], "failed")

    def test_missing_x_desktop_does_not_spawn(self):
        runtime, _ = self.ready_runtime(closed=True)
        runtime.display_ready.return_value = False
        runtime.spawn = Mock()
        response = self.control_request(runtime, b'{"command":"reconnect"}\n')
        self.assertFalse(response["ok"])
        runtime.spawn.assert_not_called()

class OwnedWindowProcessTests(unittest.TestCase):
    """Real owned child plus subprocess X-command model; never a Chrome/X probe."""
    def run_window_case(self, *, minimized=False, dead_launcher=False, engine=True, query_timeout=False, inventory="known", desktop=0):
        fixture = r'''import json, pathlib, sys, time
path=pathlib.Path(sys.argv[1]); command=sys.argv[2:]; state=json.loads(path.read_text())
if command == ['wmctrl', '-lx']:
    if state.get('query_timeout'): time.sleep(5)
    if state['inventory'] != 'empty':
        cls='custom.Browser' if state['inventory']=='unknown' else 'chromium.Chromium'
        print('0x04000007 '+str(state['desktop'])+' '+cls+' fixture Tabs preserved')
elif command[:1] == ['wmctrl']:
    if 'remove,fullscreen' in command: state['fullscreen']=False
    if 'add,maximized_vert,maximized_horz' in command: state['maximized']=True
    if '-ia' in command: state['minimized']=False; state['focused']=True
    path.write_text(json.dumps(state))
elif command[:3] == ['xprop','-id','0x04000007']:
    result='_NET_WM_STATE_MAXIMIZED_VERT, _NET_WM_STATE_MAXIMIZED_HORZ' if state['maximized'] else ''
    if state['minimized']: result+=', _NET_WM_STATE_HIDDEN'
    print('_NET_WM_STATE(ATOM) = '+result)
elif command == ['xprop','-root','_NET_CLIENT_LIST','_NET_CLIENT_LIST_STACKING']:
    print('_NET_CLIENT_LIST(WINDOW): window id # ')
    print('_NET_CLIENT_LIST_STACKING(WINDOW): window id # ')
elif command == ['xprop','-root','_NET_ACTIVE_WINDOW']:
    print('_NET_ACTIVE_WINDOW(WINDOW): window id # '+('0x4000007' if state['focused'] else '0x0'))
else: raise SystemExit('unexpected fixture command')
'''
        with tempfile.TemporaryDirectory(prefix='reconnect-window-') as directory:
            root = Path(directory)
            program = root / 'window_model.py'
            program.write_text(fixture)
            state_path = root / 'window.json'
            state_path.write_text(json.dumps({'tabs':['first.example','second.example'], 'minimized':minimized,
                                              'maximized':False, 'focused':False, 'fullscreen':True,
                                              'query_timeout':query_timeout, 'inventory':inventory, 'desktop':desktop}))
            owner = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            tracked = owner
            if dead_launcher:
                tracked = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(0)'])
                tracked.wait(timeout=3)
            runtime = supervisor.Supervisor()
            runtime.fido_control = None
            runtime.children = [('Xvfb', Mock(poll=Mock(return_value=None))), ('Chromium', tracked)]
            runtime.display_ready = Mock(return_value=True)
            runtime.vnc_ready = Mock(return_value=True)
            runtime.proxy_ready = Mock(return_value=engine)
            runtime.write_status = Mock()
            runtime.spawn = Mock(side_effect=AssertionError('A surviving window must not spawn a replacement'))
            real_run = subprocess.run
            def modeled_command(command, **options):
                self.assertIn(command[0], ('wmctrl', 'xprop'))
                return real_run([sys.executable, str(program), str(state_path), *command], **options)
            try:
                with patch.object(supervisor.subprocess, 'run', side_effect=modeled_command), patch.object(supervisor.os, 'killpg') as kill:
                    if query_timeout:
                        started = time.monotonic()
                        with self.assertRaises(subprocess.TimeoutExpired): runtime.reconnect()
                        self.assertLess(time.monotonic() - started, 4)
                    elif inventory != "known":
                        for _ in range(3):
                            with self.assertRaises((ValueError, supervisor.BrowserUnavailable)):
                                runtime.reconnect()
                            runtime.maintain_browser()
                            runtime.request_extension_upgrade()
                    else:
                        for _ in range(2):
                            result = runtime.reconnect()
                            self.assertEqual(result, {'ok':True,'restarted':False,'engine_ready':engine})
                            runtime.maintain_browser()
                        state = json.loads(state_path.read_text())
                        self.assertTrue(state['maximized'] and state['focused'])
                        self.assertFalse(state['minimized'] or state['fullscreen'])
                    self.assertEqual(json.loads(state_path.read_text())['tabs'], ['first.example','second.example'])
                    self.assertIsNone(owner.poll())
                    runtime.spawn.assert_not_called()
                    kill.assert_not_called()
            finally:
                owner.terminate(); owner.wait(timeout=3)

    def test_real_owned_healthy_window_repeated_restore_preserves_process_and_tabs(self):
        self.run_window_case()

    def test_real_owned_minimized_window_restores_without_engine(self):
        self.run_window_case(minimized=True, engine=False)

    def test_exited_launcher_with_surviving_window_stays_intact_on_later_ticks(self):
        self.run_window_case(dead_launcher=True, engine=False)

    def test_owned_minimized_all_desktop_window_is_restored(self):
        self.run_window_case(minimized=True, desktop=-1)

    def test_owned_window_on_other_desktop_is_restored(self):
        self.run_window_case(desktop=4)

    def test_unknown_class_surviving_exited_launcher_remains_intact(self):
        self.run_window_case(dead_launcher=True, inventory="unknown", engine=False)

    def test_live_owner_empty_window_inventory_never_opens_window(self):
        self.run_window_case(inventory="empty")

    def test_actual_window_query_subprocess_timeout_never_spawns_or_kills(self):
        self.run_window_case(query_timeout=True, dead_launcher=True)


if __name__ == "__main__":
    unittest.main()
