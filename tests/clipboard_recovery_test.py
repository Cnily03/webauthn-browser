"""Fault-injected clipboard recovery; no X server or clipboard contents required."""
import importlib.util
from pathlib import Path
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('clipboard_recovery_bridge', ROOT / 'runtime/clipboard_bridge.py')
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class ClipboardRecoveryTests(unittest.TestCase):
    def make_bridge(self):
        with patch.object(bridge.Bridge, 'connect_display'):
            item = bridge.Bridge()
        item.display = Mock()
        item.display.pending_events.return_value = 0
        item.window = Mock()
        item.XError = type('XError', (Exception,), {})
        return item

    def socket_path(self):
        path = Mock(spec=Path)
        path.is_symlink.return_value = False
        path.exists.return_value = False
        path.stat.return_value = SimpleNamespace(st_dev=1, st_ino=2)
        path.lstat.return_value = path.stat.return_value
        return path

    def test_constructor_failure_before_and_after_display_open_closes_resources(self):
        for phase in ('construction', 'extension', 'window', 'flush', 'sync'):
            with self.subTest(phase=phase):
                display = Mock()
                if phase == 'extension':
                    display.has_extension.side_effect = BrokenPipeError()
                elif phase == 'window':
                    display.screen.return_value.root.create_window.side_effect = BrokenPipeError()
                elif phase in ('flush', 'sync'):
                    getattr(display, phase).side_effect = BrokenPipeError()
                factory = Mock(return_value=display)
                if phase == 'construction':
                    factory.side_effect = BrokenPipeError()
                xlib = SimpleNamespace(X=Mock(), Xatom=Mock(), protocol=Mock(),
                    display=SimpleNamespace(Display=factory), error=SimpleNamespace(XError=Exception))
                with patch.dict('sys.modules', {'Xlib': xlib, 'Xlib.ext': SimpleNamespace(xfixes=Mock())}):
                    with self.assertRaises(BrokenPipeError):
                        bridge.Bridge()
                self.assertEqual(display.close.call_count, int(phase != 'construction'))
                display.screen.return_value.root.create_window.return_value.destroy.assert_not_called()

    def test_close_drops_every_session_payload_without_x_calls_even_if_close_fails(self):
        item = self.make_bridge()
        client, display, window = Mock(), item.display, item.window
        item.client = client
        client.close.side_effect = OSError()
        display.close.side_effect = BrokenPipeError()
        item.input.extend(b'private incoming')
        item.output.extend(b'private outgoing')
        item.input_deadline = item.output_deadline = 99
        item.requests.pending['old-id'] = ('old-event', 99)
        item.transfers['old-transfer'] = ('private transfer',)
        item.capture = {'window': Mock(), 'data': bytearray(b'private capture')}
        item.answer = Mock()
        item.requests.answer = item.answer
        item.close()
        item.close()
        item.disconnect()
        self.assertTrue(item.closed)
        self.assertEqual(item.requests.pending, {})
        self.assertEqual(item.transfers, {})
        self.assertIsNone(item.capture)
        self.assertEqual(item.input, b'')
        self.assertEqual(item.output, b'')
        self.assertIsNone(item.input_deadline)
        self.assertIsNone(item.output_deadline)
        self.assertIsNone(item.client)
        self.assertIsNone(item.display)
        item.requests.result({'id': 'old-id', 'text': 'late private text'})
        item.answer.assert_not_called()
        display.close.assert_called_once()
        display.flush.assert_not_called()
        window.destroy.assert_not_called()
        client.close.assert_called_once()

    def test_event_read_flush_and_select_failures_release_socket_and_state(self):
        for phase in ('pending', 'event', 'flush', 'select'):
            with self.subTest(phase=phase), patch.object(bridge.socket, 'socket') as socket_factory:
                item = self.make_bridge()
                display = item.display
                path = self.socket_path()
                if phase == 'pending':
                    display.pending_events.side_effect = BrokenPipeError()
                elif phase in ('event', 'flush'):
                    display.pending_events.return_value = 1
                    if phase == 'event':
                        display.next_event.side_effect = EOFError()
                    else:
                        item.event = lambda _: display.flush()
                        display.flush.side_effect = BrokenPipeError()
                with patch.object(bridge.select, 'select', side_effect=OSError()):
                    with self.assertRaises((OSError, EOFError)):
                        item.run(path)
                self.assertEqual(path.unlink.call_count, 2)
                socket_factory.return_value.close.assert_called_once()
                self.assertTrue(item.closed)
                display.close.assert_called_once()

    def test_bind_failure_still_closes_partial_listener_and_bridge(self):
        item = self.make_bridge()
        server = Mock()
        server.bind.side_effect = OSError()
        with patch.object(bridge.socket, 'socket', return_value=server):
            with self.assertRaises(OSError):
                item.run(self.socket_path())
        server.close.assert_called_once()
        self.assertTrue(item.closed)

    def test_cleanup_does_not_unlink_new_socket_generation(self):
        item = self.make_bridge()
        path = self.socket_path()
        def replace(*_):
            path.lstat.return_value = SimpleNamespace(st_dev=1, st_ino=3)
            raise BrokenPipeError()
        with patch.object(bridge.socket, 'socket'), patch.object(bridge.select, 'select', side_effect=replace):
            with self.assertRaises(BrokenPipeError):
                item.run(path)
        # Only the initial old-listener unlink, never the replacement.
        path.unlink.assert_called_once_with(missing_ok=True)

    def test_listener_and_path_cleanup_errors_do_not_mask_display_failure(self):
        item = self.make_bridge()
        item.display.pending_events.side_effect = EOFError('original display failure')
        path = self.socket_path()
        path.lstat.side_effect = OSError('runtime path unavailable')
        server = Mock()
        server.close.side_effect = OSError('listener close unavailable')
        with patch.object(bridge.socket, 'socket', return_value=server):
            with self.assertRaisesRegex(EOFError, 'original display failure'):
                item.run(path)
        self.assertTrue(item.closed)
        path.lstat.assert_called_once()

    def test_recovery_constructs_fresh_sessions_and_does_not_replay(self):
        first, second = self.make_bridge(), self.make_bridge()
        first.requests.pending['old-id'] = ('old-event', 99)
        first.input.extend(b'old private text')
        first.run = Mock(side_effect=BrokenPipeError())
        second.run = Mock()
        stopped = Mock()
        stopped.is_set.return_value = False
        stopped.wait.return_value = False
        factory = Mock(side_effect=[OSError(), first, second])
        bridge.run_service(stopped, factory, (OSError,))
        self.assertEqual(factory.call_count, 3)
        self.assertEqual([c.args[0] for c in stopped.wait.call_args_list], [0.25, 0.5])
        self.assertEqual(first.requests.pending, {})
        self.assertEqual(first.input, b'')
        self.assertEqual(second.requests.pending, {})
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_retry_delay_is_capped_and_stop_cancels(self):
        stopped = Mock()
        stopped.is_set.return_value = False
        stopped.wait.side_effect = [False] * 8 + [True]
        factory = Mock(side_effect=OSError())
        bridge.run_service(stopped, factory, (OSError,))
        self.assertEqual([c.args[0] for c in stopped.wait.call_args_list],
                         [.25, .5, 1, 2, 4, 5, 5, 5, 5])
        self.assertEqual(factory.call_count, 9)

    def test_stop_during_construction_prevents_listener_and_retry(self):
        stopped = threading.Event()
        item = self.make_bridge()
        item.run = Mock()
        def construct():
            stopped.set()
            return item
        bridge.run_service(stopped, construct, (OSError,))
        item.run.assert_not_called()
        self.assertTrue(item.closed)

    def test_stopped_service_never_constructs_and_live_loop_observes_stop(self):
        stopped = threading.Event()
        stopped.set()
        factory = Mock()
        bridge.run_service(stopped, factory, (OSError,))
        factory.assert_not_called()
        item = self.make_bridge()
        item.stop_event = stopped
        with patch.object(bridge.socket, 'socket'):
            item.run(self.socket_path())
        self.assertTrue(item.closed)
        item.requests.pending.clear()

    def test_stop_during_event_flood_exits_without_more_x_or_select_calls(self):
        item = self.make_bridge()
        display = item.display
        display.pending_events.return_value = 1
        item.event = Mock(side_effect=lambda _: item.stop_event.set())
        with patch.object(bridge.socket, 'socket'), patch.object(bridge.select, 'select') as select:
            item.run(self.socket_path())
        display.pending_events.assert_called_once()
        display.next_event.assert_called_once()
        select.assert_not_called()
        self.assertTrue(item.closed)

    def test_non_transport_errors_are_not_hidden(self):
        stopped = threading.Event()
        with self.assertRaisesRegex(RuntimeError, 'missing extension'):
            bridge.run_service(stopped, Mock(side_effect=RuntimeError('missing extension')), (OSError,))


if __name__ == '__main__':
    unittest.main()
