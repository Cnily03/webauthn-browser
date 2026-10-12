"""No display/socket needed: clipboard protocol state and runtime contracts."""
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('clipboard_bridge', ROOT / 'runtime/clipboard_bridge.py')
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class ClipboardRequestTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.answers = []
        self.now = 10
        self.requests = bridge.Requests(lambda value: self.sent.append(value) or True,
                                         lambda event, data: self.answers.append((event, data)),
                                         lambda: self.now)

    def request(self, event='event'):
        self.requests.request(event)
        return self.sent[-1]['id']

    def test_fresh_read_every_time_and_unicode(self):
        for text in ('first', '更新 😀\n', ''):
            key = self.request()
            self.requests.result({'type': 'read_result', 'id': key, 'text': text})
            self.assertEqual(self.answers[-1], ('event', text.encode()))
            self.assertEqual(self.requests.pending, {})
        self.assertEqual(len({item['id'] for item in self.sent}), 3)

    def test_permission_denial_does_not_reuse_previous_text(self):
        key = self.request()
        self.requests.result({'id': key, 'text': 'old secret'})
        key = self.request()
        self.requests.result({'id': key, 'error': 'denied'})
        self.assertEqual(self.answers[-1], ('event', None))
        self.assertEqual(self.requests.pending, {})
        self.assertNotIn('old secret', repr(vars(self.requests)))

    def test_timeout_and_late_reply(self):
        key = self.request()
        self.now += bridge.TIMEOUT
        self.requests.expire()
        self.requests.result({'id': key, 'text': 'late'})
        self.assertEqual(self.answers, [('event', None)])
        self.assertEqual(self.sent[-1], {'type': 'cancel', 'id': key})

    def test_expired_result_fails_without_tick(self):
        key = self.request()
        self.now += bridge.TIMEOUT
        self.requests.result({'id': key, 'text': 'late'})
        self.assertEqual(self.answers, [('event', None)])

    def test_disconnect_or_new_copy_cancels_every_pending_request(self):
        self.request('first')
        self.request('second')
        self.requests.expire(all_requests=True)
        self.assertEqual(self.answers, [('first', None), ('second', None)])
        self.assertEqual(self.requests.pending, {})

    def test_duplicate_and_unknown_results_ignored(self):
        key = self.request()
        self.requests.result({'id': 'unknown', 'text': 'unrequested'})
        self.requests.result({'id': key, 'text': 'good'})
        self.requests.result({'id': key, 'text': 'duplicate'})
        self.assertEqual(self.answers, [('event', b'good')])

    def test_payload_bound_and_invalid_unicode_fail_closed(self):
        for value in ('界' * (bridge.MAX_TEXT // 3 + 1), '\ud800', None, 123):
            key = self.request()
            self.requests.result({'id': key, 'text': value})
            self.assertEqual(self.answers[-1], ('event', None))

    def test_newer_read_cancels_older_pending_metadata(self):
        for index in range(bridge.MAX_PENDING + 1):
            self.requests.request(index)
        self.assertEqual(len(self.requests.pending), 1)
        self.assertEqual(self.answers, [(index, None) for index in range(bridge.MAX_PENDING)])

    def test_no_client_fails_immediately(self):
        self.requests.send = lambda _: False
        self.requests.request('paste')
        self.assertEqual(self.answers, [('paste', None)])
        self.assertEqual(self.requests.pending, {})

    def test_transport_disconnect_during_send_does_not_double_answer(self):
        self.requests.send = lambda _: False
        # A send implementation can synchronously revoke pending operations.
        first = True
        def reentrant(_):
            nonlocal first
            if first:
                first = False
                self.requests.expire(all_requests=True)
            return False
        self.requests.send = reentrant
        self.requests.request('paste')
        self.assertEqual(self.answers, [('paste', None)])

    def test_runtime_excludes_legacy_clipboard_and_packages_dependency(self):
        runtime = (ROOT / 'runtime/supervisor.py').read_text()
        self.assertIn('"-nosel"', runtime)
        self.assertIn('/opt/webauthn-browser/runtime/clipboard_bridge.py', runtime)
        self.assertIn('python3-xlib', (ROOT / 'Dockerfile').read_text())
        self.assertNotIn('clipboardRead', (ROOT / 'extension/manifest.json').read_text())


class ClipboardX11Tests(unittest.TestCase):
    def setUp(self):
        self.bridge = bridge.Bridge.__new__(bridge.Bridge)
        self.bridge.X = SimpleNamespace(NONE=0, CurrentTime=0, AnyPropertyType=0,
                                        PropertyChangeMask=1 << 22)
        self.bridge.Xatom = SimpleNamespace(ATOM=4)
        names = ('CLIPBOARD', 'TARGETS', 'UTF8_STRING', 'text/plain;charset=utf-8',
                 'text/plain', 'STRING', 'INCR', '_AUTH_BROWSER_COPY')
        self.bridge.atoms = {name: index + 10 for index, name in enumerate(names)}
        self.bridge.clipboard = self.bridge.atoms['CLIPBOARD']
        self.bridge.window = Mock(id=10)
        self.bridge.display = Mock()
        self.bridge.display.get_selection_owner.return_value = Mock(id=99)
        self.bridge.capture = None
        self.bridge.transfers = {}
        self.bridge.client = Mock()
        self.bridge.requests = Mock()
        self.bridge.notify = Mock()
        self.bridge.send = Mock(return_value=True)
        self.bridge.new_window = Mock(return_value=Mock(id=33))
        self.event = SimpleNamespace(selection=self.bridge.clipboard,
                                     target=self.bridge.atoms['UTF8_STRING'],
                                     property=77, requestor=Mock(id=30))

    def test_native_menu_targets_are_metadata_only(self):
        self.event.target = self.bridge.atoms['TARGETS']
        self.bridge.selection_request(self.event)
        self.bridge.requests.request.assert_not_called()
        self.event.requestor.change_property.assert_called_once()
        self.bridge.notify.assert_called_once_with(self.event, 77)

    def test_each_native_data_request_is_forwarded(self):
        self.bridge.selection_request(self.event)
        self.bridge.selection_request(self.event)
        self.assertEqual(self.bridge.requests.request.call_count, 2)

    def test_new_text_request_cancels_old_copy_capture_silently(self):
        window = Mock()
        self.bridge.capture = {'window': window, 'data': bytearray()}
        self.bridge.selection_request(self.event)
        window.destroy.assert_called_once()
        self.assertIsNone(self.bridge.capture)
        self.bridge.send.assert_not_called()
        self.bridge.requests.request.assert_called_once_with(self.event)

    def test_targets_metadata_does_not_cancel_copy_capture(self):
        window = Mock()
        self.bridge.capture = {'window': window, 'data': bytearray()}
        self.event.target = self.bridge.atoms['TARGETS']
        self.bridge.selection_request(self.event)
        window.destroy.assert_not_called()
        self.assertIsNotNone(self.bridge.capture)

    def test_denied_read_never_sets_x_property(self):
        self.bridge.answer(self.event, None)
        self.event.requestor.change_property.assert_not_called()
        self.bridge.notify.assert_called_once_with(self.event, 0)

    def test_utf8_is_byte_exact_and_not_retained(self):
        data = '界 😀'.encode()
        self.bridge.answer(self.event, data)
        self.event.requestor.change_property.assert_called_once_with(
            77, self.event.target, 8, data)
        self.assertEqual(self.bridge.transfers, {})

    def test_legacy_string_does_not_corrupt_unicode(self):
        self.event.target = self.bridge.atoms['STRING']
        self.bridge.answer(self.event, '界'.encode())
        self.event.requestor.change_property.assert_not_called()
        self.bridge.notify.assert_called_once_with(self.event, 0)

    def test_large_transfer_retains_only_active_payload_and_drops_on_finish(self):
        data = b'a' * (bridge.CHUNK + 1)
        self.bridge.answer(self.event, data)
        key = (30, 77)
        self.assertEqual(self.bridge.transfers[key][3], data)
        self.bridge.finish_transfer(key, self.bridge.transfers[key])
        self.assertEqual(self.bridge.transfers, {})
        self.event.requestor.change_property.assert_called_with(77, self.event.target, 8, b'')

    def test_remote_copy_requests_source_before_immediate_reclaim(self):
        ordered = Mock()
        capture_window = self.bridge.new_window.return_value
        ordered.attach_mock(capture_window.convert_selection, 'convert')
        ordered.attach_mock(self.bridge.window.set_selection_owner, 'own')
        self.bridge.remote_copy(SimpleNamespace(owner=Mock(id=99)))
        self.assertEqual([call[0] for call in ordered.mock_calls], ['convert', 'own'])
        self.bridge.requests.expire.assert_called_once_with(all_requests=True)
        self.assertEqual(self.bridge.capture['data'], b'')

    def test_stale_external_owner_event_does_not_read_our_own_selection(self):
        self.bridge.display.get_selection_owner.return_value = Mock(id=10)
        self.bridge.remote_copy(SimpleNamespace(owner=Mock(id=99)))
        self.bridge.new_window.assert_not_called()
        self.bridge.requests.expire.assert_not_called()

    def test_own_xfixes_echo_does_not_copy_or_read(self):
        self.bridge.remote_copy(SimpleNamespace(owner=Mock(id=10)))
        self.bridge.new_window.assert_not_called()
        self.bridge.requests.expire.assert_not_called()

    def test_remote_utf8_copy_is_sent_once_and_capture_destroyed(self):
        window = Mock()
        window.get_property.return_value = SimpleNamespace(
            property_type=self.bridge.atoms['UTF8_STRING'], format=8,
            bytes_after=0, value='远程 😀'.encode())
        self.bridge.capture = {'window': window, 'data': bytearray(), 'incr': False}
        self.bridge.capture_property()
        message = self.bridge.send.call_args.args[0]
        self.assertEqual((message['type'], message['text']), ('copy', '远程 😀'))
        self.assertIsNone(self.bridge.capture)
        window.destroy.assert_called_once()

    def test_oversized_remote_copy_discarded(self):
        window = Mock()
        window.get_property.return_value = SimpleNamespace(
            property_type=self.bridge.atoms['UTF8_STRING'], format=8,
            bytes_after=1, value=b'too big')
        self.bridge.capture = {'window': window, 'data': bytearray(), 'incr': False}
        self.bridge.capture_property()
        message = self.bridge.send.call_args.args[0]
        self.assertEqual((message['type'], message['error']), ('copy_failed', 'too_large'))
        self.assertNotIn('text', message)
        self.assertIsNone(self.bridge.capture)


    def test_invalid_remote_utf8_reports_failure_without_text(self):
        window = Mock()
        window.get_property.return_value = SimpleNamespace(
            property_type=self.bridge.atoms['UTF8_STRING'], format=8,
            bytes_after=0, value=b'\xff')
        self.bridge.capture = {'window': window, 'data': bytearray(), 'incr': False}
        self.bridge.capture_property()
        message = self.bridge.send.call_args.args[0]
        self.assertEqual((message['type'], message['error']), ('copy_failed', 'unavailable'))
        self.assertNotIn('text', message)
        self.assertIsNone(self.bridge.capture)

    def test_unsupported_remote_type_reports_failure(self):
        window = Mock()
        window.get_property.return_value = SimpleNamespace(
            property_type=999, format=32, bytes_after=0, value=[123])
        self.bridge.capture = {'window': window, 'data': bytearray(), 'incr': False}
        self.bridge.capture_property()
        self.assertEqual(self.bridge.send.call_args.args[0]['error'], 'unavailable')
        self.assertIsNone(self.bridge.capture)

    def test_canceled_capture_is_silent_and_later_failure_not_replayed(self):
        self.bridge.capture = {'window': Mock(), 'data': bytearray()}
        self.bridge.drop_capture()
        self.bridge.fail_capture()
        self.bridge.send.assert_not_called()

    def test_timeout_failure_drops_capture_once(self):
        self.bridge.capture = {'window': Mock(), 'data': bytearray()}
        self.bridge.fail_capture()
        self.bridge.fail_capture()
        self.bridge.send.assert_called_once()
        self.assertIsNone(self.bridge.capture)


if __name__ == '__main__':
    unittest.main()
