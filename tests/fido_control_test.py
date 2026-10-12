"""Simulated controller only: real Unix FDs, no Chromium/udev/device claims."""
import array
import contextlib
import io
from dataclasses import replace
import errno
import importlib.util
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fido_runtime_tests", ROOT / "runtime/supervisor.py")
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)
fido = supervisor._fido_control
Op = fido.Op
Frame = fido.Frame


class Clock:
    now = 10_000_000_000

    def __call__(self):
        return self.now


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        # Simulation is explicitly test-only and all synthetic readiness frames
        # are marked 0x81. There is no production env/CLI bypass.
        self.model = fido.FidoController("/test-only-hook", clock=self.clock, allow_simulation=True)
        self.children = {}
        self.sockets = []
        self.processes = {}
        for role in ("gateway", "browser"):
            _, control = self.model.prepare_child(role)
            self.sockets.append(control)
            self.children[role] = control
            process = Mock(poll=Mock(return_value=None))
            self.processes[role] = process
            self.model.child_started(role, process)
        self.hello = self.read("browser")
        self.assertEqual(self.read("gateway"), self.hello)
        self.assertEqual(self.hello.op, Op.HELLO)
        self.write("browser", replace(self.hello, op=Op.READY, flags=129))
        self.assertEqual(self.read("gateway").op, Op.READY)

    def test_transition_diagnostics_are_deduplicated_and_secret_free(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            unavailable = replace(self.hello, op=Op.UNAVAILABLE, flags=128)
            for _ in range(3):
                self.write("browser", unavailable)
                self.assertEqual(self.read("gateway").op, Op.UNAVAILABLE)
            self.write("browser", replace(self.hello, op=Op.READY, flags=129))
            self.assertEqual(self.read("gateway").op, Op.READY)
        text = output.getvalue()
        self.assertEqual(text.count("browser prerequisites unavailable"), 1)
        self.assertEqual(text.count("HID monitor READY"), 1)
        self.assertNotIn(self.hello.gateway_epoch.hex(), text)
        self.assertNotIn(self.hello.browser_epoch.hex(), text)
        self.assertNotIn("/test-only-hook", text)

    def test_ready_idle_never_allocates_report_endpoint_or_activates_device(self):
        # A browser-monitor READY is capability metadata, not Native authority.
        self.assertTrue(self.model.ready)
        self.assertIsNone(self.model.attachment)
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(40):
            self.clock.now += 1_000_000_000
            self.model.tick()
        self.assertIsNone(self.model.attachment)
        self.assertEqual(self.model.device_highwater, 0)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        for child in self.children.values():
            with self.assertRaises(BlockingIOError):
                child.recv(128)

    def tearDown(self):
        self.model.close()
        for sock in self.sockets:
            sock.close()

    def read(self, role):
        frame, endpoint = fido.receive_frame(self.children[role], allow_simulation=True)
        if endpoint is not None:
            self.sockets.append(endpoint)
        self.last_endpoint = endpoint
        return frame

    def write(self, role, frame, endpoint=None):
        fido.send_frame(self.children[role], frame, endpoint, allow_simulation=True)
        self.model.tick()

    def prepare(self, generation=1):
        local, remote = fido.control_pair()
        self.sockets.extend((local, remote))
        frame = Frame(Op.PREPARE, *self.model.scope, bytes([generation]) * 16,
                      generation, 7, self.clock.now + 10_000_000_000)
        self.write("gateway", frame, remote)
        self.assertEqual(self.read("browser"), frame)
        return frame, local, self.last_endpoint

    def activate(self, generation=1):
        frame, local, remote = self.prepare(generation)
        self.write("browser", replace(frame, op=Op.PREPARED, flags=129))
        self.assertEqual(self.read("gateway").op, Op.PREPARED)
        self.write("gateway", replace(frame, op=Op.ACTIVATE))
        self.assertEqual(self.read("browser").op, Op.ACTIVATE)
        self.write("browser", replace(frame, op=Op.ACTIVE, flags=129))
        self.assertEqual(self.read("gateway").op, Op.ACTIVE)
        return frame, local, remote

    def test_wire_round_trip_exact_layout_and_reserved_fields(self):
        frame = Frame(Op.PREPARE, b'g' * 16, b'b' * 16, b'a' * 16, 0x102, 0x304, 0x506)
        encoded = frame.encode()
        self.assertEqual(len(encoded), 96)
        self.assertEqual(encoded[:8], b'UFHC\x01\x03\x00\x00')
        self.assertEqual(encoded[56:64], bytes.fromhex('0000000000000102'))
        self.assertEqual(encoded[72:80], bytes.fromhex('0000000000000506'))
        self.assertEqual(Frame.decode(encoded), frame)
        for offset in (0, 4, 5, 6, 7, 88, 95):
            bad = bytearray(encoded)
            bad[offset] = 255
            with self.subTest(offset=offset), self.assertRaises(fido.ProtocolError):
                Frame.decode(bad)
        for data in (encoded[:-1], encoded + b'x'):
            with self.assertRaises(fido.ProtocolError):
                Frame.decode(data)

    def test_simulation_cannot_be_accepted_by_production_decoder(self):
        ready = replace(self.hello, op=Op.READY, flags=129)
        raw = ready.encode(allow_simulation=True)
        with self.assertRaises(fido.ProtocolError):
            Frame.decode(raw)
        self.assertEqual(Frame.decode(raw, True), ready)
        for op in (Op.READY, Op.PREPARED, Op.ACTIVE, Op.RENEWED):
            frame = ready if op == Op.READY else Frame(op, *self.model.scope, b'x' * 16, 1, 1, 20,
                                                      1 if op == Op.RENEWED else 0, 1)
            for flag in (0, 2, 128, 255):
                with self.subTest(op=op, flag=flag), self.assertRaises(fido.ProtocolError):
                    replace(frame, flags=flag).encode(True)
        for op in (Op.HELLO, Op.READY, Op.UNAVAILABLE):
            with self.assertRaises(fido.ProtocolError):
                replace(self.hello, op=op, attachment_id=b'x' * 16).encode(True)

    def test_repeated_generations_use_new_connected_endpoints(self):
        for generation in (1, 2, 3):
            frame, local, remote = self.activate(generation)
            self.assertEqual(self.model.attachment.phase, "active")
            local.send(b'A' * 64)
            self.assertEqual(remote.recv(64), b'A' * 64)
            remote.send(b'B' * 64)
            self.assertEqual(local.recv(64), b'B' * 64)
            self.write("gateway", replace(frame, op=Op.REVOKE))
            self.assertEqual(self.read("browser").op, Op.REVOKE)
            self.assertEqual(local.recv(64), b'')
            self.write("browser", replace(frame, op=Op.REVOKED))
            self.assertEqual(self.read("gateway").op, Op.REVOKED)
            self.assertIsNone(self.model.attachment)
        self.assertEqual(self.model.device_highwater, 3)

    def test_renewal_waits_for_exact_ack_and_keeps_same_endpoint(self):
        frame, local, remote = self.activate()
        inode = os.fstat(self.model.attachment.endpoint.fileno()).st_ino
        renewal = replace(frame, op=Op.RENEW, deadline_ns=frame.deadline_ns + 5_000_000_000, lease_sequence=1)
        self.write("gateway", renewal)
        self.assertEqual(self.read("browser"), renewal)
        self.assertEqual(self.model.attachment.frame.deadline_ns, frame.deadline_ns)
        self.write("browser", replace(renewal, op=Op.RENEWED, flags=129))
        self.assertEqual(self.read("gateway").op, Op.RENEWED)
        self.assertEqual(self.model.attachment.frame.deadline_ns, renewal.deadline_ns)
        self.assertEqual(os.fstat(self.model.attachment.endpoint.fileno()).st_ino, inode)
        self.assertEqual(self.model.attachment.frame.device_generation, 1)
        local.send(b'r' * 64)
        self.assertEqual(remote.recv(64), b'r' * 64)
        self.write("gateway", replace(renewal, op=Op.REVOKE))
        self.assertEqual(self.read("browser").lease_sequence, 1)
        self.write("browser", replace(renewal, op=Op.REVOKED))
        self.assertEqual(self.read("gateway").op, Op.REVOKED)

    def test_pending_renewal_cancel_accepts_matching_identity_without_lease_ack(self):
        frame, local, _ = self.activate()
        renewal = replace(frame, op=Op.RENEW, deadline_ns=frame.deadline_ns + 5_000_000_000, lease_sequence=1)
        self.write("gateway", renewal)
        self.read("browser")
        self.write("gateway", replace(frame, op=Op.REVOKE))
        self.assertEqual(self.read("browser").op, Op.REVOKE)
        self.assertEqual(local.recv(64), b'')
        # Hook may have adopted the renewal while its acknowledgement was in
        # flight. Its terminal response still matches the full record identity.
        self.write("browser", replace(renewal, op=Op.REVOKED))
        self.assertEqual(self.read("gateway").op, Op.REVOKED)
        self.assertIsNone(self.model.attachment)

    def test_rejected_future_prepare_closes_gateway_without_adopting_fd(self):
        local, remote = fido.control_pair()
        self.sockets.extend((local, remote))
        frame = Frame(Op.PREPARE, *self.model.scope, b'x' * 16, 1, 7,
                      self.clock.now + fido.MAX_LEASE_NS + 1)
        self.write("gateway", frame, remote)
        self.assertNotIn("gateway", self.model.peers)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(self.model.device_highwater, 0)

    def test_shutdown_retires_both_controls_and_attachment(self):
        _, local, _ = self.activate()
        self.model.close()
        self.assertEqual(self.model.peers, {})
        self.assertIsNone(self.model.scope)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')

    def test_delayed_renew_ack_after_old_deadline_never_revives(self):
        frame, local, _ = self.activate()
        renewal = replace(frame, op=Op.RENEW, deadline_ns=frame.deadline_ns + 5_000_000_000, lease_sequence=1)
        self.write("gateway", renewal)
        self.read("browser")
        self.clock.now = frame.deadline_ns
        self.write("browser", replace(renewal, op=Op.RENEWED, flags=129))
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')
        self.assertEqual(self.read("gateway").op, Op.REVOKED)
        self.assertEqual(self.read("browser").op, Op.REVOKE)

    def test_expiry_is_independent_of_any_child_message(self):
        frame, local, _ = self.activate()
        self.clock.now = frame.deadline_ns
        self.model.tick()
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')
        self.assertEqual(self.read("browser").op, Op.REVOKE)

    def test_old_ack_cannot_cancel_or_revive_new_generation(self):
        first, _, _ = self.activate()
        self.write("gateway", replace(first, op=Op.REVOKE))
        self.read("browser")
        self.write("browser", replace(first, op=Op.REVOKED))
        self.read("gateway")
        second, local, remote = self.activate(2)
        self.write("browser", replace(first, op=Op.ACTIVE, flags=129))
        self.assertEqual(self.model.attachment.frame.identity(), second.identity())
        local.send(b'z' * 64)
        self.assertEqual(remote.recv(64), b'z' * 64)

    def test_reused_generation_is_rejected_after_revoke(self):
        frame, _, _ = self.activate()
        self.write("gateway", replace(frame, op=Op.REVOKE))
        self.read("browser")
        self.write("browser", replace(frame, op=Op.REVOKED))
        self.read("gateway")
        local, remote = fido.control_pair()
        self.sockets.extend((local, remote))
        self.write("gateway", replace(frame, attachment_id=b'n' * 16), remote)
        self.assertNotIn("gateway", self.model.peers)
        self.assertIsNone(self.model.attachment)

    def test_child_exit_shutdowns_revocation_duplicate(self):
        _, local, _ = self.activate()
        fd = self.model.attachment.endpoint.fileno()
        self.processes["browser"].poll.return_value = 1
        self.model.tick()
        self.assertNotIn("browser", self.model.peers)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_control_eof_and_unknown_frame_retire_active_attachment(self):
        for eof in (False, True):
            with self.subTest(eof=eof):
                if eof:
                    # Restore a fresh browser scope after the malformed frame.
                    self.reconnect_role("browser")
                _, local, _ = self.activate(2 if eof else 1)
                if eof:
                    self.children["browser"].close()
                else:
                    self.children["browser"].send(b'invalid frame')
                self.model.tick()
                self.assertNotIn("browser", self.model.peers)
                self.assertIsNone(self.model.attachment)
                self.assertEqual(local.recv(64), b'')

    def reconnect_role(self, role):
        other = "browser" if role == "gateway" else "gateway"
        self.model.retire(role)
        # Drain terminal notifications before the fresh Hello.
        while True:
            try:
                self.read(other)
            except BlockingIOError:
                break
        _, control = self.model.prepare_child(role)
        self.sockets.append(control)
        self.children[role] = control
        self.model.child_started(role, Mock(poll=Mock(return_value=None)))
        hello = self.read("browser")
        self.assertEqual(self.read("gateway"), hello)
        self.write("browser", replace(hello, op=Op.READY, flags=129))
        self.read("gateway")
        return hello

    def test_independent_restarts_rescope_without_restarting_other_child(self):
        first, local, _ = self.activate()
        gateway = self.processes["gateway"]
        hello = self.reconnect_role("browser")
        self.assertEqual(local.recv(64), b'')
        self.assertEqual(hello.gateway_epoch, first.gateway_epoch)
        self.assertNotEqual(hello.browser_epoch, first.browser_epoch)
        self.assertIs(self.model.peers["gateway"].process, gateway)
        self.activate(2)
        hello2 = self.reconnect_role("gateway")
        self.assertNotEqual(hello2.gateway_epoch, hello.gateway_epoch)
        self.assertEqual(hello2.browser_epoch, hello.browser_epoch)
        self.activate(1)

    def test_bad_deadline_and_bad_renewal_close_capability(self):
        frame, local, _ = self.activate()
        bad = replace(frame, op=Op.RENEW, deadline_ns=self.clock.now + fido.MAX_LEASE_NS + 1, lease_sequence=1)
        self.write("gateway", bad)
        self.assertNotIn("gateway", self.model.peers)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')

    def test_no_uncertain_retry_after_send_queue_saturation(self):
        frame, local, _ = self.activate()
        control = self.model.peers["browser"].control
        control.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        while True:
            try:
                control.send(bytes(96))
            except BlockingIOError:
                break
        self.write("gateway", replace(frame, op=Op.RENEW, deadline_ns=frame.deadline_ns + 1, lease_sequence=1))
        self.assertNotIn("browser", self.model.peers)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')

    def test_pending_second_prepare_is_terminal(self):
        _, local, _ = self.prepare()
        own, remote = fido.control_pair()
        self.sockets.extend((own, remote))
        frame = Frame(Op.PREPARE, *self.model.scope, b'2' * 16, 2, 7, self.clock.now + 1_000_000_000)
        self.write("gateway", frame, remote)
        self.assertNotIn("gateway", self.model.peers)
        self.assertIsNone(self.model.attachment)
        self.assertEqual(local.recv(64), b'')


class AncillaryTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = fido.control_pair()
        self.peer, self.endpoint = fido.control_pair()
        self.frame = Frame(Op.PREPARE, b'g' * 16, b'b' * 16, b'a' * 16, 1, 1, 20)

    def tearDown(self):
        for item in (self.a, self.b, self.peer, self.endpoint):
            item.close()

    def fd_count(self):
        return len(os.listdir('/proc/self/fd'))

    def test_rights_are_cloexec_and_original_may_close(self):
        fido.send_frame(self.a, self.frame, self.endpoint)
        self.endpoint.close()
        frame, endpoint = fido.receive_frame(self.b)
        with endpoint:
            self.assertEqual(frame, self.frame)
            self.assertFalse(endpoint.get_inheritable())
            endpoint.send(b'x' * 64)
            self.assertEqual(self.peer.recv(64), b'x' * 64)

    def test_extra_rights_and_data_truncation_never_leak(self):
        for count, oversized in ((2, False), (40, False), (1, True)):
            with self.subTest(count=count, oversized=oversized):
                before = self.fd_count()
                self.a.sendmsg([self.frame.encode() + (b'x' if oversized else b'')],
                               [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                 array.array('i', [self.endpoint.fileno()] * count))])
                with self.assertRaises(fido.ProtocolError):
                    fido.receive_frame(self.b)
                self.assertEqual(self.fd_count(), before)

    def test_unknown_ancillary_credentials_are_rejected_with_rights_closed(self):
        self.b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        before = self.fd_count()
        fido.send_frame(self.a, self.frame, self.endpoint)
        with self.assertRaises(fido.ProtocolError):
            fido.receive_frame(self.b)
        self.assertEqual(self.fd_count(), before)

    def test_missing_rights_or_rights_on_non_prepare_rejected(self):
        self.a.send(self.frame.encode())
        with self.assertRaises(fido.ProtocolError):
            fido.receive_frame(self.b)
        before = self.fd_count()
        self.a.sendmsg([replace(self.frame, op=Op.ACTIVATE).encode()],
                       [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [self.endpoint.fileno()]))])
        with self.assertRaises(fido.ProtocolError):
            fido.receive_frame(self.b)
        self.assertEqual(self.fd_count(), before)

    def assert_rejects_fd(self, fd):
        before = self.fd_count()
        self.a.sendmsg([self.frame.encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                              array.array('i', [fd]))])
        with self.assertRaises((OSError, fido.ProtocolError)):
            fido.receive_frame(self.b)
        self.assertEqual(self.fd_count(), before)

    def test_regular_file_is_rejected_and_closed(self):
        with tempfile.TemporaryFile() as ordinary:
            self.assert_rejects_fd(ordinary.fileno())

    @unittest.skipUnless(os.environ.get('AUTH_BROWSER_TEST_UNCONNECTED_SOCKETS') == '1',
                         'unconnected socket construction denied in this sandbox; explicit capable test environment required')
    def test_stream_unconnected_and_inet_fds_are_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream, \
                socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as unconnected, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as inet:
            for item in (stream, unconnected, inet):
                self.assert_rejects_fd(item.fileno())


class LaunchTests(unittest.TestCase):
    def test_packaged_startup_prepares_control_without_hidden_flag(self):
        with patch.object(fido, 'verify_elf', side_effect=lambda path, **_kwargs: path) as verify:
            model = fido.FidoController.from_environment({})
            self.assertIsNotNone(model)
            self.assertEqual(model.hook_path, fido.DEFAULT_HOOK_PATH)
            self.assertFalse(model.allow_simulation)
            self.assertFalse(model.ready)
            self.assertIsNone(model.attachment)
            self.assertEqual(model.peers, {})
            self.assertEqual([call.args[0] for call in verify.call_args_list],
                             [fido.DEFAULT_HOOK_PATH, fido.NATIVE_CHROMIUM])
            model.close()

    def test_explicit_disable_or_malformed_override_never_prepares_control(self):
        for value in ('0', 'true', '', 'yes', '2'):
            with patch.object(fido, 'verify_elf') as verify:
                self.assertIsNone(fido.FidoController.from_environment({
                    'AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY': value}))
                verify.assert_not_called()

    def test_missing_or_invalid_package_is_observable_and_fails_closed(self):
        for failure in (OSError('missing'), ValueError('wrong architecture')):
            with patch.object(fido, 'verify_elf', side_effect=failure), \
                    patch.object(fido, 'print') as warning:
                self.assertIsNone(fido.FidoController.from_environment({}))
                self.assertIn('Native USB preparation unavailable', warning.call_args.args[0])
                self.assertIn('software and BLE remain available', warning.call_args.args[0])

    def test_environment_cannot_enable_simulation_on_automatic_startup(self):
        with patch.object(fido, 'verify_elf', return_value='/trusted/hook.so'):
            model = fido.FidoController.from_environment({
                fido.HOOK_PATH_ENV: '/trusted/hook.so',
                'AUTH_BROWSER_FIDO_SIMULATION': '1', 'UHF_SIMULATION': '1'})
            self.assertFalse(model.allow_simulation)
            model.close()

    def test_ordinary_supervisor_startup_enables_gateway_only_with_control_fd(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(fido, 'verify_elf', side_effect=lambda path, **_kwargs: path):
            runtime = supervisor.Supervisor()
            self.assertIsNotNone(runtime.fido_control)
            self.addCleanup(runtime.fido_control.close)
            with patch.object(supervisor.subprocess, 'Popen') as launch:
                runtime.spawn('gateway', ['/usr/local/bin/webauthn-browser'])
            options = launch.call_args.kwargs
            self.assertEqual(options['env']['AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY'], '1')
            self.assertEqual(options['pass_fds'], (int(options['env']['AUTH_BROWSER_FIDO_CONTROL_FD']),))
            self.assertNotIn('LD_PRELOAD', options['env'])
            self.assertIsNone(runtime.fido_control.attachment)
            self.assertNotIn('AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY', os.environ)

    def runtime(self):
        with patch.dict(os.environ, {}, clear=True):
            runtime = supervisor.Supervisor()
        runtime.fido_control = fido.FidoController('/trusted/hook.so')
        self.addCleanup(runtime.fido_control.close)
        return runtime

    def test_only_native_browser_gets_hook_and_descriptors_are_child_only(self):
        runtime = self.runtime()
        seen = []
        original = dict(os.environ)
        inherited = {'AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY': '1', 'UHF_OWNER_PID': '999',
                     'UHF_RELAY_FD': '88', 'AUTH_BROWSER_FIDO_CONTROL_FD': '77', 'LD_PRELOAD': '/old.so'}
        def popen(command, **options):
            seen.append((command, options.copy()))
            for fd in options.get('pass_fds', ()):
                self.assertFalse(os.get_inheritable(fd))
                self.assertFalse(os.get_blocking(fd))
            return Mock(poll=Mock(return_value=None))
        def cdp_spawn(command, environment, inherited_fds):
            return popen(command, env=environment, pass_fds=tuple(inherited_fds.values())), Mock()
        with patch.dict(os.environ, inherited), patch.object(fido, 'verify_elf'), \
                patch.object(supervisor, 'verify_browser_executable'), patch.object(supervisor._browser_cdp, 'spawn', side_effect=cdp_spawn), \
                patch.object(supervisor.subprocess, 'run'), patch.object(supervisor.subprocess, 'Popen', side_effect=popen):
            runtime.spawn('gateway', ['/usr/local/bin/webauthn-browser'])
            runtime.spawn('Chromium', runtime.browser_command())
            runtime.spawn('Chromium window launcher', runtime.browser_command(new_window=True))
            runtime.spawn('Openbox', ['openbox'])
            self.assertEqual(os.environ['LD_PRELOAD'], '/old.so')
        self.assertEqual(dict(os.environ), original)
        gateway, browser, secondary, other = seen
        self.assertNotIn('LD_PRELOAD', gateway[1]['env'])
        self.assertEqual(gateway[1]['env']['AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY'], '1')
        self.assertFalse(any(key.startswith('UHF_') for key in gateway[1]['env']))
        self.assertEqual(browser[0][0], fido.NATIVE_CHROMIUM)
        self.assertIn('--remote-debugging-pipe', browser[0])
        self.assertEqual(browser[1]['env']['LD_PRELOAD'], '/trusted/hook.so')
        self.assertEqual(browser[1]['env']['UHF_ENABLE'], '1')
        self.assertEqual(len(browser[1]['env']['UHF_BROWSER_EPOCH']), 32)
        self.assertNotIn('UHF_OWNER_PID', browser[1]['env'])
        self.assertNotIn('AUTH_BROWSER_FIDO_CONTROL_FD', browser[1]['env'])
        self.assertEqual(secondary[0][0], '/usr/bin/chromium')
        for command, options in (secondary, other):
            self.assertNotIn('pass_fds', options)
            self.assertNotIn('AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY', options['env'])
            self.assertNotIn('LD_PRELOAD', options['env'])
            self.assertNotIn('UHF_CONTROL_FD', options['env'])
        for _, options in (gateway, browser):
            with self.assertRaises(OSError):
                os.fstat(options['pass_fds'][0])
        self.assertNotEqual(gateway[1]['env']['AUTH_BROWSER_FIDO_GATEWAY_EPOCH'], browser[1]['env']['UHF_BROWSER_EPOCH'])

    def test_failed_hook_checks_keep_native_browser_with_no_hook_capability(self):
        runtime = self.runtime()
        with patch.object(fido, 'verify_elf', side_effect=ValueError('unsafe')), \
                patch.object(supervisor, 'verify_browser_executable'), patch.object(supervisor.subprocess, 'run'), \
                patch.object(supervisor._browser_cdp, 'spawn', return_value=(Mock(poll=Mock(return_value=None)), Mock())) as launch:
            runtime.start_browser()
        self.assertEqual(launch.call_args.args[0][0], fido.NATIVE_CHROMIUM)
        self.assertIn('--remote-debugging-pipe', launch.call_args.args[0])
        self.assertEqual(launch.call_args.kwargs['inherited_fds'], {})
        self.assertNotIn('LD_PRELOAD', launch.call_args.args[1])
        self.assertNotIn('browser', runtime.fido_control.peers)

    def test_failed_exec_closes_both_control_copies(self):
        runtime = self.runtime()
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(supervisor.subprocess, 'Popen', side_effect=OSError('exec failed')):
            with self.assertRaises(OSError):
                runtime.spawn('gateway', ['/missing'])
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertNotIn('gateway', runtime.fido_control.peers)

    def test_promoted_secondary_loses_experimental_capability(self):
        runtime = self.runtime()
        _, peer = runtime.fido_control.prepare_child('browser')
        self.addCleanup(peer.close)
        old = Mock(poll=Mock(return_value=0))
        launcher = Mock(poll=Mock(return_value=None))
        runtime.children = [('Chromium', old), ('Chromium window launcher', launcher)]
        runtime.reap_window_launcher()
        self.assertEqual(runtime.children, [('Chromium', launcher)])
        self.assertNotIn('browser', runtime.fido_control.peers)
        self.assertEqual(peer.recv(96), b'')

    def test_default_spawn_still_uses_original_popen_contract(self):
        with patch.dict(os.environ, {}, clear=True):
            runtime = supervisor.Supervisor()
        with patch.object(supervisor.subprocess, 'Popen') as popen:
            runtime.spawn('gateway', ['/normal'])
        popen.assert_called_once_with(['/normal'], start_new_session=True)

    def test_static_elf_checks_reject_privilege_symlinks_and_wrong_arch(self):
        # Synthetic ELF headers are used only for static validation, never run.
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'hook.so'
            header = bytearray(64)
            header[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HHI', header, 16, 3, 62, 1)
            struct.pack_into('<H', header, 52, 64)
            path.write_bytes(header)
            path.chmod(0o700)
            self.assertEqual(fido.verify_elf(str(path), library=True), str(path))
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                fido.verify_elf(str(link), library=True)
            for mode in (0o4700, 0o2700, 0o722):
                path.chmod(mode)
                with self.assertRaises(ValueError):
                    fido.verify_elf(str(path), library=True)
            path.chmod(0o700)
            with patch.object(fido.os, 'getxattr', return_value=b'capability'):
                with self.assertRaises(ValueError):
                    fido.verify_elf(str(path), library=True)
            with patch.object(fido.os, 'getxattr', side_effect=OSError(errno.EPERM, 'denied')):
                with self.assertRaises(ValueError):
                    fido.verify_elf(str(path), library=True)
            header[18] = 183
            path.write_bytes(header)
            with self.assertRaises(ValueError):
                fido.verify_elf(str(path), library=True)


def simulated_child(role, fd):
    """Actual child-process simulation with explicitly marked fake readiness."""
    inherited_sockets = []
    for name in os.listdir('/proc/self/fd'):
        try:
            if stat.S_ISSOCK(os.fstat(int(name)).st_mode):
                inherited_sockets.append(int(name))
        except OSError:
            pass
    assert inherited_sockets == [fd], inherited_sockets
    control = socket.socket(fileno=fd)
    control.setblocking(True)
    control.settimeout(3)
    def receive():
        # receive_frame intentionally requests DONTWAIT; wait for readability.
        import select
        if not select.select([control], [], [], 3)[0]:
            raise RuntimeError('simulated child control timeout')
        return fido.receive_frame(control, allow_simulation=True)
    def send(frame, endpoint=None):
        fido.send_frame(control, frame, endpoint, allow_simulation=True)
    hello, _ = receive()
    assert hello.op == Op.HELLO
    if role == 'browser':
        send(replace(hello, op=Op.READY, flags=129))
        for generation in (1, 2):
            frame, endpoint = receive()
            assert frame.op == Op.PREPARE and frame.device_generation == generation
            with endpoint:
                send(replace(frame, op=Op.PREPARED, flags=129))
                active, _ = receive()
                assert active.op == Op.ACTIVATE
                send(replace(active, op=Op.ACTIVE, flags=129))
                endpoint.settimeout(3)
                report = endpoint.recv(64)
                assert report == bytes([generation]) * 64
                endpoint.send(report[::-1])
                renewal, _ = receive()
                assert renewal.op == Op.RENEW
                send(replace(renewal, op=Op.RENEWED, flags=129))
                revoked, _ = receive()
                assert revoked.op == Op.REVOKE
                send(replace(revoked, op=Op.REVOKED))
        print('simulated browser: two generations, renewal and revoke', flush=True)
    else:
        ready, _ = receive()
        assert ready.op == Op.READY and ready.flags == 129
        for generation in (1, 2):
            local, remote = fido.control_pair()
            with local, remote:
                frame = Frame(Op.PREPARE, hello.gateway_epoch, hello.browser_epoch,
                              bytes([generation]) * 16, generation, 1, time.monotonic_ns() + 5_000_000_000)
                send(frame, remote)
                remote.close()
                prepared, _ = receive()
                assert prepared.op == Op.PREPARED
                send(replace(frame, op=Op.ACTIVATE))
                active, _ = receive()
                assert active.op == Op.ACTIVE
                local.settimeout(3)
                local.send(bytes([generation]) * 64)
                assert local.recv(64) == bytes([generation]) * 64
                renewal = replace(frame, op=Op.RENEW, lease_sequence=1, deadline_ns=frame.deadline_ns + 1_000_000_000)
                send(renewal)
                renewed, _ = receive()
                assert renewed.op == Op.RENEWED and renewed.lease_sequence == 1
                send(replace(renewal, op=Op.REVOKE))
                revoked, _ = receive()
                assert revoked.op == Op.REVOKED
        print('simulated gateway: real SCM_RIGHTS report exchange', flush=True)
    control.close()


class SubprocessTests(unittest.TestCase):
    def test_simulated_children_pass_actual_rights_across_two_generations(self):
        model = fido.FidoController('/test-only-hook', allow_simulation=True)
        processes = []
        try:
            for role in ('gateway', 'browser'):
                _, child = model.prepare_child(role)
                try:
                    process = subprocess.Popen([sys.executable, __file__, '--simulated-child', role, str(child.fileno())],
                                               pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               text=True)
                finally:
                    child.close()
                processes.append(process)
                model.child_started(role, process)
            deadline = time.monotonic() + 10
            while any(process.poll() is None for process in processes) and time.monotonic() < deadline:
                model.tick()
                time.sleep(0.002)
            for process in processes:
                output, errors = process.communicate(timeout=1)
                self.assertEqual(process.returncode, 0, output + errors)
                self.assertIn('simulated', output)
            model.tick()
            self.assertIsNone(model.attachment)
        finally:
            model.close()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--simulated-child':
        simulated_child(sys.argv[2], int(sys.argv[3]))
    else:
        unittest.main()
