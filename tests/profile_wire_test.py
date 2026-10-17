"""Actual local socketpair/SCM_RIGHTS fixtures; no services or devices run."""
import array
import importlib.util
import json
import os
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_profile_wire", ROOT / "runtime/profile_wire.py")
wire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wire)


class ProfileWireTests(unittest.TestCase):
    def pair(self, kind=socket.SOCK_STREAM):
        sender, receiver = socket.socketpair(socket.AF_UNIX, kind)
        for endpoint in (sender, receiver):
            endpoint.settimeout(1)
            self.addCleanup(endpoint.close)
        return sender, receiver

    @staticmethod
    def fd_count():
        return len(os.listdir("/proc/self/fd"))

    def send_rights(self, sender, payload, descriptor, count=1):
        return sender.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                          array.array("i", [descriptor] * count))])

    def test_stream_and_packet_roundtrip_without_descriptors(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            with self.subTest(kind=kind):
                sender, receiver = self.pair(kind)
                value = {"op": "prepare", "profile_id": "default", "value": "中文", "enabled": True}
                wire.send(sender, value)
                self.assertEqual(wire.receive(receiver), (value, []))

    def test_stream_and_packet_descriptors_are_cloexec_and_have_independent_ownership(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            with self.subTest(kind=kind):
                sender, receiver = self.pair(kind)
                original, peer = self.pair()
                wire.send(sender, {"op": "attach"}, original.fileno())
                value, rights = wire.receive(receiver, allow_rights=True)
                self.assertEqual(value, {"op": "attach"})
                self.assertEqual(len(rights), 1)
                descriptor = rights[0]
                try:
                    self.assertFalse(os.get_inheritable(descriptor))
                    self.assertNotEqual(descriptor, original.fileno())
                    original.close()
                    os.write(descriptor, b"fixture")
                    self.assertEqual(peer.recv(7), b"fixture")
                finally:
                    wire.close_rights(rights)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_allow_rights_does_not_require_descriptor(self):
        sender, receiver = self.pair()
        wire.send(sender, {"ok": True})
        self.assertEqual(wire.receive(receiver, allow_rights=True), ({"ok": True}, []))

    def test_fragmented_stream_record_is_reassembled(self):
        sender, receiver = self.pair()
        source, _ = self.pair()
        sender.sendall(b'{"op":')
        # Ancillary messages establish a receive boundary on AF_UNIX streams;
        # the first recvmsg can return the prefix, with the remainder next.
        self.send_rights(sender, b'"attach"}\n', source.fileno())
        value, rights = wire.receive(receiver, allow_rights=True)
        try:
            self.assertEqual(value, {"op": "attach"})
            self.assertEqual(len(rights), 1)
            self.assertFalse(os.get_inheritable(rights[0]))
        finally:
            wire.close_rights(rights)

    def test_exact_record_limit_succeeds_and_larger_record_fails(self):
        overhead = len(json.dumps({"x": ""}, separators=(",", ":")).encode()) + 1
        value = {"x": "a" * (wire.MAX_RECORD - overhead)}
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            with self.subTest(kind=kind):
                sender, receiver = self.pair(kind)
                wire.send(sender, value)
                self.assertEqual(wire.receive(receiver), (value, []))
                with self.assertRaises(wire.ProtocolError):
                    wire.send(sender, {"x": value["x"] + "a"})

    def test_oversized_received_record_is_rejected_and_rights_closed(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
            with self.subTest(kind=kind):
                sender, receiver = self.pair(kind)
                source, _ = self.pair()
                before = self.fd_count()
                self.send_rights(sender, b'{"x":"' + b"a" * wire.MAX_RECORD + b'"}\n', source.fileno())
                with self.assertRaises(wire.ProtocolError):
                    wire.receive(receiver, allow_rights=True)
                self.assertEqual(self.fd_count(), before)

    def test_missing_newline_is_rejected_on_eof_and_rights_closed(self):
        sender, receiver = self.pair()
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b'{"ok":true}', source.fileno())
        sender.shutdown(socket.SHUT_WR)
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_empty_eof_is_rejected(self):
        sender, receiver = self.pair()
        sender.shutdown(socket.SHUT_WR)
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver)

    def test_only_one_complete_record_is_allowed(self):
        for payload in (b"{}\n{}\n", b"{}\ntrailing", b"\n", b"{}\n\n"):
            with self.subTest(payload=payload):
                sender, receiver = self.pair(socket.SOCK_SEQPACKET)
                sender.send(payload)
                with self.assertRaises(ValueError):
                    wire.receive(receiver)

    def test_malformed_json_nonobject_and_invalid_encoding_close_received_rights(self):
        payloads = (b"{\n", b"[]\n", b"null\n", b"false\n", b"1\n", b'"text"\n',
                    b"{\xff}\n", b"{}\n{}\n", b"{}\ntrailing",
                    b'{"op":"first","op":"second"}\n',
                    b'{"nested":{"key":1,"key":2}}\n')
        for payload in payloads:
            with self.subTest(payload=payload):
                sender, receiver = self.pair(socket.SOCK_SEQPACKET)
                source, _ = self.pair()
                before = self.fd_count()
                self.send_rights(sender, payload, source.fileno())
                with self.assertRaises(ValueError):
                    wire.receive(receiver, allow_rights=True)
                self.assertEqual(self.fd_count(), before)

    def test_nonfinite_json_values_are_rejected_and_received_rights_closed(self):
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
            with self.subTest(token=token):
                sender, receiver = self.pair(socket.SOCK_SEQPACKET)
                source, _ = self.pair()
                before = self.fd_count()
                self.send_rights(sender, b'{"value":' + token + b"}\n", source.fileno())
                returned_rights = []
                try:
                    with self.assertRaises(ValueError):
                        _, returned_rights = wire.receive(receiver, allow_rights=True)
                finally:
                    wire.close_rights(returned_rights)
                self.assertEqual(self.fd_count(), before)

    def test_json_parser_recursion_failure_is_protocol_failure_with_rights_closed(self):
        sender, receiver = self.pair(socket.SOCK_SEQPACKET)
        source, _ = self.pair()
        before = self.fd_count()
        payload = b'{"value":' + b"[" * 1200 + b"0" + b"]" * 1200 + b"}\n"
        self.assertLess(len(payload), wire.MAX_RECORD)
        self.send_rights(sender, payload, source.fileno())
        # Parser depth behavior differs across Python versions. Force this
        # parser failure, while still testing actual socket/descriptor cleanup.
        with patch.object(wire.json, "loads", side_effect=RecursionError("JSON nesting")):
            with self.assertRaises(ValueError):
                wire.receive(receiver, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_send_rejects_nonfinite_values_before_writing(self):
        connection = Mock()
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wire.send(connection, {"value": value})
        connection.sendmsg.assert_not_called()

    def test_unexpected_descriptor_is_closed_when_not_allowed(self):
        sender, receiver = self.pair()
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b"{}\n", source.fileno())
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver)
        self.assertEqual(self.fd_count(), before)

    def test_extra_and_truncated_ancillary_descriptors_never_leak(self):
        for count in (2, 40):
            with self.subTest(count=count):
                sender, receiver = self.pair(socket.SOCK_SEQPACKET)
                source, _ = self.pair()
                before = self.fd_count()
                self.send_rights(sender, b"{}\n", source.fileno(), count)
                with self.assertRaises(wire.ProtocolError):
                    wire.receive(receiver, allow_rights=True)
                self.assertEqual(self.fd_count(), before)

    def test_unknown_credential_ancillary_is_rejected_with_rights_closed(self):
        sender, receiver = self.pair(socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b"{}\n", source.fileno())
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_malformed_ancillary_integer_bytes_close_complete_received_descriptors(self):
        sender, receiver = self.pair(socket.SOCK_SEQPACKET)
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b"{}\n", source.fileno())

        def corrupt_metadata(*arguments):
            payload, ancillary, flags, address = receiver.recvmsg(*arguments)
            # Kernels normally prevent a misaligned SCM_RIGHTS payload. Alter
            # only that metadata after the real receive to test defensive
            # cleanup of the genuine descriptor already delivered by the OS.
            level, kind, raw = ancillary[0]
            return payload, [(level, kind, raw + b"x")], flags, address

        connection = Mock()
        connection.recvmsg.side_effect = corrupt_metadata
        with self.assertRaises(wire.ProtocolError):
            wire.receive(connection, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_empty_packet_with_descriptor_closes_received_rights(self):
        sender, receiver = self.pair(socket.SOCK_SEQPACKET)
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b"", source.fileno())
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_rights_across_fragments_cannot_exceed_one(self):
        sender, receiver = self.pair()
        source, _ = self.pair()
        before = self.fd_count()
        self.send_rights(sender, b'{"ok":', source.fileno())
        self.send_rights(sender, b"true}\n", source.fileno())
        with self.assertRaises(wire.ProtocolError):
            wire.receive(receiver, allow_rights=True)
        self.assertEqual(self.fd_count(), before)

    def test_partial_stream_send_never_retransmits_ancillary_rights(self):
        # Real socketpairs above cover delivery; this deterministic short-write
        # fixture tests a rare stream send boundary without blocking a socket.
        connection = Mock()
        connection.sendmsg.return_value = 2
        source, _ = self.pair()
        value = {"ok": True}
        wire.send(connection, value, source.fileno())
        expected = b'{"ok":true}\n'
        connection.sendmsg.assert_called_once()
        arguments = connection.sendmsg.call_args.args
        self.assertEqual(arguments[0], [expected])
        self.assertEqual(arguments[1][0][:2], (socket.SOL_SOCKET, socket.SCM_RIGHTS))
        self.assertEqual(list(arguments[1][0][2]), [source.fileno()])
        self.assertEqual(arguments[2], socket.MSG_NOSIGNAL)
        connection.sendall.assert_called_once_with(expected[2:])

    def test_zero_send_is_failure_without_a_second_rights_transfer(self):
        connection = Mock()
        connection.sendmsg.return_value = 0
        with self.assertRaises(wire.ProtocolError):
            wire.send(connection, {"ok": True})
        connection.sendmsg.assert_called_once()
        connection.sendall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
