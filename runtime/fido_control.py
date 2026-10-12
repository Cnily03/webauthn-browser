"""Session-gated private supervisor control for the userspace FIDO adapter.

This is a bounded capability broker, never a HID report transport. Static ELF
checks and a successful control handshake do not establish Chromium discovery.
The test-only simulation switch is a constructor argument, never configuration.
"""
import array
import errno
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, replace
from enum import IntEnum


ZERO = bytes(16)
MAX_LEASE_NS = 30_000_000_000
FRAME = struct.Struct("!4sBBBB16s16s16sQQQQ8s")
FRAME_SIZE = 96
NATIVE_CHROMIUM = "/usr/lib/chromium/chromium"
HOOK_PATH_ENV = "AUTH_BROWSER_FIDO_HOOK_PATH"
DEFAULT_HOOK_PATH = "/opt/webauthn-browser/native/libuserland_hid_hook.so"
FLAG_MONITOR = 1
FLAG_SIMULATION = 128
MAX_PER_TICK = 32


class ProtocolError(ValueError):
    pass


class Op(IntEnum):
    HELLO = 1
    READY = 2
    PREPARE = 3
    PREPARED = 4
    ACTIVATE = 5
    ACTIVE = 6
    REVOKE = 7
    REVOKED = 8
    UNAVAILABLE = 9
    RENEW = 10
    RENEWED = 11


@dataclass(frozen=True)
class Frame:
    op: Op
    gateway_epoch: bytes
    browser_epoch: bytes
    attachment_id: bytes = ZERO
    device_generation: int = 0
    mode_generation: int = 0
    deadline_ns: int = 0
    lease_sequence: int = 0
    flags: int = 0

    def validate(self, allow_simulation=False):
        if not isinstance(self.op, Op):
            raise ProtocolError("unknown control opcode")
        if any(len(x) != 16 for x in (self.gateway_epoch, self.browser_epoch, self.attachment_id)):
            raise ProtocolError("invalid control identity")
        if self.gateway_epoch == ZERO or self.browser_epoch == ZERO:
            raise ProtocolError("empty control epoch")
        values = (self.device_generation, self.mode_generation, self.deadline_ns, self.lease_sequence)
        if any(not isinstance(x, int) or x < 0 or x >= 1 << 64 for x in values):
            raise ProtocolError("invalid control counter")
        expected = {FLAG_MONITOR, FLAG_MONITOR | FLAG_SIMULATION} if self.op in (
            Op.READY, Op.PREPARED, Op.ACTIVE, Op.RENEWED) else (
            {0, FLAG_SIMULATION} if self.op == Op.UNAVAILABLE else {0})
        if self.flags not in expected or (self.flags & FLAG_SIMULATION and not allow_simulation):
            raise ProtocolError("invalid control readiness flags")
        if self.op in (Op.HELLO, Op.READY, Op.UNAVAILABLE):
            if self.attachment_id != ZERO or any(values):
                raise ProtocolError("unexpected control attachment")
        else:
            if self.attachment_id == ZERO or not all(values[:3]):
                raise ProtocolError("missing control attachment")
            if self.op in (Op.PREPARE, Op.PREPARED, Op.ACTIVATE, Op.ACTIVE) and self.lease_sequence:
                raise ProtocolError("unexpected lease sequence")
            if self.op in (Op.RENEW, Op.RENEWED) and not self.lease_sequence:
                raise ProtocolError("missing lease sequence")
        return self

    def encode(self, allow_simulation=False):
        self.validate(allow_simulation)
        return FRAME.pack(b"UFHC", 1, int(self.op), self.flags, 0,
                          self.gateway_epoch, self.browser_epoch, self.attachment_id,
                          self.device_generation, self.mode_generation, self.deadline_ns,
                          self.lease_sequence, bytes(8))

    @classmethod
    def decode(cls, data, allow_simulation=False):
        if len(data) != FRAME_SIZE:
            raise ProtocolError("invalid control size")
        magic, version, opcode, flags, reserved, ge, be, aid, dg, mg, deadline, sequence, tail = FRAME.unpack(data)
        if magic != b"UFHC" or version != 1 or reserved or tail != bytes(8):
            raise ProtocolError("invalid control header")
        try:
            op = Op(opcode)
        except ValueError as error:
            raise ProtocolError("unknown control opcode") from error
        return cls(op, ge, be, aid, dg, mg, deadline, sequence, flags).validate(allow_simulation)

    def identity(self):
        return (self.gateway_epoch, self.browser_epoch, self.attachment_id,
                self.device_generation, self.mode_generation)


def control_pair():
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)


def connected_endpoint(fd):
    """Take ownership of exactly one connected, anonymous AF_UNIX packet FD."""
    try:
        endpoint = socket.socket(fileno=fd)
    except BaseException:
        os.close(fd)
        raise
    try:
        if endpoint.family != socket.AF_UNIX or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            raise ProtocolError("invalid control endpoint type")
        endpoint.getpeername()  # Reject an unconnected/listening socket.
        endpoint.set_inheritable(False)
        return endpoint
    except BaseException:
        endpoint.close()
        raise


def receive_frame(control, allow_simulation=False):
    """Return a frame and owned endpoint; close every received FD on rejection."""
    # Space for several FDs allows explicit rejection; MSG_CTRUNC rejects larger
    # sets too. Linux closes rights omitted by truncation, and we close the rest.
    data, ancillary, flags, _ = control.recvmsg(
        FRAME_SIZE + 1, socket.CMSG_SPACE(16 * array.array("i").itemsize),
        socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
    rights = []
    endpoint = None
    try:
        unknown = False
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                unknown = True
                continue
            fds = array.array("i")
            size = len(payload) - len(payload) % fds.itemsize
            fds.frombytes(payload[:size])
            rights.extend(fds)
            if size != len(payload):
                unknown = True
        if not data:
            raise EOFError("control closed")
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unknown:
            raise ProtocolError("truncated or unexpected control ancillary data")
        frame = Frame.decode(data, allow_simulation)
        if len(rights) != (1 if frame.op == Op.PREPARE else 0):
            raise ProtocolError("unexpected control descriptors")
        if rights:
            fd = rights.pop()
            endpoint = connected_endpoint(fd)
        return frame, endpoint
    except BaseException:
        if endpoint is not None:
            endpoint.close()
        raise
    finally:
        for fd in rights:
            os.close(fd)


def send_frame(control, frame, endpoint=None, allow_simulation=False):
    if (endpoint is not None) != (frame.op == Op.PREPARE):
        raise ProtocolError("unexpected outgoing control descriptor")
    ancillary = [] if endpoint is None else [
        (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [endpoint.fileno()]))]
    if control.sendmsg([frame.encode(allow_simulation)], ancillary,
                       socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) != FRAME_SIZE:
        raise ProtocolError("short control send")


def verify_elf(path, *, library=False):
    """Read static metadata only; never execute a probe or change permissions."""
    path = Path(path)
    if not path.is_absolute() or any(c.isspace() or c == ":" for c in str(path)):
        raise ValueError("FIDO ELF path must be absolute and unambiguous")
    # Reject symlink components and untrusted writable parent directories. The
    # configured library is trusted code; this check does not authenticate it.
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError("FIDO ELF path must have trusted ownership and permissions")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
                or info.st_uid not in (0, os.getuid())):
            raise ValueError("FIDO ELF must be an ordinary unprivileged file")
        if not library and not info.st_mode & 0o111:
            raise ValueError("FIDO browser ELF is not executable")
        try:
            capabilities = os.getxattr(fd, "security.capability")
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise ValueError("FIDO ELF capabilities could not be checked") from error
            capabilities = b""
        if capabilities:
            raise ValueError("FIDO ELF must not have file capabilities")
        header = os.read(fd, 64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("FIDO requires a native little-endian ELF64 file")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        if machine != 62 or version != 1 or kind not in ((3,) if library else (2, 3)):
            raise ValueError("FIDO requires native x86-64 ELF code")
        if struct.unpack_from("<H", header, 52)[0] != 64:
            raise ValueError("invalid FIDO ELF header")
    finally:
        os.close(fd)
    return str(path)


@dataclass
class Peer:
    control: socket.socket
    epoch: bytes
    process: object = None


@dataclass
class Attachment:
    frame: Frame
    endpoint: socket.socket
    phase: str = "preparing"
    renewal: Frame = None

    def close(self):
        # shutdown affects aliases already delivered by SCM_RIGHTS. No report
        # bytes are consumed, forwarded or logged by the supervisor.
        try:
            self.endpoint.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.endpoint.close()


class FidoController:
    def __init__(self, hook_path=None, *, clock=time.monotonic_ns, allow_simulation=False):
        self.hook_path = hook_path
        self.clock = clock
        self.allow_simulation = allow_simulation
        self.peers = {}
        self.scope = None
        self.ready = False
        self.attachment = None
        self.device_highwater = 0
        self.last_retired = None
        self.last_diagnostic = None

    def _diagnostic(self, state):
        # Fixed lifecycle labels only: never report epochs, attachment IDs, FDs,
        # device paths or opaque reports. Repeated waiting frames stay quiet.
        if state != self.last_diagnostic:
            self.last_diagnostic = state
            print(f"[native-usb] {state}", file=sys.stderr, flush=True)

    @classmethod
    def from_environment(cls, environ=None):
        environ = os.environ if environ is None else environ
        # Ordinary packaged startup prepares only metadata/control. The existing
        # approved Native session must still request Prepare+Activate before
        # any report endpoint or virtual FIDO device exists. Explicit 0 keeps
        # an emergency deployment opt-out; malformed overrides fail closed.
        if environ.get("AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY", "1") != "1":
            return None
        try:
            hook = verify_elf(environ.get(HOOK_PATH_ENV, DEFAULT_HOOK_PATH), library=True)
            verify_elf(NATIVE_CHROMIUM)
        except (OSError, ValueError):
            # Do not turn an unsupported architecture/missing hook into a
            # desktop failure, but make the unavailable preparation observable.
            print("[supervisor] Native USB preparation unavailable: packaged browser/hook validation failed; software and BLE remain available.", file=sys.stderr, flush=True)
            return None
        return cls(hook)

    def prepare_child(self, role):
        if role not in ("gateway", "browser"):
            raise ValueError("unknown FIDO child")
        self.retire(role)
        control, child = control_pair()
        epoch = secrets.token_bytes(16)
        while epoch == ZERO:
            epoch = secrets.token_bytes(16)
        self.peers[role] = Peer(control, epoch)
        if role == "gateway":
            self.device_highwater = 0
            additions = {"AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY": "1",
                         "AUTH_BROWSER_FIDO_CONTROL_FD": str(child.fileno()),
                         "AUTH_BROWSER_FIDO_GATEWAY_EPOCH": epoch.hex()}
        else:
            additions = {"LD_PRELOAD": self.hook_path, "UHF_ENABLE": "1",
                         "UHF_CONTROL_FD": str(child.fileno()), "UHF_BROWSER_EPOCH": epoch.hex()}
        return additions, child

    def child_started(self, role, process):
        if role in self.peers:
            self.peers[role].process = process
        self._hello()

    def _scope_frame(self, op, flags=0):
        if self.scope is None:
            return None
        return Frame(op, *self.scope, flags=flags)

    def _hello(self):
        if self.scope is not None or set(self.peers) != {"gateway", "browser"}:
            return
        if any(peer.process is None for peer in self.peers.values()):
            return
        self.scope = (self.peers["gateway"].epoch, self.peers["browser"].epoch)
        hello = self._scope_frame(Op.HELLO)
        if self._send("browser", hello):
            if self._send("gateway", hello):
                self._diagnostic("control handshake sent; waiting for genuine HID monitor readiness")

    def _send(self, role, frame, endpoint=None):
        peer = self.peers.get(role)
        if peer is None or frame is None:
            return False
        try:
            send_frame(peer.control, frame, endpoint, self.allow_simulation)
            return True
        except (OSError, ValueError):
            # No queue/retry on an uncertain send: close the capability instead.
            self.retire(role)
            return False

    def _revoke(self, *, notify=True):
        old = self.attachment
        self.attachment = None
        if old is None:
            return
        old.close()
        self._diagnostic("report endpoint revoked and closed")
        self.last_retired = old.frame
        if notify:
            frame = replace(old.frame, op=Op.REVOKE, flags=0)
            if old.phase != "revoking":
                self._send("browser", frame)
            # Revoked represents supervisor-enforced endpoint shutdown, not a
            # claim that Chromium observed a remove event.
            self._send("gateway", replace(frame, op=Op.REVOKED))

    def retire(self, role):
        peer = self.peers.pop(role, None)
        if peer is None:
            return
        peer.control.close()
        self._diagnostic(f"{role} control peer retired")
        self._revoke()
        other = "browser" if role == "gateway" else "gateway"
        self._send(other, self._scope_frame(Op.UNAVAILABLE))
        self.ready = False
        self.scope = None
        self.last_retired = None

    child_failed = retire

    def close(self):
        self.retire("browser")
        self.retire("gateway")

    def _live_deadline(self, deadline):
        now = self.clock()
        return now < deadline <= now + MAX_LEASE_NS

    def _matching(self, frame):
        current = self.attachment
        return current is not None and frame.identity() == current.frame.identity()

    def _handle(self, role, frame, endpoint):
        if self.scope is None or (frame.gateway_epoch, frame.browser_epoch) != self.scope:
            return  # Delayed messages from an old child cannot alter this scope.
        if frame.op == Op.UNAVAILABLE:
            self._diagnostic(f"{role} prerequisites unavailable; waiting for recovery")
            self.ready = False
            self._revoke()
            self._send("gateway" if role == "browser" else "browser", frame)
            return
        if role == "browser" and frame.op == Op.READY:
            if not self.ready:
                self.ready = True
                self._diagnostic("test-only simulated HID monitor READY" if frame.flags & FLAG_SIMULATION else
                                 "genuine HID monitor READY; waiting for an authorized Native attachment")
                self._send("gateway", frame)
            return
        if role == "gateway" and frame.op == Op.PREPARE:
            if (not self.ready or self.attachment is not None
                    or frame.device_generation <= self.device_highwater
                    or not self._live_deadline(frame.deadline_ns)):
                raise ProtocolError("unavailable or stale FIDO preparation")
            # Keep one duplicate solely to shut down all endpoint aliases on
            # revocation. The received original is closed by tick's finally.
            owned = connected_endpoint(os.dup(endpoint.fileno()))
            self.device_highwater = frame.device_generation
            self.attachment = Attachment(frame, owned)
            self._diagnostic("authorized report endpoint PREPARE sent to browser")
            self._send("browser", frame, endpoint)
            return
        if not self._matching(frame):
            # A canceled operation may acknowledge late. It cannot revive its
            # endpoint or cancel a newer generation. Reject every received FD.
            if frame.device_generation <= self.device_highwater:
                return
            raise ProtocolError("unknown FIDO attachment")
        current = self.attachment
        if role == "gateway" and frame.op == Op.REVOKE:
            # Revocation matches the attachment identity, not a lease ACK that
            # may still be in flight. It cannot extend or revive anything.
            current.close()
            current.phase = "revoking"
            current.renewal = None
            self._send("browser", frame)
            return
        if role == "browser" and frame.op == Op.REVOKED and current.phase == "revoking":
            self.last_retired = current.frame
            self.attachment = None
            self._send("gateway", frame)
            return
        if self.clock() >= current.frame.deadline_ns:
            self._revoke()
            return
        if role == "gateway" and frame.op == Op.RENEW:
            if (current.phase != "active" or current.renewal is not None
                    or frame.lease_sequence != current.frame.lease_sequence + 1
                    or frame.deadline_ns <= current.frame.deadline_ns
                    or not self._live_deadline(frame.deadline_ns)):
                raise ProtocolError("invalid FIDO renewal")
            # A proposed renewal does not extend the acknowledged lease. tick
            # must still revoke at the old deadline while this ACK is pending.
            current.renewal = frame
            self._send("browser", frame)
            return
        if role == "browser" and frame.op == Op.RENEWED:
            pending = current.renewal
            if (pending is None or frame.deadline_ns != pending.deadline_ns
                    or frame.lease_sequence != pending.lease_sequence
                    or not self._live_deadline(frame.deadline_ns)):
                raise ProtocolError("invalid FIDO renewal acknowledgement")
            current.frame = pending
            # The committed lease retains this same endpoint and identity; no
            # Prepare or new device generation is synthesized by renewal.
            current.renewal = None
            self._send("gateway", frame)
            return
        if (frame.deadline_ns != current.frame.deadline_ns
                or frame.lease_sequence != current.frame.lease_sequence):
            raise ProtocolError("mismatched FIDO attachment lease")
        transitions = {
            ("browser", Op.PREPARED, "preparing"): ("prepared", "gateway"),
            ("gateway", Op.ACTIVATE, "prepared"): ("activating", "browser"),
            ("browser", Op.ACTIVE, "activating"): ("active", "gateway"),
        }
        transition = transitions.get((role, frame.op, current.phase))
        if transition is None:
            raise ProtocolError("unexpected FIDO attachment transition")
        current.phase = transition[0]
        if current.phase == "active":
            self._diagnostic("browser acknowledged report endpoint ACTIVE; this is not authentication success")
        self._send(transition[1], frame)

    def tick(self):
        for role, peer in list(self.peers.items()):
            if peer.process is not None and peer.process.poll() is not None:
                self.retire(role)
        if self.attachment is not None and self.clock() >= self.attachment.frame.deadline_ns:
            self._revoke()
        for role in ("browser", "gateway"):
            for _ in range(MAX_PER_TICK):
                peer = self.peers.get(role)
                if peer is None:
                    break
                endpoint = None
                try:
                    frame, endpoint = receive_frame(peer.control, self.allow_simulation)
                    self._handle(role, frame, endpoint)
                except BlockingIOError:
                    break
                except (OSError, ValueError, EOFError):
                    self.retire(role)
                    break
                finally:
                    if endpoint is not None:
                        endpoint.close()
        # Work is bounded even if a child continuously writes valid messages.
