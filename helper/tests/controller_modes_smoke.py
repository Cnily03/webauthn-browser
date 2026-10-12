"""Actual CLI/Desktop controllers, one synthetic pipe device, real local WebSockets.

No physical USB/BLE APIs. Build with:
  cargo build --manifest-path helper/Cargo.toml --example controller-fixture --features desktop,test-support
Run the normal checks, or add --stress [REPETITIONS] for bursts and a >30 s delay.
"""
import argparse
import base64
import fcntl
import json
import os
import pty
import re
import select
import socket
import struct
import subprocess
import tempfile
import termios
import time
from pathlib import Path

from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed

ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
FIXTURE_ID = b"webauthn-helper fake controller fixture v1"
KEEPALIVE = base64.b64encode(bytes([0xCE]) * 64).decode()


class Frontend:
    def __init__(self, binary, mode, disable_usb=False, delay_ms=None, exchange_delay_ms=None):
        self.mode = mode
        self.output = b""
        self.output_paused = False
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            self.port = held.getsockname()[1]
        self.master, self.slave = pty.openpty()
        self.stderr = tempfile.TemporaryFile()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 100, 0, 0))

        def terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

        args = [str(binary), "--disable-ble", "--listen", f"127.0.0.1:{self.port}"]
        if disable_usb:
            args.append("--disable-usb")
        env = dict(
            os.environ,
            FIXTURE_UI=mode,
            FIXTURE_PORT=str(self.port),
            FIXTURE_DISABLE_USB=str(int(disable_usb)),
            NO_COLOR="1",
            DBUS_SYSTEM_BUS_ADDRESS="unix:path=/nonexistent-helper-fixture-bus",
        )
        env.pop("FIXTURE_DELAY_MS", None)
        env.pop("FIXTURE_EXCHANGE_DELAY_MS", None)
        if delay_ms is not None:
            env["FIXTURE_DELAY_MS"] = str(delay_ms)
        if exchange_delay_ms is not None:
            env["FIXTURE_EXCHANGE_DELAY_MS"] = str(exchange_delay_ms)
        # stderr must remain independent when only terminal stdout is paused.
        self.process = subprocess.Popen(
            args, stdin=self.slave, stdout=self.slave, stderr=self.stderr,
            preexec_fn=terminal, env=env,
        )
        try:
            self.until(b"Listening: ")
        except BaseException:
            self.dispose()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.dispose()

    def diagnostics(self):
        size = os.fstat(self.stderr.fileno()).st_size
        stderr = os.pread(self.stderr.fileno(), min(size, 65536), max(0, size - 65536))
        return (self.output[-65536:] + b"\nSTDERR:\n" + stderr).decode(errors="replace")

    def pump(self, seconds=0.1):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            remaining = max(0, min(0.02, end - time.monotonic()))
            if select.select([self.master], [], [], remaining)[0]:
                try:
                    self.output = (self.output + os.read(self.master, 65536))[-2_000_000:]
                except OSError:
                    return

    def until(self, text, mark=0):
        end = time.monotonic() + 8
        while time.monotonic() < end:
            self.pump(0.03)
            if text in ANSI.sub(b"", self.output)[mark:]:
                return
            assert self.process.poll() is None, self.diagnostics()
        raise AssertionError((text, self.diagnostics()))

    def pair(self, first=False):
        ws = connect(
            f"ws://127.0.0.1:{self.port}", origin="https://fixture.example",
            close_timeout=2, ping_interval=None,
        )
        ws.send(json.dumps(dict(
            type="pair", token=os.urandom(24).hex(),
            session_id="FakeBackendSession012345678901234567890",
        )))
        if first and self.mode == "cli":
            self.until(b"Browser Origin: https://fixture.example")
            os.write(self.master, b"\r")
        end = time.monotonic() + 5
        while True:
            value = json.loads(ws.recv(timeout=max(0.01, end - time.monotonic())))
            if value.get("state") == "paired":
                return ws
            assert value.get("state") not in ("closed", "error"), value
            assert time.monotonic() < end, self.diagnostics()

    def pause_stdout(self):
        self.pump(0.1)
        termios.tcflow(self.slave, termios.TCOOFF)
        self.output_paused = True

    def close(self):
        start = time.monotonic()
        if self.process.poll() is None:
            os.write(self.master, b"quit\n")
            # Deliberately never resume paused stdout to help shutdown pass.
            self.process.wait(timeout=6)
        assert self.process.returncode == 0, self.diagnostics()
        if not self.output_paused:
            self.pump()
        return time.monotonic() - start

    def dispose(self):
        # Even a failed regression kills/reaps before restoring this private PTY.
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=3)
        if self.output_paused:
            termios.tcflow(self.slave, termios.TCOON)
            self.output_paused = False
        os.close(self.master)
        os.close(self.slave)
        self.stderr.close()


def frame(ws, tag, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = json.loads(ws.recv(timeout=max(0.01, end - time.monotonic())))
        if value["type"] == tag:
            return value
        assert value.get("state") not in ("closed", "error", "lease_expired"), value
        assert value["type"] not in ("fido_close", "fido_status"), value
    raise AssertionError(tag)


def send(ws, tag, relay, **values):
    ws.send(json.dumps(dict(type=tag, version=1, relay_id=relay, **values)))


def open_relay(ws, relay, remaining_ms=30000):
    send(ws, "fido_open", relay, remaining_ms=remaining_ms)
    assert frame(ws, "fido_ready")["relay_id"] == relay


def renew(ws, relay, sequence, remaining_ms=30000):
    send(ws, "fido_renew", relay, lease_sequence=sequence, remaining_ms=remaining_ms)
    reply = frame(ws, "fido_renewed")
    assert reply["relay_id"] == relay and reply["lease_sequence"] == sequence, reply
    assert 0 < reply["remaining_ms"] <= remaining_ms, reply


def echo(ws, relay, sequence, byte):
    payload = base64.b64encode(bytes([byte]) * 64).decode()
    send(ws, "fido_report", relay, sequence=sequence, data=payload)
    reply = frame(ws, "fido_report")
    assert reply["relay_id"] == relay, reply
    assert reply["data"] == payload and reply["sequence"] == sequence, reply


def run(binary, mode):
    with Frontend(binary, mode) as ui:
        for iteration in range(2):
            with ui.pair(first=iteration == 0) as ws:
                relay = frame(ws, "fido_available")["relay_id"]
                # Synthetic open is acknowledged; no reports are exchanged before FidoOpen.
                ui.pump(0.5)
                renew(ws, relay, 1)
                open_relay(ws, relay)
                for sequence in range(3):
                    echo(ws, relay, sequence, iteration * 16 + sequence)
                renew(ws, relay, 2)
            ui.pump(0.6)
        assert b"BLE: starting" not in ui.output
        ui.close()
    with Frontend(binary, mode, disable_usb=True) as disabled:
        with disabled.pair(first=True) as ws:
            try:
                value = json.loads(ws.recv(timeout=0.7))
                assert value["type"] != "fido_available", value
            except TimeoutError:
                pass
            assert ws.ping().wait(timeout=2)
        disabled.close()
        assert b"BLE: starting" not in disabled.output and b"USB: finding" not in disabled.output
    print(f"PASS: actual {mode}; approval, idle renewal, 6 echoes, reconnect, USB-only and both-disabled pairing", flush=True)


def paused_stdout(binary, mode):
    with Frontend(binary, mode) as ui:
        with ui.pair(first=True) as ws:
            relay = frame(ws, "fido_available")["relay_id"]
            ui.pause_stdout()
            open_relay(ws, relay)
            for sequence in range(3):
                echo(ws, relay, sequence, 0x40 + sequence)
            renew(ws, relay, 1)
            assert ws.ping(b"paused-stdout").wait(timeout=2)
            send(ws, "fido_close", relay)
            assert frame(ws, "fido_close")["relay_id"] == relay
        elapsed = ui.close()
        assert ui.output_paused and ui.process.poll() == 0
    print(f"PASS: {mode} paused stdout; ready, reports, renewal, ping, close; exit {elapsed:.3f}s without resuming output", flush=True)


def burst_round(binary, mode, repetition):
    with Frontend(binary, mode) as ui:
        with ui.pair(first=True) as ws:
            old_relay = frame(ws, "fido_available")["relay_id"]
            open_relay(ws, old_relay)
            payloads = [base64.b64encode(bytes([sequence]) * 64).decode() for sequence in range(129)]
            start = time.monotonic()
            for sequence, payload in enumerate(payloads):
                send(ws, "fido_report", old_relay, sequence=sequence, data=payload)
            for sequence, payload in enumerate(payloads):
                reply = frame(ws, "fido_report", timeout=max(0.01, start + 12 - time.monotonic()))
                assert reply["relay_id"] == old_relay, reply
                assert reply["sequence"] == sequence and reply["data"] == payload, reply
            elapsed = time.monotonic() - start
            assert elapsed < 2, f"129-report drain must finish below 2s, got {elapsed:.3f}s"
            renew(ws, old_relay, 1)
            assert ws.ping().wait(timeout=2)
        ui.pump(0.6)
        with ui.pair() as ws:
            new_relay = frame(ws, "fido_available")["relay_id"]
            assert new_relay != old_relay
            for tag, fields in [
                ("fido_report", dict(sequence=0, data=payloads[0])),
                ("fido_open", dict(remaining_ms=30000)),
                ("fido_renew", dict(lease_sequence=2, remaining_ms=30000)),
            ]:
                send(ws, tag, old_relay, **fields)
                assert frame(ws, "fido_close")["relay_id"] == old_relay
            open_relay(ws, new_relay)
            echo(ws, new_relay, 0, 0x7F)
            renew(ws, new_relay, 1)
            assert ws.ping().wait(timeout=2)
        ui.close()
    print(f"PASS: {mode} stress {repetition}; 129 ordered complete echoes {elapsed:.3f}s; stale report/open/renew rejected without changing new pairing", flush=True)
    return elapsed


def interrupted_burst(binary, mode, local_revoke):
    count = 258  # Never exceed the shared bounded endpoint capacity.
    with Frontend(binary, mode, exchange_delay_ms=5) as ui:
        with ui.pair(first=True) as ws:
            relay = frame(ws, "fido_available")["relay_id"]
            open_relay(ws, relay)
            payloads = [base64.b64encode(bytes([sequence % 256]) * 64).decode()
                        for sequence in range(count)]
            for sequence, payload in enumerate(payloads):
                send(ws, "fido_report", relay, sequence=sequence, data=payload)
            first = frame(ws, "fido_report")
            assert first["relay_id"] == relay and first["sequence"] == 0, first
            assert first["data"] == payloads[0], first
            start_ping = time.monotonic()
            assert ws.ping(b"active-bounded-burst").wait(timeout=1)
            ping_elapsed = time.monotonic() - start_ping
            start = time.monotonic()
            if local_revoke:
                os.write(ui.master, b"revoke\n")
            else:
                send(ws, "fido_close", relay)
            delivered = 1
            closed = False
            while True:
                try:
                    value = json.loads(ws.recv(timeout=max(0.01, start + 1 - time.monotonic())))
                except ConnectionClosed:
                    assert local_revoke, "Protocol relay close must preserve the paired socket"
                    closed = True
                    break
                if value["type"] == "fido_report":
                    assert value["relay_id"] == relay and value["sequence"] == delivered, value
                    assert value["data"] == payloads[delivered], value
                    delivered += 1
                    assert delivered < count, "Burst finished before cancellation was exercised"
                    continue
                if local_revoke and value.get("state") == "closed":
                    break
                assert not local_revoke and value["type"] == "fido_close" and value["relay_id"] == relay, value
                break
            terminal_elapsed = time.monotonic() - start
            assert terminal_elapsed < 1, f"Cancellation/revocation took {terminal_elapsed:.3f}s"
            # Frames already delivered before the terminal response were accounted
            # for above. Nothing from the canceled device may follow that boundary.
            end = time.monotonic() + 0.4
            while not closed and time.monotonic() < end:
                try:
                    value = json.loads(ws.recv(timeout=max(0.01, end - time.monotonic())))
                except TimeoutError:
                    break
                except ConnectionClosed:
                    closed = True
                    break
                assert value["type"] != "fido_report", f"Report after cancellation: {value}"
                assert local_revoke and value.get("state") == "closed", value
            if not local_revoke:
                assert not closed and ws.ping(b"relay-stays-closed").wait(timeout=1)
        ui.close()
    action = "local revoke/Stop listening" if local_revoke else "protocol relay close"
    print(f"PASS: {mode} active 258-report burst interrupted by {action}; {delivered} delivered, "
          f"ping {ping_elapsed:.3f}s, terminal response {terminal_elapsed:.3f}s; no reports after terminal response", flush=True)


def delayed_exchange(binary, mode):
    with Frontend(binary, mode, delay_ms=32000) as ui:
        with ui.pair(first=True) as ws:
            relay = frame(ws, "fido_available")["relay_id"]
            open_relay(ws, relay, remaining_ms=10000)
            payload = base64.b64encode(bytes([0xD1]) * 64).decode()
            send(ws, "fido_report", relay, sequence=0, data=payload)
            start = time.monotonic()
            next_renew = start + 4
            sequence = 0
            keepalives = 0
            acknowledged = 0
            pending_renewal = None
            while True:
                now = time.monotonic()
                assert now - start < 40, "Delayed fake exchange exceeded its bound"
                if now >= next_renew:
                    assert pending_renewal is None, "Previous renewal was not acknowledged"
                    pending_renewal = acknowledged + 1
                    send(ws, "fido_renew", relay, lease_sequence=pending_renewal, remaining_ms=10000)
                    next_renew = now + 4
                try:
                    value = json.loads(ws.recv(timeout=min(1, max(0.01, next_renew - time.monotonic()))))
                except TimeoutError:
                    continue
                assert value.get("relay_id") == relay, value
                if value["type"] == "fido_renewed":
                    assert pending_renewal is not None and value["lease_sequence"] == pending_renewal, value
                    assert 0 < value["remaining_ms"] <= 10000, value
                    acknowledged = pending_renewal
                    pending_renewal = None
                else:
                    assert value["type"] == "fido_report" and value["sequence"] == sequence, value
                    sequence += 1
                    if value["data"] == payload:
                        break
                    assert value["data"] == KEEPALIVE, value
                    keepalives += 1
                ui.pump(0.005)
            elapsed = time.monotonic() - start
            assert elapsed > 30 and keepalives >= 10 and acknowledged >= 7, (elapsed, keepalives, acknowledged)
            if pending_renewal is not None:
                reply = frame(ws, "fido_renewed")
                assert reply["lease_sequence"] == pending_renewal and reply["relay_id"] == relay, reply
                assert 0 < reply["remaining_ms"] <= 10000, reply
                acknowledged = pending_renewal
            # Duplicate renewal sequence fails closed rather than extending this lease.
            send(ws, "fido_renew", relay, lease_sequence=acknowledged, remaining_ms=10000)
            assert frame(ws, "fido_close")["relay_id"] == relay
            assert ws.ping().wait(timeout=2)
        ui.close()
    print(f"PASS: {mode} delayed exchange {elapsed:.3f}s; {keepalives} ordered synthetic keepalives, {acknowledged} strict renewals; duplicate renewal closes relay", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--stress", type=int, nargs="?", const=3, default=0,
                        metavar="REPETITIONS", help="matched 129-report rounds per mode (default 3), plus >30 s delayed exchanges")
    args = parser.parse_args()
    parser.error("--stress must be from 0 through 20") if not 0 <= args.stress <= 20 else None
    binary = args.binary.resolve()
    identity = subprocess.run([str(binary), "--fixture-identify"], capture_output=True, timeout=5, check=True)
    assert identity.stdout.strip() == FIXTURE_ID, "Use the fake-only controller-fixture executable"
    for mode in ["cli", "desktop"]:
        run(binary, mode)
        paused_stdout(binary, mode)
    if args.stress:
        timings = {mode: [] for mode in ("cli", "desktop")}
        for repetition in range(1, args.stress + 1):
            for mode in timings:
                timings[mode].append(burst_round(binary, mode, repetition))
        for mode in timings:
            interrupted_burst(binary, mode, local_revoke=False)
            interrupted_burst(binary, mode, local_revoke=True)
            delayed_exchange(binary, mode)
        print("129-report drain timings: " + "; ".join(
            f"{mode} min={min(values):.3f}s max={max(values):.3f}s" for mode, values in timings.items()
        ), flush=True)
