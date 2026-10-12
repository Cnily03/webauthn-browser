"""Actual CLI/Desktop logging, synthetic events only. No device or controller APIs.

Build:
  cargo build --manifest-path helper/Cargo.toml --example logging-fixture --features desktop,test-support
Run:
  python3 helper/tests/logging_smoke.py --binary helper/target/debug/examples/logging-fixture

Each child remains alive until this script reads its FIFO completion marker and
acknowledges it. This exercises the production CLI sink without a timing sleep or
changing its deliberately non-draining process-lifetime guard.
"""
import argparse
import errno
import os
import pty
import re
import selectors
import subprocess
import time
from pathlib import Path


ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
FIXTURE_ID = b"webauthn-helper fake logging fixture v1"
COMPLETE = b"LOGGER_FIXTURE_DRAINED"
ORIGIN = b"https://logging-fixture.example"


def capture(binary, mode, placement, no_color, rust_log):
    sink = "stdout" if mode == "cli" else "stderr"
    other = "stderr" if mode == "cli" else "stdout"
    env = dict(os.environ, TERM="xterm-256color")
    for name in ("NO_COLOR", "RUST_LOG", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR"):
        env.pop(name, None)
    if no_color:
        env["NO_COLOR"] = "1"
    if rust_log is not None:
        env["RUST_LOG"] = rust_log

    terminal_stream = sink if placement == "tty" else other if placement == "opposite-tty" else None
    master = slave = None
    streams = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if terminal_stream:
        master, slave = pty.openpty()
        streams[terminal_stream] = slave
    process = None
    output = dict(stdout=bytearray(), stderr=bytearray())
    try:
        process = subprocess.Popen(
            [str(binary), mode], stdin=subprocess.PIPE, env=env, **streams,
        )
        if slave is not None:
            os.close(slave)
            slave = None
        acknowledged = False
        with selectors.DefaultSelector() as selector:
            for name in ("stdout", "stderr"):
                stream = getattr(process, name)
                fd = master if name == terminal_stream else stream.fileno()
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_READ, name)
            deadline = time.monotonic() + 8
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise AssertionError(f"Logger fixture timed out: {output!r}")
                for key, _ in selector.select(timeout=0.1):
                    try:
                        data = os.read(key.fd, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        data = b""  # Linux PTY EOF after the final slave closes.
                    if not data:
                        selector.unregister(key.fd)
                        continue
                    output[key.data].extend(data)
                    if not acknowledged and COMPLETE in output[sink]:
                        process.stdin.write(b"done\n")
                        process.stdin.flush()
                        process.stdin.close()
                        acknowledged = True
            process.wait(timeout=2)
            assert acknowledged, f"Missing completion marker: {output!r}"
            assert process.returncode == 0, (process.returncode, output)
        return bytes(output[sink]), bytes(output[other])
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(process, name)
                if stream is not None and not stream.closed:
                    stream.close()
        for fd in (master, slave):
            if fd is not None:
                os.close(fd)


def check(binary, mode, placement, no_color, rust_log, ble_debug, usb_debug):
    raw, other = capture(binary, mode, placement, no_color, rust_log)
    label = (mode, placement, no_color, rust_log)
    assert not other, (label, "Wrong output stream", other)
    plain = ANSI.sub(b"", raw).replace(b"\r\n", b"\n")
    preinstalled = mode == "desktop-preinstalled"
    colored = placement == "tty" and not no_color and not preinstalled
    for action in (b"Connected", b"Approved"):
        expected = action + b": " + ORIGIN
        assert plain.count(expected) == 1, (label, expected, raw)
        line = next(line for line in raw.splitlines() if action in line)
        assert b"\\x1b" not in line and b"\\u{1b}" not in line, (label, line)
        if colored:
            assert b"\x1b[38;5;10m" + action + b"\x1b[39m" in line, (label, line)
        else:
            assert b"\x1b" not in line, (label, line)
    for word, color in ((b"enabled", b"10"), (b"disabled", b"11")):
        expected = b"BLE: " + word
        assert plain.count(expected) == 1, (label, expected, raw)
        line = next(line for line in raw.splitlines() if expected in ANSI.sub(b"", line))
        assert b"\\x1b" not in line and b"\\u{1b}" not in line, (label, line)
        if colored:
            assert b"BLE: \x1b[38;5;" + color + b"m" + word + b"\x1b[39m" in line, (label, line)
        else:
            assert b"\x1b" not in line, (label, line)
    assert (b"\x1b" in raw) == colored, (label, raw)
    assert b"invalid-fixture" not in plain, (label, plain)
    assert b"FORBIDDEN_" not in plain, (label, plain)
    assert plain.count(COMPLETE) == 1, (label, plain)
    if preinstalled:
        assert plain.count(b"Preinstalled subscriber preserved") == 1, (label, plain)
        return
    for transition in (b"BLE fixture transition", b"USB fixture transition"):
        assert plain.count(transition) == 1, (label, transition, plain)
    for marker, enabled in ((b"BLE fixture counters", ble_debug), (b"USB fixture counters", usb_debug)):
        assert plain.count(marker) == int(enabled), (label, marker, plain)
    injection = b"ordinary fixture injection \\x1b[31muntrusted\\x1b[0m"
    assert plain.count(injection) == 1, (label, plain)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    identity = subprocess.run(
        [str(binary), "--fixture-identify"], capture_output=True, timeout=3, check=True,
    )
    assert identity.stdout.strip() == FIXTURE_ID and not identity.stderr, "Refusing a non-fixture executable"
    filters = (
        (None, False, False),
        ("debug", True, True),
        ("info,webauthn_helper::relay::ble=debug", True, False),
        ("info,webauthn_helper::relay::fido=debug", False, True),
        ("trace,btleplug=trace,hidapi=trace,tungstenite=trace", True, True),
        ("info,btleplug=trace,hidapi=trace,tungstenite=trace", False, False),
        ("malformed=not-a-level", False, False),
    )
    count = 0
    for mode in ("cli", "desktop"):
        for placement, no_color in (("tty", False), ("tty", True), ("pipe", False), ("opposite-tty", False)):
            for rust_log, ble_debug, usb_debug in filters:
                check(binary, mode, placement, no_color, rust_log, ble_debug, usb_debug)
                count += 1
    for placement, no_color in (("tty", False), ("tty", True), ("pipe", False), ("opposite-tty", False)):
        check(binary, "desktop-preinstalled", placement, no_color, None, False, False)
        count += 1
    print(f"PASS: {count} actual CLI/Desktop logger cases; no device APIs invoked")


if __name__ == "__main__":
    main()
