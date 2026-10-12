#!/usr/bin/env python3
"""Compile only a C harness and test the existing hook; never builds Rust."""
import hashlib
import os
import pathlib
import socket
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
LIB = ROOT / "target/debug/libuserland_hid_hook.so"
BASE = os.environ.copy()
for key in ("LD_PRELOAD", "UHF_ENABLE", "UHF_RELAY_FD", "UHF_OWNER_PID"):
    BASE.pop(key, None)


def run_case(harness, mode, owner=None):
    client, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    peer.settimeout(15)
    errors = []

    def echo():
        try:
            while True:
                packet = peer.recv(128)
                if not packet:
                    break
                if len(packet) != 64:
                    raise RuntimeError("fixture received invalid report length")
                peer.sendall(packet)
        except Exception as error:
            errors.append(type(error).__name__)
        finally:
            peer.close()

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    try:
        env = BASE | {"LD_PRELOAD": str(LIB), "UHF_ENABLE": "1", "UHF_RELAY_FD": str(client.fileno())}
        args = [str(harness), mode, str(client.fileno())]
        if owner is not None:
            env["UHF_OWNER_PID"] = owner
            args.append(owner)
        result = subprocess.run(
            args, env=env,
            pass_fds=(client.fileno(),), capture_output=True, text=True, timeout=15,
        )
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        if result.returncode:
            raise RuntimeError(f"{mode}: child exited {result.returncode}")
    finally:
        client.close()
        thread.join(timeout=2)
    if thread.is_alive() or errors:
        raise RuntimeError(f"{mode}: fixture did not finish cleanly: {errors}")


def main():
    if not LIB.is_file():
        raise SystemExit("Missing already-built hook library; this test does not build it")
    digest = hashlib.sha256(LIB.read_bytes()).hexdigest()
    print(f"Hook SHA-256: {digest}", flush=True)
    with tempfile.TemporaryDirectory(prefix=".fork-isolation-", dir=TESTS) as directory:
        harness = pathlib.Path(directory) / "harness"
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2",
             "-pthread", "-o", str(harness), str(TESTS / "fork_isolation.c")],
            env=BASE, check=True, timeout=20,
        )
        for mode in ("basic", "relay-reuse", "alias-reuse", "blocked-pin", "fork-exec", "capability-aliases"):
            print(f"\n=== {mode} ===", flush=True)
            run_case(harness, mode)
        owners = (
            ("malformed", "not-a-pid"),
            ("zero", "0"),
            ("negative", "-1"),
            ("overflow", "184467440737095516160"),
            ("mismatched positive", str(os.getpid())),
        )
        for label, owner in owners:
            print(f"\n=== inactive owner: {label} ===", flush=True)
            run_case(harness, "inactive-owner", owner)
    assert hashlib.sha256(LIB.read_bytes()).hexdigest() == digest, "Hook binary changed during regression"
    print("\nPASS 6 fork lifecycle and 5 inactive-owner subprocess cases; existing hook binary unchanged; no browser, udev, or real authenticator used", flush=True)


if __name__ == "__main__":
    main()
