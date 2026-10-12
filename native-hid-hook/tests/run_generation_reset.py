#!/usr/bin/env python3
"""Bounded isolated regression against the already-built hook; never runs Cargo."""
import hashlib
import os
import pathlib
import select
import socket
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
LIB = ROOT / "target/debug/libuserland_hid_hook.so"
BASE = os.environ.copy()
for key in ("LD_PRELOAD", "UHF_ENABLE", "UHF_RELAY_FD"):
    BASE.pop(key, None)


def run_case(harness, mode):
    client, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    peer.settimeout(5)
    ready_r, ready_w = os.pipe()
    proceed_r, proceed_w = os.pipe()
    owned = {ready_r, ready_w, proceed_r, proceed_w}
    proc = None
    try:
        env = BASE | {
            "LD_PRELOAD": str(LIB),
            "UHF_ENABLE": "1",
            "UHF_RELAY_FD": str(client.fileno()),
        }
        proc = subprocess.Popen(
            [str(harness), str(client.fileno()), str(ready_w), str(proceed_r), mode],
            env=env,
            pass_fds=(client.fileno(), ready_w, proceed_r),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        client.close()
        for fd in (ready_w, proceed_r):
            os.close(fd)
            owned.remove(fd)
        if not select.select([ready_r], [], [], 5)[0] or os.read(ready_r, 1) != b"R":
            raise RuntimeError(f"{mode}: child failed to open old virtual aliases")
        if mode == "queued":
            for value in (0x31, 0x32, 0x33):
                peer.sendall(bytes([value]) * 64)
        peer.close()
        os.write(proceed_w, b"C")
        stdout, stderr = proc.communicate(timeout=10)
        print(stdout, end="", flush=True)
        print(stderr, end="", flush=True)
        if proc.returncode:
            raise RuntimeError(f"{mode}: regression exited {proc.returncode}")
    finally:
        client.close()
        peer.close()
        for fd in owned:
            os.close(fd)
        if proc is not None and proc.poll() is None:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=5)
            print(stdout, end="", flush=True)
            print(stderr, end="", flush=True)


def main():
    if not LIB.is_file():
        raise SystemExit("Missing already-built target/debug/libuserland_hid_hook.so; this test does not build it")
    digest = hashlib.sha256(LIB.read_bytes()).hexdigest()
    print(f"Hook SHA-256: {digest}", flush=True)
    with tempfile.TemporaryDirectory(prefix=".generation-reset-", dir=TESTS) as directory:
        harness = pathlib.Path(directory) / "harness"
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2",
             "-o", str(harness), str(TESTS / "generation_reset.c")],
            env=BASE, check=True, timeout=20,
        )
        for mode in ("empty", "queued"):
            print(f"\n=== old endpoint queue: {mode} ===", flush=True)
            run_case(harness, mode)
    assert hashlib.sha256(LIB.read_bytes()).hexdigest() == digest, "Hook binary changed during regression"
    print("\nPASS 2 isolated subprocesses; existing hook binary unchanged; no real authenticator or browser used", flush=True)


if __name__ == "__main__":
    main()
