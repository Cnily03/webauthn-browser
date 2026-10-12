#!/usr/bin/env python3
"""Only anonymous socketpair I/O; no host device, listening socket, or auth fake."""
import os, pathlib, socket, subprocess, threading
root = pathlib.Path(__file__).resolve().parents[1]
lib = str(root / "target/debug/libuserland_hid_hook.so")
harness = str(root / "target/harness")
base = os.environ.copy()
for key in ("LD_PRELOAD", "UHF_ENABLE", "UHF_RELAY_FD", "UHF_OWNER_PID"):
    base.pop(key, None)
results = []
def run(label, env, mode="inactive", fds=()):
    print(f"\n=== {label} ===", flush=True)
    proc = subprocess.run([harness, mode, str(fds[0]) if fds else "-1"], env=env, pass_fds=fds, capture_output=True, text=True, timeout=30)
    print(proc.stdout, end="", flush=True)
    print(proc.stderr, end="", flush=True)
    if proc.returncode:
        raise RuntimeError(f"{label} failed: {proc.returncode}")
    results.append(proc.stdout)
    return proc.stdout
run("baseline real libc/libudev, no preload", base)
run("preload present, no opt-in", base | {"LD_PRELOAD": lib})
run("opt-in with invalid relay FD fails closed", base | {"LD_PRELOAD": lib, "UHF_ENABLE": "1", "UHF_RELAY_FD": "999999"})
pipe_r, pipe_w = os.pipe()
try:
    run("opt-in rejects a pipe relay", base | {"LD_PRELOAD": lib, "UHF_ENABLE": "1", "UHF_RELAY_FD": str(pipe_r)}, fds=(pipe_r,))
finally:
    os.close(pipe_r); os.close(pipe_w)
stream_a, stream_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    run("opt-in rejects an unframed stream relay", base | {"LD_PRELOAD": lib, "UHF_ENABLE": "1", "UHF_RELAY_FD": str(stream_a.fileno())}, fds=(stream_a.fileno(),))
finally:
    stream_a.close(); stream_b.close()
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
failures = []
packets = [0]
def echo_fixture():
    try:
        while True:
            data = b.recv(1024)
            if not data:
                break
            if len(data) != 64:
                raise AssertionError(f"transport report length {len(data)}, expected 64")
            packets[0] += 1
            if data[0] == 0xe3:
                break
            reply = data[:63] if data[0] == 0xe1 else data + b"\0" if data[0] == 0xe2 else data
            b.sendall(reply)
    except Exception as error:
        failures.append(str(error))
    finally:
        b.close()
thread = threading.Thread(target=echo_fixture, daemon=True)
thread.start()
try:
    run("explicit opt-in, packet-preserving opaque echo fixture", base | {"LD_PRELOAD": lib, "UHF_ENABLE": "1", "UHF_RELAY_FD": str(a.fileno())}, "active", (a.fileno(),))
finally:
    a.close()
thread.join(timeout=5)
assert not thread.is_alive() and not failures, failures
input_lines = [[line for line in result.splitlines() if line.startswith("INPUT_REAL ")] for result in results]
assert len({str(value) for value in input_lines}) == 1, "Unrelated input enumeration changed"
print(f"\nPASS fixture received {packets[0]} opaque 64-byte packets; no credentials or CTAP/WebAuthn success synthesized")
print("PASS unrelated input enumeration matches no-preload baseline exactly (empty here; no actual sysfs device coverage)")
