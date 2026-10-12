# WebAuthn Browser FIDO-only userspace HID hook

Source-only Linux x86_64 Rust cdylib with thin C ABI trampolines. The Docker builder
compiles its normal feature set. Ordinary packaged startup prepares its control
channel; virtual-device activation still requires the approved Native session.
There is no kernel HID/UHID device, generic keyboard or all-USB forwarding.

The normal monitor adapter requires genuine libudev new/filter/enable/get-FD
success, multiplexes genuine readiness with bounded FIDO add/remove notifications,
and preserves unrelated real events. A fresh control generation owns one opaque
64-byte report endpoint; the hidraw output convention adds report ID zero (65 bytes).
Renewal retains the generation; revocation terminally disables old aliases.

See [launcher design](../docs/fido-launcher-design.md), [wire and ownership](../docs/fido-control-protocol.md),
and [native fixture details](tests/README-control-hotplug.md). The shared MIT
control codec is source-included from ../src/fido-relay/src/control.rs using a relative
path. No sibling experiment, fixed workspace path or precompiled library is needed.

## Build and tests

Use an installed Rust toolchain, Linux C compiler, Python3 and libudev.so.1:

```sh
cargo build --locked --release --manifest-path native-hid-hook/Cargo.toml
cd native-hid-hook
sh tests/test_control_hotplug.sh
python3 tests/run_fork_isolation.py
python3 tests/run_generation_reset.py
```

The control script explicitly builds both the compile-only simulation and normal
adapter, uses anonymous IPC and an explicitly linked mock libudev source, then
restores the normal build. It never launches Chromium or opens a physical device.
No environment flag can enable compiled-out simulation; production consumers reject
its visible simulation bit. Legacy tests/run.py additionally probes real monitor
construction and must only be used where that operation is permitted; it was not
repeated during the current genuine-adapter validation. The old browser probe is
not included here.

These tests are simulations/native ABI checks. Real Chromium discovery, signed
create/get over the whole outer-page path, physical USB interoperability and actual
raw-fork descendant sanitation remain unverified. Earlier singleton/monitor EPERM
failures were preserved without bypass.

## Limits

One active attachment, 64-byte unnumbered FIDO reports, bounded queues and explicit
caller-valid ABI pointers. Unknown libudev pointers delegate without dereferencing.
Standard libc fork closes tracked dedicated capabilities and preserves unrelated
FD reuse. Raw fork/clone, untracked raw duplication/SCM, deliberate marker/CLOEXEC
changes, adversarial private-FD access, same-PID exec with retained aliases and
incompatible third-party atfork ordering are outside this lifecycle contract.
This interposer is not a security sandbox. Non-null invalid user buffer/string
pointers are not safely probed or fault-recovered.

Original source: MIT (LICENSE). Pinned libc dependency: MIT OR Apache-2.0 (licenses/).
System libudev/glibc remain dynamically linked with their own distribution notices.
