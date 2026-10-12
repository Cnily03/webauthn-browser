# Opt-in control generations and native hotplug simulation

This document describes isolated native tests of the packaged Linux x86_64 preload hook. They do not demonstrate Chromium compatibility, browser reconnect, CTAP/WebAuthn success, a real authenticator, or a kernel HID device.

## Genuine monitor adapter and current evidence

The normal build implements a genuine libudev monitor adapter in `src/monitor.rs`. It preserves original new/filter/enable/get-fd results and errno. READY(flags=1) requires a real monitor object, successful real enable, a usable nonblocking real monitor FD, and successful bounded adapter setup. Before prerequisites exist, the control scope reports Unavailable(flags=0) and stays pending; later readiness emits READY. Last-monitor loss terminally revokes the current generation and reports Unavailable, while a later successfully enabled monitor can restore readiness for a fresh attachment.

A bounded readiness worker polls the genuine FD plus a private acknowledgement socket. It emits at most one outstanding genuine-readiness token and waits for the receive wrapper to delegate the real event before rearming. Synthetic add/remove tokens share the pollable Unix packet readiness endpoint. No worker consumes genuine events or HID reports. Synthetic overflow is terminal for virtual USB; its bounded wake tokens are drained, and unrelated genuine events continue forwarding without a readable-null busy loop.

All private endpoints have captured SO_COOKIE identities. Public endpoint use pins the original identity, and delayed cleanup cannot close or erase a replacement capability registered at a reused FD number. The ordinary real monitor owns its genuine FD; the adapter retains an extra genuine monitor reference until its readiness worker has stopped. Reference changes, filter metadata changes and receives are serialized per monitor under a fork gate. `filter_update` is a genuine-library passthrough after the lock-free fork-child check: it changes no adapter metadata and can be called internally through the PLT by genuine `enable_receiving` while the outer wrapper already owns its locks. No epoll anonymous-inode identity shortcut or extra syscall prerequisite is used.

The **normal-build adapter has been validated with an explicit test-only mock libudev source**, including original new/enable/get-fd/filter failures, event forwarding, filter isolation, restart, overflow, raw FD reuse, and standard-fork cleanup. This is distinct from the compile-only simulation feature. No new real netlink monitor or browser attempt was made for this stage. The earlier real-monitor EPERM evidence remains applicable to this environment. Successful Chromium discovery, authentication, real hotplug, and browser reconnect remain unverified.

The normal mock suite also covers an unfiltered monitor and an enumeration created
before monitor readiness. Enumeration stays hidden through Prepare, exposes one
generation after Activate, and hides it on Revoke. Reconstructed devices are checked
for hidraw/HID/USB ancestry, HID properties, USB product sysattr, generation-specific
paths, exact sealed descriptor bytes through `open64` and `fopen64`, and matching
HID descriptor/info ioctls. Revoked descriptor paths remain denied after a fresh
generation activates. These checks exercise the native discovery ABI contract;
they do not execute Chromium's HID parser or verify a particular browser binary.

### Genuine-library reentry regression

Some libudev versions implement `udev_monitor_enable_receiving` by calling the
public `udev_monitor_filter_update` through the PLT. Taking the adapter gate again
in the nested update deadlocks the owning thread and READY polling. The normal
mock now preserves that preemptible call, and its runner asserts the actual
`JUMP_SLOT` relocation. Against the prior hook this reproduced a bounded timeout;
with the passthrough fix the same path completes and emits READY. The suite also
checks nested update errors and errno without false readiness, fresh-monitor
recovery, direct update passthrough, and reference changes racing ordinary fork.
The outer enable's genuine reference and adapter locks remain held throughout.

The inspected local libudev exhibits this call chain; systemd v252 uses a different
internal enable call. This fixes a demonstrated compatibility defect, but does
not establish the cause of a particular user's container wait without matching
its library and runtime evidence. No genuine monitor or Chromium was launched.

A normal build has no simulated-monitor constructor. Setting `UHF_SIMULATION` or another environment variable cannot enable simulation or bypass genuine monitor prerequisites.

## Explicit modes

- Legacy: `UHF_ENABLE=1` plus `UHF_RELAY_FD=<connected Unix seqpacket fd>` retains the prior one-endpoint behavior and all legacy tests.
- Control: `UHF_ENABLE=1`, `UHF_CONTROL_FD=<connected Unix seqpacket fd>`, and a nonzero 32-hex-digit `UHF_BROWSER_EPOCH` select the metadata controller.
- Supplying both descriptor variables is rejected. Missing/invalid epoch, wrong socket type, and inherited/mismatched owner markers fail closed.
- Initial loading binds `UHF_OWNER_PID`, marks the retained control descriptor CLOEXEC, registers fork handlers, and then starts the nonblocking controller thread.

The exact MIT std+libc codec is source-included from `../../src/fido-relay/src/control.rs`; keep native-hid-hook and src/fido-relay in the same source checkout. It enforces canonical 96-byte frames and strict SCM_RIGHTS ownership. No authenticator report is logged.

## Generation guarantees exercised by tests

Prepare takes one freshly owned packet endpoint but keeps the device invisible. Matching Activate publishes an add event and exposes generation-specific paths. Revoke, lease expiry, report peer HUP/RDHUP, control EOF/protocol failure, or event queue overflow terminally revoke all retained HID handles. Hooked reads/writes and old-path opens then return ENODEV, including when old report packets remain queued. Old udev metadata remains readable until unref; no old path can open the next endpoint.

Prepare requires matching browser/gateway scope, an increasing device-generation high-water mark, nondecreasing owner mode generation, a fresh attachment ID, and an absolute CLOCK_MONOTONIC deadline within 30 seconds. Renew requires a still-live active lease, exactly the next sequence starting at 1, and a later bounded deadline, without replacing the endpoint or replaying a report. Revoke matches full attachment identity independently of lease fields, including pending renewals. Duplicate terminal revokes are harmless acknowledgements. Previously seen gateway epochs are rejected; their bounded history survives scope changes. Fresh gateway Hello after revoke/unavailable resets its generation high-water mark; its paths include gateway and attachment identity, so old paths cannot rebind. Unexpected acknowledgements, replays, and late activation fail closed.

The rights-registration mutex covers recvmsg, validation, rejection/drop, and capability registration. Atfork lock order is rights, genuine-monitor gate, FD registry, then udev registry. Child callbacks only identity-check/close already-registered socket capabilities and release frozen guards; they allocate/free/resolve no symbols. Owned genuine- and simulated-monitor child calls opt out through lock-free token registries before any mutex. The prior unsupported raw fork/clone, adversarial private-FD guessing, raw duplicate tracking, and atfork ordering limitations remain.

## Compile-only native simulation

`cargo build --offline --features simulation` enables an explicit C test constructor:

`struct udev_monitor *uhf_simulation_monitor_new(struct udev *context);`

It must be invoked explicitly; ordinary `udev_monitor_new_from_netlink` is not replaced. The resulting test pointer supports monitor enable/get-fd/ref/unref/receive-device and device ref/getter operations. It is not a general libudev monitor implementation. All READY/Prepared/Active/Renewed replies carry flags **129**, identifying simulation; production consumers must reject that bit. Production exports no constructor.

The simulation adapter uses a pollable nonblocking Unix packet wake pair. The genuine adapter uses a wake pair and an acknowledgement pair. Both are limited to 16 monitors and at most 32 queued synthetic events per monitor; genuine readiness is coalesced to one pending token. The genuine live-monitor bound includes workers awaiting shutdown. Overflow is terminal. Device trees are capped at 128, enumeration objects at 64, virtual descriptors at 256, capability aliases at 256, and transient operation pins at 256. Attachment replay metadata is capped at 256 per gateway scope; gateway epoch history is capped at 256 per browser owner. Reaching a bound cannot silently drop events or create unbounded retained metadata.

## Reproduce

Run `tests/test_control_hotplug.sh` from the hook directory. It builds the simulation explicitly, compiles the native C ABI harness, exercises anonymous control/report packet IPC, runs the shared codec tests and clippy, then restores the normal genuine-adapter build, verifies pending startup without fake readiness, and runs the explicit mock-libudev suite. It uses no browser, sudo, installation, daemon, real authenticator, kernel HID injection, or sandbox weakening.

Archived evidence filenames from the original investigation (generated logs are not
required source inputs and may not be present in a fresh checkout):

- `control_hotplug.log`: lifecycle, queued-report denial, renew/replay, bounds, EOF/HUP, malformed rights, gateway restart, queue overflow, and 128 forks racing 64 descriptor deliveries.
- `control_production.log`: absent simulation symbol, ignored simulation environment, and Unavailable(flags=0) while genuinely pending.
- `monitor_adapter.log`: normal-build genuine-adapter contract against the explicit mock libudev source.
- `control_final_validation.log`: that checkpoint's complete normal/simulation builds, strict clippy checks, wire unit tests, and native suites.
- `control_legacy_regression.log`: prior native ABI, all six fork lifecycle and five inactive-owner cases, and both legacy endpoint queue cases on the normal build. The legacy queued-packet behavior remains intentionally unchanged; terminal queue denial belongs to control generations.

## Test/source packaging

Required runtime build inputs are `Cargo.toml`, `Cargo.lock`, `build.rs`, `native/abi.c`, and `src/{lib,control,control_wire via source include,fd,udev,monitor}.rs`. The checked-in hook already uses the relative source include `../../src/fido-relay/src/control.rs`; preserve this source layout when packaging. Do not copy target directories, binaries, or generated Python bytecode.

The new source-only tests are `tests/udev_abi.h`, `control_hotplug_native.c`, `run_control_hotplug.py`, `run_control_production.py`, `mock_udev_monitor.c`, `monitor_adapter_native.c`, `run_monitor_adapter.py`, `test_control_hotplug.sh`, and this README. Dependencies are Linux x86_64, a Rust toolchain supporting the existing naked ABI trampolines, cached/pinned libc 0.2.190 for offline builds, a C compiler, Python 3, and libudev.so.1. The script uses the enclosing workspace toolchain when present, otherwise the caller's normal Cargo/Rust environment.
