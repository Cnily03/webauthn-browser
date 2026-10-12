# Session-gated FIDO launcher and device generations

## Current implementation and scope

The original one-shot adapter could not safely be connected by adding `pass_fds`
alone. That assessment led to an implemented session-gated control plane: private
supervisor IPC, authenticated backend Prepare/Activate, renewable device generations,
terminal cancellation, and a genuine libudev monitor adapter. The normal adapter
requires successful untouched libudev construction, filters, receive enablement
and a usable monitor FD; it does not hide their failures. Its native ABI behavior
is tested using an explicitly linked mock libudev source. A separate compile-only
simulation adapter is visibly marked and rejected by production consumers.

The software mode and existing native hybrid/BLE flow remain available. The packaged
launcher prepares its trusted control channel automatically; this creates no virtual
device or report endpoint until an approved Native session requests activation. This source implementation is an experimental, runnable path
for a compatible environment, **not a verified Chromium USB/WebAuthn result**.
No actual Chromium or real monitor retry was performed during this stage.

## Pinned Chromium process placement

The normal Linux FIDO HID path is browser-process hosted in Chromium 154.0.8037.57, upstream commit `73c14f6228d7cd537c855007e8f88678969cc0eb`:

1. `device/fido/fido_discovery_factory.cc:46–51` creates `FidoHidDiscovery` for USB HID.
2. `content/browser/browser_main_loop.cc:1458–1459` installs its binder. Lines 422–430 dispatch binding to the browser UI thread and call `GetDeviceService`. [Pinned source](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/content/browser/browser_main_loop.cc#422)
3. `content/browser/device/device_service.cc:81–126,131–147` creates and owns `DeviceService` in browser UI sequence-local storage. It does not launch a utility process. The additional `device/` component in this path matters. [Pinned source](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/content/browser/device/device_service.cc#81)
4. `services/device/device_service.cc:208–214` directly owns `HidManagerImpl`, whose constructor calls `HidService::Create` (`services/device/hid/hid_manager_impl.cc:28–36`). [Device service](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/services/device/device_service.cc#208), [HID manager](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/services/device/hid/hid_manager_impl.cc#28)
5. `services/device/hid/hid_service.cc:72–74` selects `HidServiceLinux` with `USE_UDEV`. Linux enumeration and device opens use task runners in that hosting process (`hid_service_linux.cc:380–385,419–426`). [Factory](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/services/device/hid/hid_service.cc#72), [Linux implementation](https://chromium.googlesource.com/chromium/src/+/73c14f6228d7cd537c855007e8f88678969cc0eb/services/device/hid/hid_service_linux.cc#380)

Thus the initial browser process is the appropriate injection target; renderer, utility, or zygote access is not required for this normal path. Mojo interfaces and a build target named `utility` are not evidence of an out-of-process HID service. This source conclusion does not establish actual FD retention, downstream binary equivalence, or observed browser success.

The original investigation recorded six additional source files in its local `launch-source-manifest.json`, alongside an 18-file HID manifest, and checked hashes and parent-tree Git blob IDs. Those archived investigation files are not required build inputs for this repository; the pinned upstream links above identify the evidence. No Chromium rebuild was attempted.

## Implemented process and session ownership

`runtime/supervisor.py` launches the gateway and initial browser as independent
children. `runtime/fido_control.py` creates one private anonymous control channel
for each recorded child epoch. The gateway receives only its own channel. The
initial, explicitly verified `/usr/lib/chromium/chromium` ELF receives the hook and
browser channel. Window-reopen and extension-recovery singleton launchers remain
uninjected. A wrapper script is not an acceptable injection target: it could
spread preload to helper commands and consume the intended initial exec ownership.

The supervisor checks regular ELF architecture/type, root/current ownership,
trusted nonsymlink path components, write permissions, set-ID bits and file
capabilities. It does not relax any of these checks to accept a writable hook.
A failed preflight leaves the ordinary browser path usable and reports the
experimental control unavailable.

Only an existing authenticated helper-session owner in confirmed native mode can
request a fresh report endpoint. Backend checks run before Prepare, before Activate
and after the exact acknowledgement. Each reservation binds the exact pairing
token and mode generation; cancellation while awaiting an ACK cannot attach later.
The browser and gateway do not receive a shared startup report socket.

Each attachment owns a new packet endpoint and unique device path. Revocation makes
old virtual opens/read/write aliases terminal even if old packets remain queued.
Fresh device, attachment and process identities prevent a late frame from reaching
a replacement. Reusing a numeric FD never rebinds an old alias. Browser restart and
gateway restart have independent epochs; no mode change implicitly restarts the
user's browser or transfers an old CTAPHID transaction.

The supervisor retains one tracked report-FD duplicate solely for terminal
`shutdown(SHUT_RDWR)` and close. It never reads reports. Child/control loss, expiry,
malformed IPC or bounded-send failure revoke that duplicate; it cannot silently
keep an abandoned connection usable. Sender transient copies close after SCM_RIGHTS
transfer. See [exact control protocol and bounds](fido-control-protocol.md).

## Genuine monitor adapter and failure boundaries

The hook wraps only owned monitor records after the real libudev constructor
succeeds. Genuine filter, enable, get-FD and receive results remain authoritative;
unknown pointers delegate to the real API. A bounded worker polls the genuine
monitor FD and a private acknowledgement endpoint. It sends one genuine-readiness
token to a pollable socket, then waits for the caller's real `receive_device` to
rearm. Synthetic FIDO add/remove tokens share that bounded readiness source.
The worker never consumes genuine device events or authenticator reports.

A socket-backed readiness mux retains SO_COOKIE-based identity protection. A plain
epoll FD was rejected because its anonymous-inode stat identity cannot prove
open-file-description identity after raw close/reuse. This design adds no kcmp,
ptrace, seccomp, kernel HID, UHID, host mount or generic USB prerequisite.

Startup can report Unavailable while no genuine enabled monitor exists and later
report Ready when the real prerequisite succeeds. Losing the last qualifying
monitor revokes the current generation. A new monitor can restore readiness but
cannot revive the old generation. Errors from real monitor construction or enable
are returned unchanged; no successful monitor is invented after EPERM.

The compile-only `simulation` feature is for deterministic C ABI tests. Its explicit
constructor cannot be enabled by environment variables and its ACK flags include
bit 128. Production supervisor/gateway reject this bit. Tests of the normal adapter
instead link an explicit mock libudev library; they demonstrate the real wrapper's
ABI/control behavior, not an actual netlink monitor or kernel event source.

## Renewable authorization and observable status

Each confirmed absolute CLOCK_MONOTONIC grant lasts at most 30 seconds and is capped
by current native/helper authorization. A healthy pair renews the **same** endpoint
and generation through helper ACK, conservative transit subtraction, authenticated
backend request and native ACK. The old deadline remains binding until the new ACK
is validated. Missing/ambiguous acknowledgements are terminal, with no transaction
replay. Mode exit, logout, token rotation, helper disconnect, endpoint failure and
page teardown cancel the matching generation.

`experimental_fido_launcher_ready` and `experimental_fido_available` are separate.
The page needs a fresh actual helper FIDO advertisement as well as backend readiness
before opening. If USB is advertised but the browser channel is unavailable, a
separate notice explains that helper pairing and BLE can still work. No transport
status is labeled USB-connected or successful WebAuthn.

## Build and enable in a compatible environment

The self-contained source layout is:

- `native-hid-hook/`: Rust cdylib, thin C ABI, license and bounded native tests.
- `src/fido-relay/src/control.rs`: MIT std+libc wire implementation, source-included
  through the relative `../../src/fido-relay/src/control.rs` path.
- `runtime/fido_control.py`, `src/relay/fido_launcher.rs`, `src/relay/fido_relay.rs`: process,
  authorization and opaque report adapters.
- `helper/src/relay/usb/`: separately approved physical FIDO-only adapter.
- `tests/ctap2_fixture/`: disposable ephemeral signed CTAP2 fixture and no-launch-by-default browser acceptance runner.

From the repository root, use the installed Rust toolchain and C compiler:

```sh
cargo build --locked --release --manifest-path native-hid-hook/Cargo.toml
cargo test --offline fido_launcher::tests
cargo test --offline relay::fido_relay::tests
python3 -m unittest discover -s tests -p '*test.py'
```

The Docker builder compiles the normal hook only on Linux x86_64 and installs it
root-owned/read-only under `/opt/webauthn-browser/native/`. Other architectures
retain the ordinary default browser path and do not get this hook. No target,
shared object, report logs or credentials are committed.

Ordinary `docker compose up --build -d` prepares the packaged browser control path;
there is no separate USB enable flag. Select Native mode and approve the helper's
exact Origin. The image's `AUTH_BROWSER_FIDO_HOOK_PATH` points to its packaged
library. A custom path must meet the same trusted-path checks. Explicit
`AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY=0` is an emergency opt-out, not a required
startup setting. Malformed overrides, missing libraries and unsupported architectures
fail closed while leaving software/BLE available.

Only the gateway child receiving an actual private control FD gets the normalized
internal enable marker. Secondary launchers and unrelated children receive neither
that capability nor the preload. Never set global `LD_PRELOAD` or `/etc/ld.so.preload`.
Existing live browser instances are not silently restarted or retrofitted. Helper
CLI/Desktop default to FIDO availability, but require a live approved pairing before
discovery/open; `--disable-usb` or the Desktop USB checkbox opts out. One exact
qualifying key can attach; multiple keys require explicit selection. See
[helper restrictions](helper-usb-fido.md). No sandbox or device permission changes
are implied.

A genuine Chromium HID monitor may be initialized only when a website first asks
for FIDO. While that prerequisite is pending, the page renews the advertised but
unopened helper offer only under live paired/Native authorization. No CTAP report is
forwarded before open. Strict helper lease sequences continue across the eventual
open; native lease sequences begin independently when its fresh generation exists.
This avoids an otherwise terminal 30-second idle timeout before a first request.

## Fork ownership and remaining acceptance

Standard libc-fork cleanup closes only identity-matching dedicated control/report
capabilities, virtual aliases, ordinary/chained duplicates and in-flight pins.
Registries are frozen in a fixed order, and child callbacks allocate/free/resolve
nothing. Per-process owner markers and close-on-exec flags prevent ordinary inherited
exec from initializing another hook. Unrelated descriptors reused at old numbers
are preserved. New monitor/control resources follow the same bounded ownership.

This is lifecycle hygiene, not a sandbox boundary. Raw fork/clone, untracked raw
SCM/duplication, private-FD manipulation, deliberately altered owner/CLOEXEC markers,
same-PID exec with retained aliases and incompatible third-party atfork ordering
remain unsupported. Actual Chromium descendant sanitization still needs observation.

A normal-sandbox browser acceptance run must establish all of:

1. The actual initial browser maps the intended library, owns the endpoint and
   hosts observed libudev/HID calls; constructor success is insufficient.
2. Renderer/utility/zygote/raw-fork descendants retain no usable report/control
   capabilities, including singleton and recovery races.
3. Real libudev monitor startup succeeds; Chromium's genuine HID parser accepts the
   FIDO-only descriptor and its poll/read/write path exchanges complete reports.
4. Removal during a request, new owner/session, renewed leases and independent
   child restarts create distinct generations without late-frame crossover.
5. The real outer-page/helper path reaches a disposable CTAPHID/CTAP2 authenticator
   and verifies create/get signatures. A physical key is not required for this test.

The earlier unchanged singleton-socket EPERM and genuine-monitor EPERM observations
remain valid environment limitations. Tests in this stage use anonymous sockets,
explicit mocks, native C ABI, authenticated HTTP and jsdom; none asserts actual
Chromium discovery. Docker image execution, real physical USB and macOS helper
binaries remain separate unverified stages.

## Historical checkpoint

Before generation control, the isolated one-shot hook was hardened at SHA-256
`f512bdbf00b6f50e4869973e8067f63f41fc54a96976fbffd28ac806d30f0bd5`.
Its 11 fork/owner and 2 endpoint-generation cases showed that old aliases stayed
terminal after peer replacement but could still contain previously queued reports.
That hash describes the earlier library, **not** the current generation build.
It remains in the separate experiment's preserved evidence. Current source and
validation totals are recorded in [TESTING](../TESTING.md), with the relevant native
scripts shipped beside the source.
