# WebAuthn Helper

`webauthn-helper` is the CLI; `webauthn-helper-desktop` is the native egui/eframe
app. Both accept an inbound browser pairing, request local approval of its exact
Origin, and share BLE discovery forwarding and a Linux/Windows FIDO USB adapter.
Neither requires Node, Python, a local browser extension, or a WebView to run.

## Quick start

1. Run the matching executable from `/downloads`. CLI starts listening immediately;
   Desktop starts stopped. In Desktop, click **Start listening**.
2. Use the actual helper address in the outer WebAuthn Browser Native controls.
   CLI prints `Listening: ws://127.0.0.1:PORT`; Desktop shows the plain address.
   The webpage opens the connection and sends its one-use pairing frame.
3. Approve only the exact Origin you trust. Enabled transports become available
   after that socket successfully pairs. Opening a socket alone starts no device.
4. Continue sign-in in the container website. For a phone, scan container
   Chromium's native QR, keep the phone near the helper, and approve on the phone.
   For USB, follow the selected authenticator's normal PIN/touch flow.

```sh
./webauthn-helper-linux-x86_64
./webauthn-helper-linux-x86_64 --listen 127.0.0.1:18863
./webauthn-helper-linux-x86_64 --disable-ble
./webauthn-helper-linux-x86_64 --disable-usb
```

Both channels default on. Disabling BLE stops only scanning; disabling USB closes
only its device transport. Either or both can be disabled while the listener and
approved browser pairing remain alive. The old `--disable-fido` and
`--experimental-fido` flags are rejected. Use `--help` for current options.

Every process starts at port **10233** unless CLI `--listen` overrides it. Only
`127.0.0.1` and ports 1024-65535 are accepted. Binding tries 20 consecutive ports,
then an OS-selected free port, retaining the successful listener throughout.
It never probes existing services. Use the actual resulting address; `/` is the
WebSocket endpoint and `/bridge` remains a compatible alias. The listener serves
plain HTTP/WebSocket. A `wss://` address requires a separately configured trusted
local TLS endpoint.

No port, Origin approval, token, or device choice is written to disk. Desktop
Stop/Start preserves its current address; CLI `port PORT` changes only this
process. Old configuration files are ignored.

## Local consent

Only one pairing candidate can await approval. CLI shows its full Origin in a
magenta inline panel with cyan selected `[ Approve ]` / `[ Reject ]` controls.
Left/Right or Tab changes the choice; Enter defaults to Approve. The panel never
clears scrollback or enters an alternate screen. Desktop shows a native dialog
with the same channel-aware question and bottom-right Approve/Reject buttons.

Approval remembers the exact canonical Origin for this process. Later requests
from that Origin skip the prompt but still need fresh socket-bound, one-use
tokens. A different scheme, host, or port requires approval. BLE starts only after
successful pairing; USB additionally requires its current session binding.

- **Reject, Revoke, or Stop:** withhold the affected Origin across fresh tokens,
  backend sessions, and listener restarts. Revoke also forgets all approvals and
  withholds those Origins. Stop retains previous approval memory.
- **Local reset:** CLI `allow ORIGIN` or Desktop **Allow a new pairing request**
  removes withholding without adding approval. A retained approval can still
  apply; a forgotten or never-approved Origin must be confirmed again.
- **Timeout, network loss, or lease expiry:** do not withhold the Origin. The
  browser can retry; remembered approval remains usable.
- **Non-interactive CLI:** a pending request is immediately refused and withheld
  if stdin or stdout is not a TTY. Restore the terminal and use the local reset,
  or restart. Piped input cannot approve a request.

Approval expires after 60 seconds. A paired helper socket has a 300-second lease;
`lease_expired` allows a still-authorized browser to obtain a fresh token and
re-pair. Browser retries after `closed` cannot bypass local withholding or reopen
its prompt. Restarting the helper clears all process-only consent state.

CLI input is bound to the pending request. Buffered/repeated Enter, pasted keys,
EOF, expired answers, and answers for a disconnected request cannot approve its
replacement. A terminal too narrow for the complete Origin fails closed. Raw
mode and cursor state are restored after completion, cancellation, errors, and
panic cleanup.

### Terminal commands

- `start`: retry BLE scanning for an approved, BLE-enabled connection.
- `stop`: withhold the active/pending Origin, revoke pairing, and stop transports.
- `revoke`: also clear remembered approvals and withhold those Origins.
- `allow ORIGIN`: clear that exact Origin's withholding without granting approval.
- `status`: show listener, browser, scan state, and event count.
- `port PORT`: stop this listener and bind a new loopback port for this process.
- `usb status`, `usb select IDENTIFIER`, `usb detach`, `usb retry`: local USB controls.
- `help`, `quit`: show commands or clean up and exit. EOF/Ctrl-C also exit.

Never paste a pairing token into a terminal command. The webpage sends it in the
first WebSocket frame; it is absent from URLs, ordinary logs, and snapshots.

## Desktop controls

**WebAuthn Helper Desktop** has a centered **Listen Address** field, one Start/Stop
button, and Listener/Browser/BLE/USB status rows. All rows reserve the same
checkbox column; only BLE/USB have checkboxes immediately before their dot and
label. The label/input use slightly larger text. Device choice appears only when
multiple matching USB interfaces require selection.

Listener, browser pairing, BLE scanning, and USB relay readiness are separate
states. `BLE: listening for phone` describes receive-only scanning. An opened USB
device waiting for the browser is not shown as a connected report relay. Starting,
stopping, unavailable, and unconfirmed cleanup remain distinguishable.

**Stop listening** revokes pairing, stops transports, closes browser sockets, and
releases the port. Window close requests bounded cleanup; failure stays visible
instead of being reported as a successful stop. There is no persistent log panel.

## Transport boundaries

### BLE

The helper forwards only FFF9/FDE2 ServiceData advertisements used by hybrid/caBLE.
It creates no passkey, signature, user-verification result, or proximity evidence.
Device names, MAC addresses, RSSI, manufacturer data, and GATT traffic are excluded.

Linux leaves the OS service-UUID filter empty because BlueZ can drop
service-data-only advertisements there; Windows/macOS retain their OS filter.
The local UUID allowlist, 1-64-byte payload bound, bounded queue, and 20-per-second
forwarding cap still apply. Only actual ServiceDataAdvertisement events are
forwarded. Cached discovery/update notifications are counted but their stored
ServiceData is never replayed. The first enumerated adapter is selected.
See [btleplug's Linux caveat](https://github.com/deviceplug/btleplug#scan-filtering-on-linux-bluez).

A forwarded observation or scan counter does not prove phone authentication.
Moving observations through a helper changes the native proximity trust boundary;
equivalent native-local proximity security is not claimed.

### FIDO USB

Discovery/open is gated by a live approved pairing. One matching FIDO interface
opens automatically; multiple interfaces require explicit selection. Only
USB usage page `0xF1D0`, usage `1`, FIDO-only unnumbered descriptors with exact
64-byte Input/Output reports are supported. Arbitrary HID, keyboards, NFC, and
legacy BLE GATT authenticators are outside this adapter's scope.

The selected device is retained in memory for the same backend session and
Origin across helper re-pairing. Missing or ambiguous devices never fall back to
another key. `usb retry` preserves that choice. Explicit `usb detach` stays
suspended across re-pairing until retry; Desktop uses its USB checkbox.
Disabling/re-enabling USB resets the local selection.

Device I/O runs in a supervised, killable child with bounded pipes and
parent-death cleanup. This supports cancellation; it is not an OS security
sandbox. Unconfirmed cleanup blocks replacement until helper restart. No host
permissions or device policies are changed.

Physical open and browser report readiness are separate. A waiting offer may
renew before `fido_open`; it performs no report I/O before open. Each strictly
sequenced renewal is capped at 30 seconds and the current pairing expiry. Open
preserves the consumed renewal sequence. Failed, cancelled, replayed, or uncertain
attachments never automatically replay a transaction. PIN/touch policy is unchanged.

Shared queues hold at most 258 reports, two maximum 129-report CTAPHID messages.
Full eight-report batches drain promptly while yielding to socket/control work;
every batch still checks ownership and expiry. See [USB scope and tests](../docs/helper-usb-fido.md).

## Logging

Both UIs use standard `tracing`/`tracing-subscriber` RFC3339 UTC timestamps and
levels. CLI writes to stdout; Desktop writes to stderr if a console/launcher
captures it. Windows Desktop creates no console or log window. Colors depend on
that output stream being a TTY and respect `NO_COLOR`.

INFO shows connection and transport-state changes; failures use WARN. A changed
Desktop BLE checkbox logs `BLE: enabled` or `BLE: disabled` even before listener
startup. Repeating the same setting neither logs again nor resets the scan-start
guard. These setting events are distinct from actual scanner transitions.
Periodic BLE/USB counters are DEBUG:

```sh
RUST_LOG=debug ./webauthn-helper-linux-x86_64
RUST_LOG=info,webauthn_helper::relay::fido=debug ./webauthn-helper-linux-x86_64
```

`RUST_LOG` accepts standard level/target directives; missing or malformed values
use INFO. Dependency targets remain disabled even at trace. Only the audited
lifecycle target permits library-generated ANSI; ordinary messages are sanitized.
A preinstalled Desktop subscriber is preserved and receives plain action words.
Canonical Origins may appear in connection logs. Tokens, reports, device identity,
advertisement payloads, and QR contents never do.

CLI operational logs use official `tracing-appender` with a bounded off-thread
queue of 256 records, each at most 8 KiB. Suspended output can discard ordinary
logs but cannot stall approved USB reports or renewal. Consent panels and answers
never enter that queue. Shutdown does not join the process-lifetime log worker
or invoke its potentially blocking timeout output; queued logs are best-effort.

## Platforms and downloads

The catalog has CLI/Desktop names for Linux x86_64, Windows x86_64 (`.exe`), and
macOS universal. The default source delivery has an empty downloads directory;
build or add the required executables separately. See the historical
[build records](../docs/helper-cross-build.md). When release files are prepared
locally, their optional `downloads/builds.json` records provenance and hashes.

- **Linux:** prior release files require glibc 2.39+, BlueZ/system D-Bus, an adapter,
  and normal Bluetooth permissions. libdbus client code is bundled. Desktop also
  needs X11-compatible display and OpenGL/EGL libraries.
- **Windows 10/11:** btleplug uses WinRT/system Bluetooth APIs. Files were built
  with official Debian MinGW tools and are unsigned. CLI uses the console
  subsystem; Desktop uses the GUI subsystem. Native execution is unverified.
- **macOS:** BLE source uses CoreBluetooth and Info.plist permission descriptions.
  The required Apple targets/SDK/frameworks are unavailable here. No current
  source-check or executable is claimed. Native CI is configured but unverified;
  signing, notarization, and permission attribution remain unverified. The physical
  USB adapter currently supports Linux/Windows only.

Browser HTTPS-to-loopback or Private/Local Network Access restrictions may apply.
Use supported browser permission flows. The helper does not install certificates,
change browser security flags, open firewall rules, or bypass OS restrictions.

The user reported working Desktop USB/BLE and CLI BLE, with intermittent USB
failures. Synthetic tests reproduced a CLI output stall and a maximum-message
queue/latency problem; both have software fixes. Those results do not establish
every real-host cause or successful hardware authentication. Development testing
uses fake devices, local sockets/pipes, source checks, and cross-compilation.
Native desktop rendering, Windows execution, and hardware E2E remain unverified.

## Build and test

From the repository root:

```sh
cargo fmt --manifest-path helper/Cargo.toml --check
cargo test --locked --manifest-path helper/Cargo.toml --features desktop --all-targets
cargo clippy --locked --manifest-path helper/Cargo.toml --features desktop,test-support --all-targets -- -D warnings
cargo build --locked --manifest-path helper/Cargo.toml --features desktop --bins
cargo build --locked --manifest-path helper/Cargo.toml --release --features desktop --bins
python3 tests/helper_http_smoke.py
python3 tests/helper_cli_pty_smoke.py --binary helper/target/debug/webauthn-helper
```

Python fixtures use `tests/requirements.txt`. The POSIX PTY suite covers keyboard
choices, colors, exact-Origin consent, refusal reset, reconnect, stale input,
disconnect, the real 60-second timeout, narrow/resize failure, and restoration.
Approved cases disable USB and direct BLE to an unavailable test D-Bus.

The fake-only examples require `test-support`; release builds must omit it:

```sh
cargo build --locked --manifest-path helper/Cargo.toml --examples --features desktop,test-support
python3 helper/tests/controller_modes_smoke.py --binary helper/target/debug/examples/controller-fixture --stress 1
python3 helper/tests/logging_smoke.py --binary helper/target/debug/examples/logging-fixture
```

Controller tests use the actual CLI loop/Desktop controller, identical fake-device
pipes, and real loopback WebSockets. Stress adds 129-report bursts, stale-relay
isolation, cancellation/revocation, and 32-second delayed responses with keepalives
and renewal. Stalled stdout stays suspended through transport work and exit.
The logger's 60 process cases cover sink TTY, NO_COLOR, filters, ANSI sanitization,
deduplication, and preinstalled subscribers without invoking a device API.
Rendered egui tests check row/button geometry, fonts, and request-bound controls
without opening a native window.

Include LICENSE, THIRD_PARTY_LICENSES.txt, and source when redistributing.
`downloads/builds.json` records the revision actually used for each shipped build;
a later documentation-only source commit does not change that provenance.

## Source and protocol

- `src/pairing/`: process consent, wire validation, session state, socket lifetime.
- `src/server/`: loopback listener, local `Handle`, HTTP controls, bounded writes.
- `src/relay/`: BLE forwarding, opaque FIDO transport, supervised USB modules.
- `src/cli/`, `src/desktop/`: UI-specific controllers, input, and logging sinks.
- `src/logging.rs`, `src/diagnostics.rs`: shared formatting/filtering and safe events.

Thin binaries preserve the public library API through named exports. Unit tests
are colocated in each owning module; shared testing modules contain fixtures.
True process integration tests remain under `helper/tests/`.

The first WebSocket text frame must arrive within five seconds:
`{"type":"pair","token":"<one-use token>"}`. An optional `session_id` contains
32-128 ASCII letters, digits, hyphens, or underscores; legacy omission still pairs,
but physical USB requires the session binding. Up to four incomplete handshakes
are bounded independently of the single approval candidate and authenticated
connection. Frames are limited to 8 KiB.

Pairing consumes each token once, including remembered-Origin reconnects. Limits
are 4096 consumed tokens and 256 withheld Origins. Exceeding either bound fails
closed until process restart; refusals are never evicted to reopen access. The capability-guarded
local control API uses the same validation; remote pairing frames cannot reset
local consent. Approval memory does not replace the outer webpage/backend's
fresh CSRF, token, or native-mode lease checks.

Disconnect, revocation, and expiry cancel owned transports. Cleanup checks the
request ID and epoch so an old socket cannot clear a replacement session. OS
cleanup failure is visible and blocks reuse. The local account/process is trusted:
loopback Host/Origin checks do not protect against compromised local software.
