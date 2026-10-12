# Native mode and Chromium's authenticator dialog

Select Native before the website request. Stock container Chromium owns real
registration/sign-in, device selection, QR codes and results. The outer page
manages mode and the local helper connection; it does not generate, capture or
replace the QR code.

## Workflow

1. Choose Native relay ("原生中继") on the lower-left browser control strip. The
   upper-left navigation is independent of this draggable, collapsible strip.
2. Start `webauthn-helper` or `webauthn-helper-desktop` and enter its displayed
   address, normally `ws://127.0.0.1:10233`. Address and Connect stay available
   during approval, successful pairing and retries.
3. Verify and approve the exact outer-page Origin in the helper. Only approved
   Origins are remembered in process memory. Explicit rejection keeps that
   Origin blocked locally while the page continues trying to connect, until
   the helper user explicitly allows another approval request.
4. Wait for real engine detachment and helper pairing confirmation. The green
   address check means those states are ready; it does not prove scanning, phone
   connection or authentication. Temporary disconnects show a spinner and retry
   at one-second intervals rather than turning the address field red.
5. Start registration/sign-in on the container website and use the choices
   Chromium actually offers. For a phone, scan its real QR code, keep the phone
   near the helper computer and confirm there. Switching to Software simulation
   ("软件模拟") returns to the stored software authenticators.

## Session and cancellation

- Mode ownership is independent of an individual `create`/`get` request.
- Switching cancels in-flight intercepted software requests; they cannot be
  transferred in place. Start a new request on the website.
- Only one helper connection attempt is current. Address changes, explicit
  Connect, mode changes and leaving the page invalidate old callbacks.
- Mode uses bounded renewable authority within the original login/CSRF lifetime,
  with extension acknowledgment. Late renewals or old-tab cleanup cannot revive
  expired/logged-out/revoked ownership or cancel a newer owner.
- Pairing tokens are single-use. Reconnect rotates a potentially sent token;
  approved-Origin memory lives only in the helper process.
- Reattaching the software proxy cannot retract work already handed to Chromium's
  native authenticator. Cancel an existing native dialog there when needed.

## Supported transports

The phone hybrid/caBLE path relays BLE discovery advertisements:
phone → local helper → outer-page WebSocket → gateway → private container
BlueZ/D-Bus → Chromium. Phone and Chromium own the caBLE tunnel and signatures.
This is not generic Bluetooth/USB forwarding or legacy BLE GATT. A software
credential's USB type likewise does not attach a physical USB device.

Linux Chromium discovers USB authenticators through HID. A WebSocket alone cannot
create a hidraw endpoint, and BlueZ's userspace D-Bus surface cannot substitute for
USB HID. The [experimental FIDO USB path](experimental-fido-relay.md) provides a
FIDO-only userspace ABI on Linux x86_64, subject to genuine libudev-monitor
prerequisites, fresh device generations and renewable control leases. Ordinary
startup needs no extra experimental flag. After exact-Origin approval and pairing,
the helper opens only an interface matching the restricted FIDO descriptor.
Keyboard/arbitrary USB forwarding and RP/credential substitution are excluded.

Static and explicit simulation checks cover this path. User reports of working
Desktop USB/BLE and CLI BLE, followed by intermittent USB behavior, are separate
from development evidence; real hardware acceptance has not been performed here.
Helper pairing, launcher readiness and report-endpoint attachment are distinct.
USB unavailability is shown separately while BLE and software remain usable.

No host device mount, privileged mode, UHID setup or Chromium patch is added.
Website transports/authenticatorSelection and browser policy still constrain
native choices; Native mode cannot force a site to accept a transport it excludes.

## Evidence boundary

Unit/component/protocol/executable checks do not replace hardware acceptance.
Existing Chromium/Unix-socket EPERM restrictions in the development environment
were not bypassed. Full Docker, Chromium, phone and USB authentication has not
been validated there. Seeing a broadcast adapter in Chromium proves enumeration
only, not successful authentication.

## Diagnosing a phone stuck on Connecting

The helper's scanning status means local BLE scanning started. It does not prove
Chromium received a packet or completed a caBLE network tunnel/WebAuthn request.
Standard tracing logs report adapter readiness and scan start/stop/failure at
INFO. Five-second accepted/dropped diagnostics are DEBUG-level (see the
[helper logging options](../helper/README.md)); missing default INFO counters do
not imply zero traffic. Accepted means valid FFF9/FDE2 data entered
the helper WebSocket queue; logs exclude payloads, hardware addresses and QR data.

`docker compose logs -f webauthn-browser` includes bridge discovery, forwarded
and waiting_for_discovery counters:

- Helper accepted stays zero: check local Bluetooth permission, distance and actual
  phone advertising; this is not a container authentication-success signal.
- Accepted increases but no container relay stream/forwarded: inspect the outer
  connection and current Native session.
- waiting_for_discovery increases: advertisements reached the container but
  Chromium has no active discovery. Check a new Native website request and its
  open QR/device chooser.
- forwarded increases while the phone still waits: data reached private BlueZ.
  Chromium decryption, networking and site validation still need real diagnosis;
  counters alone cannot establish success.

Visiting Settings and returning in the same tab preserves Native ownership.
Counters describe only stages actually traversed; they do not guarantee a fix
for every Connecting failure.

Pinned source: [v2_discovery.cc](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/device/fido/cable/v2_discovery.cc)
reads Google/FIDO ServiceData on DeviceAdded/DeviceChanged and starts LE discovery.
[v2_constants.h](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/device/fido/cable/v2_constants.h)
sets v2 advertisement size to 20 bytes. The bridge's v2_sized counter counts only
published observations of that size; it does not inspect encrypted data or prove
matching the current QR code. The later hybrid network tunnel does not depend on
this bridge's GATT Connect.

## Linux service-data filtering

[btleplug's upstream notes](https://github.com/deviceplug/btleplug#scan-filtering-on-linux-bluez)
warn that Linux BlueZ UUID scan filters may discard service-data advertisements.
The Linux helper therefore omits the OS UUID list but retains strict local
FFF9/FDE2 checks, 1–64-byte payload bounds and at most 20 successfully queued items
per second. Windows/macOS OS filtering is unchanged. Unrelated advertisements,
addresses and payload logs are excluded.

The events_seen/service_data_events/discovery_update_notifications counters
distinguish no events, discovery-only notifications and nonmatching service data.
Discovery/update notifications can be cached and do not prove fresh proximity;
cached ServiceData is not reread/replayed. adapter_count/selected_index reveal
only count and selected index, never hardware addresses. Selection remains the
first adapter; the counters do not assume the phone is at fault.

USB has separate `[native-usb]` transition logs: control handshake sent, genuine
HID monitor READY, prerequisites unavailable, PREPARE, ACTIVE and peer retired.
READY proves monitor prerequisites; ACTIVE is an endpoint-control acknowledgment.
Neither means website authentication succeeded. Repeated waiting messages are
deduplicated, with no attachment IDs, tokens, FDs or reports logged. Simulated
READY is explicitly test-only and cannot stand for real-environment evidence.
