# Experimental physical FIDO USB adapter

## Scope and local controls

The helper now has an experimental physical adapter for **one selected USB FIDO
interface** on Linux and Windows. No-argument CLI and Desktop startup enable it,
but discovery/open waits for exact-Origin approval and authenticated pairing.
Software mode and an unpaired helper create no HID attachment. Disable it for
this process with `--disable-usb`, or clear the native Desktop **USB** checkbox. `--disable-ble` independently disables Bluetooth. The old
`--disable-fido` and activation flags are removed. Nothing is saved.

Discovery starts only after the existing exact-Origin approval and authenticated
pairing succeed. One matching interface opens automatically. If several match,
the CLI prints opaque identifiers for `usb select IDENTIFIER`; Desktop shows
separate Attach choices. Identifiers belong to the current discovery and paired
connection, rather than an index into a changing device list. Identical devices
may share labels; disconnect unwanted keys before an explicit disable/re-enable reset if
needed to select the intended key. Paths and serial
numbers stay private to the local worker protocol and are never displayed or
logged. `usb status`, `usb detach`, and `usb retry` provide local controls;
Desktop has equivalent status, Detach USB, and Retry USB buttons.

Explicit **Detach USB** / `usb detach` suspends USB across automatic helper
re-pairing until explicit Retry USB / `usb retry` or checkbox off/on. Internal
disconnect/cancellation does not set this user suspension latch.

A selected device is never silently replaced during an attachment. Discovery or
open errors, unsupported descriptors, permission denial, unplug, malformed I/O,
queue overflow and lease failure close the attachment. They do not auto-retry on
the same helper connection. Retry is explicit. Across helper re-pairing for the same backend session and Origin, the exact
selected device metadata is retained in memory. Only that device may reopen; a
missing/ambiguous match fails without falling back, even if another sole key is
available. Retry preserves this choice. A new backend session or explicit checkbox
off/on resets it. The memory is bounded to one choice and is never persisted or
logged. Existing once-per-Origin process consent still applies. Explicit helper rejection/revoke/stop
retains its existing terminal behavior.

## Restricted device profile

Candidates must report USB bus, usage page `0xF1D0`, usage `1`. After opening the
exact discovery identity, the worker checks the opened-device metadata again and
validates its report descriptor. The initial conservative profile accepts only:

- One FIDO Application collection, without nested or additional collections
- Unnumbered 64-byte Input usage `0x20` and Output usage `0x21`
- Eight-bit data/variable/absolute fields, logical range 0–255
- No report IDs, feature reports, mixed keyboard/mouse/vendor usages, long items,
  global push/pop, or ambiguous/truncated descriptors

HIDAPI writes contain the required zero report-ID prefix plus the 64-byte opaque
payload. Full 65-byte write completion is required. Reads must be exactly 64
bytes; a 65-byte read buffer detects and rejects oversized/numbered reports.
Unsupported legitimate FIDO descriptors are rejected rather than rewritten.
This is not arbitrary HID support, all USB security-key support, or an all-
transport authenticator bridge. PIN, touch, user presence and user verification
remain authenticator/browser policy. The adapter interprets no CTAP payload and
never creates signatures, credentials, approvals or successful assertions.

## Cancellation, ownership and renewal

All HIDAPI calls run in a disposable copy of the helper executable, before its
normal listener/UI starts. The child receives only inherited private stdin/stdout
pipes; stderr is discarded. Its bounded, length-prefixed protocol permits one
discovery, one selected open, and serial opaque report exchanges. The child entry path performs
no network operations and has no logger or automatic reopen. This is process isolation for
cancellation, not an OS security sandbox.

Linux sets a parent-death SIGKILL and checks the expected parent PID in the
pre-exec child, before HIDAPI initialization. Windows assigns the child to a
private KILL_ON_JOB_CLOSE Job before any Discover/Open command; assignment
failure kills and refuses the worker. No global job policy or breakaway setting
is changed. Abrupt parent death therefore cannot leave a normal blocked worker
holding a device indefinitely. Linux behavior is covered by a killed-parent /
blocked-fake-child test; Windows has compile evidence only.

The parent retains exact Origin, session, helper request and epoch ownership. It
revalidates before discovery/open, atomically when attaching, and around each I/O
exchange. A 10 ms watchdog also checks the actual renewable attachment ownership
and deadline while an exchange is pending. Every pipe exchange has a two-second deadline. Cancel, disconnect,
expiry or failure kills the child; process reaping is capped at 750 ms. A failed
reap or task cleanup is **cleanup unconfirmed**, blocking replacements until the
helper restarts. Killing a process cannot guarantee immediate kernel-device
cleanup on a malfunctioning OS; the UI does not claim otherwise.

A relay lease initially lasts at most 30 seconds. Authenticated `fido_renew` /
`fido_renewed` messages extend the same live endpoint using a separate strictly
increasing lease sequence, capped at both 30 seconds and the existing paired
helper expiry. Renewals never replay reports or reopen a device. Expired leases
cannot be resurrected. Duplicate/invalid matching renewals revoke the relay.
The page/launcher side must also acknowledge its bounded native renewal; helper
acknowledgment alone is not proof of end-to-end transport availability.

The current helper pairing still has its finite five-minute lease. Re-pairing
creates a new attachment and device generation, with no old transaction replay;
the browser's separately authorized global native mode can remain selected.

## Dependency provenance and validation boundary

Pinned official Rust crate: `hidapi = 2.6.7`, from crates.io / hidapi-rs.
The downloaded crate SHA-256 was checked against the official registry index:
`818c0e1d27887aaf76fe737042e27a66b796a7b099e6d2e1a72d106c2dff3fa6`.
Linux uses `linux-native-basic-udev`; Windows uses the bundled upstream HIDAPI C
backend with the existing MinGW compiler. No host package installation or device
permission changes are required by the build. Normal OS device permissions are
still required at runtime. The Windows native-Rust backend was not selected
because its immediate-success write path returns an ambiguous zero-byte count.
macOS has no physical adapter in this iteration; no Apple executable is claimed.

Sources:
- https://docs.rs/hidapi/2.6.7/hidapi/struct.HidDevice.html
- https://docs.rs/hidapi/2.6.7/hidapi/struct.DeviceInfo.html
- https://docs.rs/crate/hidapi/2.6.7/features
- https://github.com/ruabmbua/hidapi-rs
- https://github.com/libusb/hidapi
- https://index.crates.io/hi/da/hidapi

Validation is static and simulated. Tests use pure fake backends and Python
standard-library worker fixtures over private pipes. They do **not** enumerate
or open any real HID device, invoke the real HIDAPI child, change permissions,
or authenticate with hardware. Test sources are in
`helper/src/relay/usb/{mod,descriptor,backend,supervisor}.rs` and
`helper/src/relay/fido.rs`, with unit suites at the end of their owning modules. Linux and Windows compilation is separate from
hardware, OS permissions, real-browser routing or end-to-end passkey validation.

While the real Chromium HID monitor is starting, the same advertised USB offer
may renew with strictly increasing lease sequence numbers before `fido_open`.
Each extension remains bounded by 30 seconds and the live pairing expiry. No HID
report read/write occurs before open, and opening preserves the consumed renewal
sequence. Expired, cancelled, replayed or uncertain attempts never restart
automatically or replay a transaction. Physical attachment status distinguishes
waiting for the browser transport from a ready report relay.
