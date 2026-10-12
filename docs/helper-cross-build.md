# WebAuthn Helper cross-build verification

The repository includes real Linux x86_64 and Windows x86_64 CLI and Desktop executables. See
`downloads/README.md` for the exact hashes and `helper/README.md` for runtime
requirements. Compilation is not Bluetooth/OS-permission validation.

## Windows GNU from Linux

Use Rust's official `x86_64-pc-windows-gnu` target plus a reputable distro's
MinGW-w64 x86_64 compiler, binutils and development headers. This delivery used
six official Debian packages verified against the repository's SHA-256 values,
extracted into an isolated build directory without global installation changes:
GCC MinGW 14-posix, GNU binutils 2.44, MinGW-w64 runtime and headers.

```sh
rustup target add x86_64-pc-windows-gnu
# Put the chosen distro toolchain's bin directory on PATH.
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
cd helper
cargo check --locked --features desktop --bins --target x86_64-pc-windows-gnu
cargo build --locked --release --features desktop --bins --target x86_64-pc-windows-gnu
for binary in webauthn-helper webauthn-helper-desktop; do
  x86_64-w64-mingw32-objdump -p target/x86_64-pc-windows-gnu/release/$binary.exe
  cp target/x86_64-pc-windows-gnu/release/$binary.exe ../downloads/$binary-windows-x86_64.exe
done
```

The resulting PE32+ is x86-64 and imports Windows system DLLs only. There is no
separate MinGW DLL to ship. It is unsigned; Windows execution, SmartScreen,
Bluetooth permissions and real phone authentication remain untested.

## macOS

The predecessor v30 source passed both official Rust targets
(`aarch64-apple-darwin`, `x86_64-apple-darwin`) with all-target desktop Clippy.
Those Apple Rust targets and an Apple SDK are unavailable in this restored
workspace, so the current consent/default-USB/logging changes have not been
source-checked for macOS. Historical release-link attempts from the predecessor package reached
Rust's bundled Darwin LLD through a temporary linker-argument adapter. Linking then failed because an authorized
Apple SDK and its libraries/frameworks are unavailable: `libSystem`, `libobjc`,
AppKit, CoreBluetooth and Foundation. The blocker is the missing SDK and Apple
libraries, not a missing Darwin linker. No native macOS executable was produced.

Use the supplied native macOS CI jobs or a Mac with its authorized Xcode/Command
Line Tools installation. An embedded Info.plist supplies the Bluetooth usage
string; signing, notarization, privacy permission attribution and a possible
app bundle need real macOS validation. No unrecognized SDK mirror, policy bypass,
or renamed Linux executable is used. CI has not been run in this delivery.

## Publishing downloads

Copy only successful executables to the allowlisted filenames under `downloads/`.
The general `/downloads` listing and file routes observe directory changes without
a restart. Restart the server/image only to refresh the legacy immutable
`/api/helper/downloads` executable catalog (the old `/api/companion/downloads`
route remains a compatibility alias); that catalog does not advertise
missing or wrong-platform files. Package the accompanying licenses and
source with the release; never place pairing tokens, credentials, logs or SDKs
in the download directory.

## Historical physical-adapter build checkpoint

The recorded Linux/Windows CLI and Desktop builds included the consent-gated physical
FIDO adapter described in [helper USB scope](helper-usb-fido.md). They were
rebuilt serially with `--offline --locked --release --features desktop --bins`,
using the existing official MinGW toolchain for Windows. HIDAPI is pinned to
2.6.7: Linux uses `linux-native-basic-udev`, Windows uses vendored upstream C.
No host dependency installation or device-permission change was performed.

Historical adapter checkpoint: 117 helper tests (83 core, 15 CLI unit, 12 Desktop unit, 7 CLI
subprocess); all-target desktop Clippy with `-D warnings` for Linux and Windows GNU; release CLI HTTP smoke and full real-PTY consent
suite including the actual 60-second timeout. USB tests use fake backends and
fake subprocesses only, including blocked-I/O cancellation and Linux parent-death
cleanup. Windows Job lifetime behavior is compile-checked, not executed here.
Historical Apple source checks omitted the physical adapter; no current Apple
check or macOS binary is claimed.

For each release, refresh the four executable sizes and SHA-256 values in ignored
local `downloads/builds.json` and `downloads/README.md`. The [current test manifest](../TESTING.md)
records the latest verified source checkpoint; the counts above are historical. Linux binaries require
GLIBC_2.39 and retain only libc/libm/libgcc_s dynamic dependencies. Windows
imports are system DLLs only, with console/GUI subsystems matching CLI/Desktop.
Hardware USB, Windows runtime, desktop rendering and real Chromium/WebAuthn
acceptance remain unverified. No new archive or upload is part of this checkpoint.

## Continuous reconnect and normal USB activation

The no-argument CLI and Desktop enable USB after live authenticated exact-Origin
approval, with `--disable-usb`/Desktop checkbox opt-out. Fake tests confirm that
unpaired, software-mode and preapproved-but-unconnected states never spawn a HID
worker. Explicit Reject/Revoke/Stop and non-TTY refusal withhold the exact Origin
across token/backend-session rotation until a local allow-again action or process
restart. Approval timeout, network loss and lease expiry remain retryable.
CLI/Desktop use standard helper-only tracing BLE diagnostics; Desktop stderr
requires a console or launcher capture and the Windows GUI creates no console.

Deferred native readiness keeps the same unopened offer/device via bounded,
strictly sequenced renewals. No HID report I/O occurs until the actual peer open;
opening carries the renewal sequence forward. Fake-process and real-loopback
tests cover this path without a physical device.

## Linux service-data filter regression

The current helper removes only the Linux OS UUID scan filter, preserving local
FFF9/FDE2 and payload/queue/rate checks. Six synthetic regressions cover platform
filter policy, service-data-only input, invalid/unrelated input, bounded forwarding,
cached-notification non-replay and privacy-safe saturating counters. No BLE device
was accessed; actual phone authentication requires user retesting.
