# Testing and validation

Run commands from the repository root unless a section says otherwise. Node.js
24+, pnpm@latest, an installed Rust toolchain, Python 3 and the platform build
dependencies are required. Keep dependency versions locked. Test fixtures must
not be enabled in release helper binaries.

## Core checks

With Node 24 installed, bootstrap the current pnpm release (npm is used only
for this installation). If pnpm was previously enabled through Corepack, run
`corepack disable pnpm` first to remove that shim:

```sh
npm install --global pnpm@latest --no-audit --no-fund
```

There is no exact `packageManager` pin. Each bootstrap selects the registry
`latest` release; application dependencies remain frozen by `pnpm-lock.yaml`.
Docker may reuse its bootstrap layer: use `docker compose build --no-cache`
when you want to resolve a newer pnpm release.

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web test
pnpm --dir web run typecheck
pnpm --dir web run build
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -s tests -p '*_test.py'
for test in tests/extension_*test.cjs; do node "$test"; done
```

Build web assets before compiling a release gateway; they are served from the
local build or copied into the image by Docker. A source ZIP deliberately omits
`web/dist/`. Source and packaged extension assets share a fingerprint verified
by `runtime/verify_extension.py`; changing an included asset requires updating
`extension/build.sha256` and rerunning upgrade/handshake checks.

## Helper checks

```sh
cargo fmt --manifest-path helper/Cargo.toml -- --check
cargo test --locked --manifest-path helper/Cargo.toml --features desktop --all-targets
cargo clippy --locked --manifest-path helper/Cargo.toml --features desktop,test-support --all-targets -- -D warnings
cargo build --locked --manifest-path helper/Cargo.toml --features desktop,test-support --example controller-fixture --example logging-fixture
python3 helper/tests/logging_smoke.py --binary helper/target/debug/examples/logging-fixture
python3 helper/tests/controller_modes_smoke.py --binary helper/target/debug/examples/controller-fixture --stress 1
```

The helper suites cover exact-Origin authorization, remembered approvals,
withholding after explicit rejection/revocation, terminal restoration, channel
independence, strict report framing, renewals, stale generations and cancellation.
Logging tests use the actual CLI/Desktop initialization to verify ANSI/NO_COLOR,
TTY selection, INFO state changes, DEBUG counters and dependency-log suppression.
Controller fixtures use fake devices and real local WebSockets; they never open
an actual authenticator. See [helper build instructions](helper/README.md) for
platform dependencies, final release commands and cross-compilation checks.

## Release HTTP and terminal checks

```sh
cargo build --locked --release
python3 tests/frontend_assets_smoke.py
python3 tests/gateway_admission_smoke.py
python3 tests/event_stream_smoke.py
python3 tests/helper_downloads_smoke.py
python3 tests/helper_http_smoke.py
python3 tests/helper_cli_pty_smoke.py --binary downloads/webauthn-helper-linux-x86_64
```

Run HTTP smoke scripts serially; they own temporary service instances/ports.
Read each script's command-line help when selecting nondefault binary paths.
The CLI PTY suite includes the real approval timeout, keyboard navigation,
rejection, cancellation and restoration checks. It does not approve physical
hardware access. Downloads checks verify actual manifest hashes, authentication,
large streaming files, raw/Unicode names and traversal/symlink/FIFO rejection.

Additional persistence, backup and clipboard checks are available in
`tests/persistence_smoke.py`, `tests/restore_smoke.py`,
`tests/attestation_der_smoke.py` and `tests/clipboard_transport_smoke.py`.
Run transport-dependent checks only where their documented prerequisites are
available. A denied or skipped Unix/device operation is not a passed test.

## Browser lifecycle and navigation

`tests/browser_cdp_test.py` uses owned Python subprocess peers to validate private
fd3/fd4 mapping, FIDO descriptor collisions, high descriptor numbers, fragmented
NUL-delimited replies, stale IDs, timeouts and pipe ownership. The supervisor and
extension suites model one-window consolidation, group/pinned ordering, graceful
close, fresh process/capability generations, requester cancellation and restored
fingerprints. Gateway tests cover owner/CSRF checks, bounded receipts, monotonic
sequences and more than 128 sequential legitimate operations.

Initial `ensure` never restarts a live browser. Manual `restart` does not
implicitly retry an uncertain mutation. Only definitely rejected, typed admission
races may refresh an initial ensure intent within its original deadline.
[Lifecycle documentation](docs/browser-lifecycle.md) explains privacy and saved
session limits: normal close may discard unsaved page state or session-only data
according to the profile's settings. Tests do not establish actual Chromium
session restoration in this environment.

Local-address observer tests cover links, scripts, proven redirects, forms,
bookmarks, same-document changes, failed local connections and manually typed
exclusions. Backend delivery is authenticated, bounded, memory-only and fresh.
The received prompt has five fully visible seconds after its entrance; hover or
keyboard focus pauses the remaining time. Cancel and lifecycle changes clear it.
Only a synchronous user click opens the unchanged URL. See
[coverage and declared extension permissions](docs/local-navigation.md).

Frontend tests use jsdom and mocked browser APIs. DOM/computed-style assertions
are not pixel screenshots. Desktop egui tests inspect generated geometry for
aligned status columns, input fonts and approval controls; they are not a native
Windows desktop acceptance test.

## FIDO adapter and disposable fixtures

See [native hook tests](native-hid-hook/README.md),
[CTAP2 fixture](tests/ctap2_fixture/README.md),
[transport fixtures](tests/fixtures/README.md), and
[experimental relay boundaries](docs/experimental-fido-relay.md).

Simulation exercises strict 64-byte FIDO reports, complete message bursts,
backpressure, lease renewal, reconnect/cancel and stale-capability rejection.
The matched CLI/Desktop tests reproduced blocked output delaying CLI readiness;
the bounded off-thread logging sink fixes that synthetic path. This does not
prove every reported intermittent physical USB failure has the same cause.

Do not substitute an echo peer for real WebAuthn create/get acceptance. Do not
change host security settings, create kernel HID devices or bypass denied browser
prerequisites to obtain a passing result. Preserve the actual failure/skip reason.

## Recorded evidence and artifact provenance

Current source validation (2026-10-12) passes:

- 732 frontend tests across 28 files, TypeScript and production web build,
  using a clean pnpm 12.11.2 frozen installation (`pnpm@latest` resolved on
  2026-10-12). The imported lock preserves all 220
  package versions and integrity hashes from the previous lockfile.
- 248 backend tests, with four existing integration ignores, plus strict Clippy.
- 145 helper tests, 60 logger process cases and Linux/Windows GNU strict Clippy.
- 248 Python tests: 245 passed and three environment-dependent skips.
- Seven extension VM suites, including 92 navigation cases plus packaged wiring
  and 21 managed-window cases.
- Release gateway HTTP/CSP/authentication/SSE checks and verified download hashes.
- Final Linux helper HTTP and full PTY checks, including the real 60-second
  approval timeout. Windows binaries were cross-built and inspected, not run.

`downloads/builds.json` records the commit that actually produced each release
set; never relabel old bytes as a fresh build. Comment-only revisions may retain
verified prior artifacts, but changed executable display strings require a rebuild. Verify hash and byte size
before packaging. Do not enable the `test-support` feature in release binaries.

There is no macOS release build in the supplied artifacts. Apple SDK/targets and
native Apple execution were unavailable for this release. Historical Apple
source checks are not current macOS build evidence. The supplied Linux binaries
require GLIBC 2.39.

User reports include working Desktop USB/BLE and CLI BLE on a real host, alongside
intermittent USB problems. This development environment did not verify physical
authenticators/phones, real Chromium session restoration, Windows runtime behavior,
or a built Docker image's visual output. A helper connection, BLE scan or USB
READY event alone is not end-to-end authentication evidence.
