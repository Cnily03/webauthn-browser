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
CLI subprocess tests parse the listener announcement separately from lifecycle
logs. Unsupported physical USB backends (including macOS) may emit exactly one
`WARN USB: unavailable` startup record; unrelated and duplicate records still
fail. Synthetic startup records cover this ordering on every platform. EOF tests
wait for the listener announcement before closing stdin, because the bounded,
best-effort logger intentionally does not drain at process exit. They then
require exit within five seconds. Command-stream tests also wait for the final
status response after help before sending quit or EOF; observing startup alone
cannot guarantee that later command output reached the log sink. Both shutdown
paths run the full command sequence, and the quit case keeps stdin open until
the process exits. The HTTP smoke test likewise observes status before quitting.
These fixtures do not replace native macOS CI.
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
hardware access. Downloads checks verify actual manifest hashes, public global access and protected
legacy authentication,
large streaming files, raw/Unicode names and traversal/symlink/FIFO rejection.

Additional persistence, backup and clipboard checks are available in
`tests/persistence_smoke.py`, `tests/restore_smoke.py`,
`tests/attestation_der_smoke.py` and `tests/clipboard_transport_smoke.py`.
Run transport-dependent checks only where their documented prerequisites are
available. A denied or skipped Unix/device operation is not a passed test.

Under the scoped profile API, `event_stream_smoke.py` and the successful clipboard
transport smoke require a running profile-manager/engine-owner fixture. The old
unscoped browser-success flow is intentionally rejected. A prerequisite skip in
this environment is not a successful end-to-end SSE or clipboard check; scoped
owner/standby, CSRF, snapshot and release behavior is also tested in-process.

## Clipboard connection recovery

```sh
pnpm --dir web test src/ClipboardSync.test.tsx src/clipboard.test.ts
pnpm --dir web run typecheck
pnpm --dir web run build
cargo test --locked --bin webauthn-browser relay::clipboard
python3 -m unittest discover -s tests -p '*clipboard*test.py'
```

The frontend regression reproduces a six-hour live desktop whose clipboard-only
socket closes: the previous implementation never opened a replacement socket.
Fake-timer/jsdom checks cover reconnect backoff, one-second unopened deadlines,
fresh profile tickets, stopped retries after revoked admission, ownership-only
resets, teardown, stale ticket/permission/event results, and identity changes
before an old fallback click. Existing Clipboard API tests cover fresh on-demand
reads, immediate writes, gesture fallback, bounds and no retained payloads.

Rust relay tests cover transport-only heartbeat, matching/missing Pong and
revocation; Python bridge fixtures cover selection/request cancellation and
controller ownership. `clipboard_recovery_test.py` additionally injects display
construction/extension/window/flush/sync failures, event/read/select failures,
partial-listener and cleanup failures, replacement socket generations, bounded
retry delays and shutdown cancellation. It verifies that all old request and
payload state is discarded before a replacement session. The focused bridge
protocol/recovery suites pass 40 tests. Another 12
`clipboard_supervisor_test.py` fixtures cover clipboard-only process replacement,
backoff, failed exec, stop/startup cancellation, no duplicate child, unchanged
profile epochs/data and mandatory desktop failure handling. These results do not
claim an actual X server restart. These synthetic checks do not establish real X11,
reverse-proxy or browser-permission behavior. Complete the scoped, long-lived,
Chrome/Firefox/Safari acceptance in [docs/clipboard.md](docs/clipboard.md) on a
Docker/browser-capable host before claiming end-to-end clipboard acceptance.

## Profile isolation and concurrent ownership

```sh
python3 -m unittest discover -s tests -p 'profile_*_test.py'
python3 tests/profile_http_smoke.py
```

The HTTP smoke uses an actual gateway process and disposable storage; set
`AUTH_BROWSER_TEST_BINARY` to select an explicit compiled gateway. It covers
case-insensitive names, default-profile protections, saved versus effective
enabled flags, separate profile cookies, cross-profile rejection, password/logout
revocation, rolling access expiry and persistence across gateway restarts. It
also checks that profiles share authenticator identities while deleted/recreated
names receive fresh browser identities.

Runtime fixtures exercise separate profile roots, private manager control,
descriptor ownership, process teardown and display sizing. Display tests verify
ordered RandR commands and observed geometry against modeled responses, supported
by the packaged Xvfb/xrandr source behavior; they do not run a real X server.
Ownership tests must cover simultaneous acquisition, standby promotion, idle
expiry, stale generations, canceled work and a delayed old-owner cleanup racing
with a new owner. Heartbeats and status polls must not extend user-activity time.

The frontend tests cover login routes, remembered-profile navigation, settings
mutations, owner controls and profile-scoped preferences. These remain jsdom
checks, not real multi-browser or real VNC acceptance. See
[profile behavior and limits](docs/profiles.md).

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

Unavailable-profile takeover and cleanup counts (2026-10-17):

- Transport loss and authority revocation hide takeover until profile availability
  and authentication are confirmed. Deleted, disabled or unauthorized profiles
  never offer takeover; valid idle-expired and disconnected viewers retain
  explicit reacquisition. Late checks are ignored after teardown, and failed
  availability checks never trigger automatic acquisition.
- Cleanup count acknowledgement validates `cleaned + pending + skipped` against
  the server's configured-profile admission snapshot, independent of concurrent
  CRUD. Historical deletion jobs do not enter that denominator; completed data
  deletions remain separate.
- Runtime profile tests: 191 passed. Rust all-target tests: 316 passed and
  13 ignored; Clippy, the fresh release build and profile HTTP smoke passed. Cleanup snapshots configured IDs before
  queue waits. Completed deletion receipts are acknowledged only after the
  durable journal commit; a lost acknowledgement is retried in the background.
- Focused frontend checks: ten profile takeover/navigation cases and 36 Settings
  cleanup cases passed. Other cases were filtered out; no broad ProfileApp rerun
  was performed for this correction. Typecheck, production build and five
  documentation contracts passed; the existing large-chunk advisory remains.

Forced owned-instance cleanup and broker recovery (2026-10-17):

- Failed-instance cleanup may force-stop revalidated owned survivors through
  pidfds after bounded graceful shutdown; normal Reconnect Browser remains
  graceful-only. Persistent storage is removed only for an explicit journaled
  profile deletion. Unknown ownership remains pending.
- Cleanup pending details use bounded, mapped explanations. Settings shows at
  most two distinct reasons without internal IDs, preserving pending warnings
  and previously completed deletion counts.
- Compose Downloads uses the requested short read-only bind
  `./downloads:/downloads:ro`; the `./.data:/data` mount is unchanged.
- Runtime profile tests: 182 passed. Rust all-target tests: 313 passed and 13
  ignored; named Unix-socket orchestration remains environment-blocked. Clippy
  with warnings denied, formatting, the fresh release build and profile HTTP
  smoke passed. Cancellation tests simulate controlled descriptor
  adoption and initialization staging; they do not run a real manager/proxy
  integration. Viewer cancellation releases only the unpublished reservation
  matching its exact ID and generation, preserving an existing viewer.
- Retired FIDO control channels can obtain a fresh manager offer only after
  endpoint/epoch validation, without restarting Chromium; healthy launchers are
  retained. Final review accepted the force scope and retired-control repair.
- Focused frontend cleanup tests: 30 passed (45 unrelated Settings cases
  filtered out). Typecheck, production build, three Docker-context contracts
  and five documentation contracts passed. The build retains its existing
  large-chunk advisory. No real-browser or deployed-container recovery is claimed.

Pending deletion cleanup recovery (2026-10-17):

- Manual and automatic cleanup may complete only an existing explicit deletion
  journal entry after confirmed runtime shutdown. The cleanup response includes
  `deleted_profiles`; `browser_data_retained` is false only when that count is
  positive. The UI validates this relationship and reports completed prior
  deletions alongside any still-pending resources, preserving unrelated drafts.
- This corrects the earlier v51 manual-cleanup restriction; default storage,
  disable, local forget and historical orphan directories remain protected.
- Runtime profile tests: 169 passed. Three manager regressions reproduce
  `cleaned: 0, pending: 1` against v51 and pass with this correction. Recovery
  restores pristine-namespace absence proofs after no-op stops, accounts for
  unreadable sandbox children through a verified live process-group leader, and
  retries failed startup inventory plus pending journal entries.
  Cleanup releases application-wide operation/lifecycle locks during manager
  waits, then revalidates the exact runtime epoch under a dedicated pass lock.
  Concurrency regressions cover busy startup, post-lock healthy-worker checks,
  and rejecting inventory snapshots made stale by a concurrent profile launch.
  Final independent review accepted the fixes and reran all 36 manager tests
  successfully.
- Rust all-target tests: 301 passed and 11 ignored (the same eight earlier
  ignores and three environment-denied AF_UNIX orchestration fixtures noted
  below). All-target Clippy with warnings denied, formatting, the fresh release
  build and profile HTTP smoke passed. These fixtures do not establish real
  Chromium behavior or successful recovery of the user's deployed container.
- Focused frontend cleanup tests: 22 passed (45 unrelated Settings cases were
  filtered out). Typecheck, production build and five documentation contracts
  passed. The build retains its existing large-chunk advisory. No broad
  ProfileApp rerun or real-browser verification was performed for this correction.

Explicit Settings profile deletion (2026-10-17):

- Deleting a non-default profile requires a permanent-data-loss confirmation.
  Success requires the backend to confirm removal of its immutable-ID directory
  after revoking access and stopping owned processes. Disable, local forget,
  default data and historical orphan storage remain outside the erasure
  operation. New explicit deletions have durable recovery. The subsequent pending
  cleanup correction lets manual and automatic cleanup finish only these already
  journaled deletions; it never initiates a new deletion.
- Rust all-target tests: 297 passed and 11 ignored. Eight ignores predate this
  change; three new Unix-socket orchestration fixtures are explicitly ignored
  because this environment denies AF_UNIX socket creation with EPERM. They are
  not passing integration evidence. All-target Clippy with warnings denied,
  formatting, the fresh release build and profile HTTP smoke passed.
- Python profile tests: 159 passed, including partial unlink failure/retry and
  parent-directory fsync failure recovery. Independent review reran all 12
  profile-erasure tests successfully. These tests use disposable fixture storage;
  no deployed profile data was deleted and no deployment was performed.
- Frontend typecheck, production build and five documentation contract tests
  passed. The build retains the existing large-chunk advisory. Targeted
  serialized Vitest checks passed all 59 ProfileSettings and 39 profile-utility
  cases, including permanent deletion warning/cancellation, default protection,
  unconfirmed/pending deletion acknowledgement and uncertain-network no-retry.
  ProfileApp passed 102 of 107 cases in that run; five late-file cases reached
  the existing 15-second timeout. A fresh process reran those exact five at the
  unchanged timeout and all passed in 0.43–1.18 seconds each. All 205 targeted
  cases therefore have passing evidence across runs, but the original combined
  command was not a clean pass. The initial parallel attempt was interrupted
  after producing no test results; the completed run used `--maxWorkers=1`
  and `--no-file-parallelism`. No real browser or deployed-data deletion is claimed.

Runtime reconciliation, name-only public profiles and public Downloads (2026-10-17):

- Runtime cleanup uses a lifetime manager lock, pre-spawn generation manifests,
  exact PID/start identity with pidfds, and persistent X artifact inode leases.
  Failed/orphan resources receive one bounded automatic attempt; startup resumes
  durable stop intents without repeating generic cleanup. Manual Settings cleanup
  skips healthy stacks unless an existing durable disable/delete intent requires
  their graceful stop. Unconfirmed survivors keep their slots and journal entries.
- Resource tests include real owned subprocess/pidfd signaling plus mocked X
  artifact checks, PID/group reuse, missing/mixed ownership, restart tmpfs loss,
  bounded budgets and no user-data deletion. They do not run real Chromium/Xvfb.
- Prior integrated Python checkpoint: 400 tests, 397 passed and three explicit
  pre-skips (retained evidence; not rerun for the Downloads access change). The two
  named D-Bus startup tests and unconnected-socket ancillary test previously denied
  by this environment were not retried. Independent review passed 29 resource and
  27 manager tests. Rust/Python share eleven cleanup protocol contract cases.
- Rust: 291 tests passed, eight existing environment-dependent ignores; strict
  Clippy, formatting and release build passed on the final public-Downloads tree.
  Serial real profile, gateway admission and helper-download HTTP smokes were
  rerun and passed; persistence retains its earlier passing checkpoint. Boundary tests
  search for the known internal profile UUID, not unrelated viewer/request IDs
  or authenticator AAGUIDs, and cover rename/name reuse and old-cookie rejection.
- Frontend serialized aggregate: 960 passed, one Settings-lifetime test timed out
  at the 15-second limit (961 total, 33 files, 1007.37 seconds). This is not claimed
  as a fully passing aggregate. The same test passed in isolation (1.54 seconds).
  Its multi-transition integration-test budget was raised to 30 seconds without
  changing assertions; the complete ProfileApp file rerun passed all 107 tests
  (505.75 seconds). The full aggregate was not repeated after that test-only change.
  The earlier three-file targeted run passed 151 with the same single timeout;
  direct Downloads rerun passed all 24. Validation used pnpm 11.25.0, Node 24.19.0
  and Vitest 5.0.3, reusing installed dependencies without a lockfile or package-
  manager pin change. Strict TypeScript, production build and real served-assets/
  CSP smoke passed; the existing large-chunk warning remains. No rendered-browser
  or Docker acceptance was performed.
- Global `/downloads`, `/api/downloads` and `/downloads/{filename}` are public
  without a profile parameter or password. HTTP checks cover anonymous GET/HEAD,
  enabled passwords, logout/restart and protected scoped/legacy compatibility.
  Frontend checks keep Downloads independent from status availability and prevent
  download-list errors from revoking active browser ownership.
- Public profile identifiers are names; immutable profile UUIDs remain in backend
  storage and admin Settings. Public-cookie migration requires one fresh sign-in.
  Profile rename preserves its filesystem directory and revokes old-name access.
- The Settings password switch now requires a nonempty value on every enabled
  Save. Manual cleanup preserves unrelated drafts. Menu status separates red
  unavailable identities from orange invalid authentication and reports detailed
  errors through the shared, exit-safe global Snackbar.

Prior v49 evidence: named navigation, stable accordions and tracked-only Docker
inputs (2026-10-16; profile identity, status colors and Downloads routing below
are historical and superseded by the current work):

- Public Browser destinations use profile names, and Downloads uses a name
  selector. Internal identity guards reject stale/reused names; expired pending
  intents remain rejected through repeated entry reads. The chooser opens plain
  `/` with a nonsecret bounded intent instead of a root query parameter.
- The profile icon follows the leftmost collapse control inside its collapsible
  region. Current-row clicks do nothing. Missing/disabled remembered entries stay
  visible and orange. Local removal requires two clicks within three seconds.
- Settings accordions keep stable margins/header sizes and zero elevation. Exit
  content remains for the 180ms transition while immediately clearing plaintext
  and disabling stale fields; old exit callbacks cannot affect a new editor.
- Docker no longer copies or reads runtime downloads. A fresh tracked-only
  context contains every build input; the image fetches the unchanged pinned
  ZeroOmega release/source with hash verification. Compose creates an absent
  runtime downloads directory without replacing existing files. The default
  source ZIP includes only an empty downloads directory.
- Frontend: 904 tests passed across 32 files, strict TypeScript and production
  build passed with pnpm 12.14.0. Application dependencies/lockfile are unchanged;
  the existing large-bundle warning remains. Guarded helper-download new tabs
  include blocked-popup, timeout, cancellation and late-response checks.
- Three serial real HTTP smokes pass: built assets/CSP, gateway admission, and
  profile CRUD/cookie isolation/remembered access/scoped downloads. Rust and
  helper source are unchanged; their prior evidence is carried forward.
- Python aggregate: 360 passed and three existing skips. The 12 installer/context
  tests and five documentation tests also pass in their focused checks. The
  tracked-input check ran in this Git checkout and explicitly skips without Git
  metadata in the source ZIP; other installer/context checks remain runnable.
- Installer/context contracts use mocked upstream responses. Docker is unavailable
  in this environment; no actual image build or rendered-browser QA is claimed.

Inline profile controls, navigation and cleanup retries (2026-10-16):

- Existing profiles edit inline through accessible MUI Accordions; creation and
  deletion retain dialogs. One profile expands at a time. Collapse, cancellation
  and profile switches clear transient passwords and discard unsaved drafts.
- The profile menu now occupies the navigation bar's leftmost slot. Its green
  marker follows the selected profile independently of engine ownership. Password
  and profile login gates show the same navigation without acquiring a viewer or
  browser capability. Single-profile mode hides the profile menu.
- A lost successful-stop reply can be retried for the exact confirmed-stopped
  runtime generation. A newer live generation or uncertain shutdown cannot use
  that receipt. Cleanup also refuses to terminate a live auxiliary Chromium
  launcher without its owned graceful-close pipe.
- The stop-only gateway reply budget is 60 seconds, covering the manager
  worker-reply and confirmed-exit waits. Shared Rust/Python timing fixtures
  protect this boundary; timeout or uncertain exit still cannot count as success.
- Mode-only changes preserve valid remembered profile credentials while revoking
  live viewer/helper authority. Actual password revisions and explicit disable
  still revoke access. Expired passwordless tokens cannot be revived by public
  access. Local forget is scoped to one browser credential, including disabled
  and deleted profiles, with CSRF and another-browser isolation checks.
- Remembered menu metadata does not expire or disappear after authentication
  failure. A current-document failure is orange; the actual current profile is
  green. Inactive local forget clears only its scoped credential after successful
  logout. The current profile cannot be forgotten, and immutable-ID destinations
  prevent stale names from opening a replacement profile. Root default resume
  and explicit chooser intent are separate.
- Settings keeps its independent management session and mounted form through
  profile changes. Browser/viewer authority can be released without replacing
  the administrative route with a profile-login gate.
- The updated real HTTP profile smoke passes three mode cycles with the same
  profile/admin cookies, access gating, expiry, local forget and persistence.
  Final Rust checks pass 281 tests with eight existing ignores, formatting,
  strict Clippy and release compilation.
- Final frontend aggregate: 863 tests across 31 files, typecheck and production
  build pass with pnpm 12.14.0; dependencies and lockfile are unchanged. The
  existing large-chunk build advisory remains. Python aggregate: 354 passed and
  three existing skips. Served-assets/CSP, gateway admission, restart persistence
  and documentation checks pass; independent source/focused review found no blocker.
- These checks use jsdom and simulated browser/display process contracts where
  applicable. They do not establish new physical-helper or real Chromium/Xvfb
  acceptance. Unchanged helper downloads retain their existing build provenance.

Current-viewport resizing and password controls (2026-10-16):

- Owner page entry and manual reconnection now apply the current bounded viewport,
  including smaller and mixed-axis dimensions. Repeated changes reuse the same
  display and verify its actual dimensions; ordinary window resizing alone does
  not trigger lifecycle operations. Standby viewers cannot resize the display.
- Focused runtime checks: 64 Python tests and 25 Rust window-control tests pass.
  They cover repeated exact sizing, mode reuse, optional resize failures,
  cancellation/deadlines and no duplicate destructive restart.
- Browser-profile settings use one password switch and a stable input. Blank
  edits retain an existing password; entering text replaces it; explicitly
  switching off and saving removes protection. New protection requires a
  nonempty password. Transient plaintext clears on toggle, close and teardown.
- Frontend: 820 tests in 31 files pass, including 64 focused profile/settings
  tests; typecheck and production build pass with pnpm 12.13.0 after a frozen
  lockfile install. The build retains its existing large-chunk advisory.
- Release HTTP smokes pass for built assets/CSP/authenticated noVNC boundaries
  and profile access/persistence/revocation. Documentation checks pass. Unchanged
  helper binaries match their existing hash manifest; no helper rebuild occurred.
- The user confirmed initial resizing in the prior release on their deployment.
  Repeated resizing here uses production command paths with simulated display
  effects; no additional real Chromium/Xvfb acceptance is claimed.

Best-effort sizing and control diagnostics (2026-10-16):

- Invalid optional geometry and RandR failures no longer block Ensure/Restart
  or final maximization. Inspect ignores geometry without resizing. Startup
  can retain the existing Xvfb geometry if initial logical sizing fails.
- Actual Rust workflow serialization feeds the production Python supervisor
  over pipes for existing/absent browsers, Ensure/Restart, malformed viewport
  input and simulated resize failure. Tests require one restart at most, no
  sizing retry after failure within the operation, and no unconfirmed geometry.
- Combined sizing-error/cancellation and stale-epoch checks still prevent
  browser close. Post-apply query failure does not claim rollback. Failure
  responses use correlated, allowlisted stage/reason codes; arbitrary errors
  and secrets are rejected. Runtime status writes include a timestamp.
- Rust aggregate: 276 passed and eight existing ignored. Python aggregate:
  347 tests, 344 passed and three existing environment skips; 99 profile-focused
  tests pass. Formatting, strict all-target Clippy, release compilation and
  documentation checks pass.
- Serial release HTTP smokes pass for profile CRUD/cookie isolation/revocation,
  gateway admission/authentication/CSRF and persistence across gateway restart.
- Browser/display effects are simulated. No real Chromium/Xvfb resize or built
  Docker-image acceptance is claimed. Frontend and helper code are unchanged;
  their earlier evidence and helper binary provenance remain applicable.

Browser viewport command correction (2026-10-13):

- The production Rust workflow and wire serializer now feed the real Python
  supervisor command parser through subprocess pipes. Only browser/display
  effects are modeled; no X server, socket listener or physical device starts.
- The eight-case regression reproduces the original `Invalid viewport`/503
  failure before the fix, then passes for Ensure/Restart, existing/closed
  browsers and viewport present/absent. Inspect omits the field and stays
  read-only; Ensure/Restart/Maximize retain the supplied dimensions.
- Run the contract with
  `cargo test --locked viewport_workflows_cross_actual_rust_wire_and_python_supervisor`.
  Backend aggregate: 273 passed, eight existing ignored; formatting and strict
  all-target Clippy and release build pass.
- 131 focused frontend tests pass, including viewport changes between initial
  connection and manual restart with the same current owner credentials.
  TypeScript, production web build and actual release profile/admission/assets
  HTTP smokes pass. Dependencies remain frozen with pnpm 12.11.2.
- These checks do not claim a real Chromium/Xvfb resize. Unchanged helper
  binaries retain their original hashes and provenance.

Xvfb parser correction (2026-10-13):

- Reproduced the v43 startup exception with a normal-only `xrandr --query`
  inventory lacking the optional parenthesized capability list. The formatting
  follows [xrandr's output code](https://sources.debian.org/src/x11-xserver-utils/7.3%2B6/xrandr/xrandr.c):
  capabilities are omitted when only the normal orientation is supported.
- 26 display tests and 91 profile-focused tests pass. The RandR model now uses
  this plain Xvfb format for initialization, growth, retry and cancellation;
  explicit rotation, reflection, offsets and multiple outputs remain rejected.
- Python aggregate: 339 tests, 336 passed and three environment-dependent skips.
  These are parser/model/process checks, not a new real Xvfb or Docker run.
- Rust, frontend, extension and helper source are unchanged. Their evidence below
  is carried forward; release binaries were not rebuilt for this Python-only fix.

Profile-change validation (2026-10-12):

- 808 frontend tests across 31 files, strict TypeScript check and production
  web build, using pnpm 12.11.2 (`pnpm@latest` on the validation date).
  Application dependency versions and the frozen lockfile remain unchanged.
- 272 backend tests passed, eight ignored, plus strict all-target Clippy.
  Four pre-existing integration ignores remain. Four new named-manager IPC
  tests could not bind their temporary Unix socket in this environment (EPERM):
  `health_and_stop_require_exact_correlation_without_descriptors`,
  `rejected_single_and_multiple_rights_are_closed`,
  `ensure_rejects_foreign_runtime_paths_and_missing_fido_right`, and
  `canceled_manager_wait_drops_a_late_received_descriptor`, all under
  `profiles::runtime::tests`.
- 337 Python tests: 334 passed and three existing environment-dependent skips;
  89 profile-focused tests pass. The skipped checks require private D-Bus Unix
  sockets or an unconnected socket construction denied by this environment.
- Anonymous-socket codec/descriptor tests and an eleven-case shared manager
  protocol fixture pass. Python exercises its real manager state machine;
  Rust consumes the same fixture. This does not replace named-socket acceptance.
- Seven extension VM suites and unchanged packaged fingerprint verification.
- Actual gateway HTTP/storage checks for profile login, isolated cookies,
  rolling expiry across gateway restarts, revocation, CRUD, shared authenticators
  and scoped downloads, including raw filenames and rejected path escapes.
- Final release build and five serial HTTP smokes pass: SPA/hashed assets/CSP,
  gateway admission and scoped tickets, profile behavior, download hashes and
  large-file/path protections, and restart-persistent keys/passwords/backups.
- In-process scoped SSE checks for owner/standby admission, CSRF, snapshots
  and stream closure on release. Full manager-backed SSE/clipboard transport
  acceptance remains subject to the prerequisites described above.

Unchanged helper source and the shared FIDO library retain the prior validated
release binaries and provenance: 145 helper tests, 60 logging process cases,
Linux/Windows GNU Clippy, Linux HTTP and full CLI PTY checks. Windows binaries
were cross-built and inspected, not run. These helper builds were not repeated
merely to relabel their provenance for the profile feature.

When optional helper releases are supplied, `downloads/builds.json` records the
commit that actually produced each release set; never relabel old bytes as a fresh build. Comment-only revisions may retain
verified prior artifacts, but changed executable display strings require a rebuild. Verify hash and byte size
before packaging. Do not enable the `test-support` feature in release binaries.

There was no macOS release build in those prior helper artifacts. Apple SDK/targets and
native Apple execution were unavailable for this release. Historical Apple
source checks are not current macOS build evidence. Those prior Linux binaries
require GLIBC 2.39. The current source ZIP has an empty downloads directory.

User reports include working Desktop USB/BLE and CLI BLE on a real host, alongside
intermittent USB problems. This development environment did not verify physical
authenticators/phones, real Chromium session restoration, Windows runtime behavior,
or a built Docker image's visual output. A helper connection, BLE scan or USB
READY event alone is not end-to-end authentication evidence.

## WebRTC Control packaging

`python3 -m unittest discover -s tests -p 'webrtc_control_test.py'` requires
Python `cryptography` (the image installs Debian's `python3-cryptography`). It
checks signed CRX fixtures, pinned identity/source, checksum/signature failures,
MV3 validation, unsafe archives, read-only assets and profile-safe coexistence.
The actual official 0.3.5 CRX download and installer were also verified. These
checks do not prove Chromium extension execution or container upgrade behavior.

Deployment acceptance: open a fresh profile and verify all three bundled
extensions, the WebRTC Control official ID, toolbar toggle and options; change
its options, restart the browser, then recreate the image with the same `/data`
mount and confirm the options, other extension settings and browser data remain.
Repeat in an existing profile and a second independent profile. Confirm WebRTC
behavior with protection on/off against the intended calling or test site.
Docker is unavailable in the current validation environment. Local Chromium
startup is blocked by sandbox socket permissions, so these browser/container
acceptance steps have not been reported as passing.

Validation on the WebRTC Control change: Python discovery ran 453 tests with
`OK (skipped=3)`; the seven new WebRTC Control tests and all three tracked Docker
context contracts passed. All `tests/extension_*test.cjs` VM suites passed,
including 92 local-navigation cases and 21 managed-window cases. The existing
packaged engine fingerprint/host verification and `git diff --check` also passed.
No Rust or frontend source changed; their build/test suites were not rerun.

## Scoped request identifier regression

Profile forwarding retains the outer `name` and wildcard `path` captures when
matching the inner API route. The regression uses the actual assembled gateway
router (`http::router`), profile login and viewer acquisition; directly calling a
handler or nesting an isolated profile router would miss this failure. Before the
fix, software key selection returned HTTP 500 with `Expected 1 but got 3`.
Named-field extraction now selects the inner `id` without depending on capture
count or order. The same extraction applies to native start/finish and the three
scoped key administration aliases. Global profile administration routes are not
forwarded and retain their existing extraction.

```sh
cargo test --locked scoped_request_paths_complete_software_steps_and_cancel
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
BINARY="${CARGO_TARGET_DIR:-target}/release/webauthn-browser"
AUTH_BROWSER_TEST_BINARY="$BINARY" python3 tests/profile_http_smoke.py
python3 tests/gateway_admission_smoke.py --backend-binary "$BINARY"
python3 tests/persistence_smoke.py --backend-binary "$BINARY"
# Requires separately built helper releases and downloads/builds.json:
python3 tests/helper_downloads_smoke.py --backend-binary "$BINARY"
```

Validation of this fix: the targeted regression passed for both profiles; the
full gateway Rust suite passed 319 tests with 13 existing ignored tests and no
failures. Formatting, Clippy with warnings denied, and the release build passed.
The profile, gateway-admission and restart-persistence HTTP smokes passed
serially against that release. The downloads smoke stopped at its prerequisite
(`Build real helper release artifacts first`); it did not run its download
assertions. The source-only checkout intentionally has no helper release
artifacts, and its ZIP retains an empty `downloads/` directory. Ignored optional
socket/device tests were not counted as passes.

The regression covers default and password-protected named profiles: software
registration selection, password setup, password verification, touch, stored-key
login, denial and completed-request replay; native start, canceled finish and
replay; key edit, credential deletion and key deletion. Missing profile access,
owner or CSRF, cross-profile authority, and private-ID URLs remain rejected.
Scoped key mutations still require global settings authority, including when
the caller owns an authenticated profile engine. No profile routing, name-only
public identity, middleware or authentication rules changed.

These are in-process router and loopback HTTP checks with synthetic software
credentials. They do not establish real Chromium/relying-party, physical
USB/BLE, Docker, or native macOS acceptance. Frontend, extension and helper
sources are unchanged; their separate suites are not rerun for this Rust-only
route-extraction fix.

### Container recreation and viewer recovery

`python3 tests/browser_profile_lock_test.py` covers exclusive-profile recovery of
foreign-host Chromium singleton links, data preservation, persistent guard
contention, a visible live profile process, same-host live PID, mocked active
socket refusal, malformed/changed links, lock-last interruption/retry, and the
supervisor's guarded prelaunch call. Socket probes are mocked in this unit suite;
it is not evidence of a real Chromium or Docker restart.

`pnpm --dir web test src/ProfileApp.test.tsx -t 'rotated CSRF|disconnected|real disconnect'`
covers an offline disconnect followed by a gateway CSRF rotation, explicit viewer
reacquisition and a new remote desktop, without replaying a manual restart.
The CSRF rotation regression fails against the prior hook and passes with the fix.

Deployment acceptance still requires `docker compose down` / `docker compose up`
on a backed-up, exclusively owned data directory: preserve tabs and stored data,
confirm the browser becomes available, and confirm no stale-singleton refusal or
clipboard cleanup traceback blocks startup. Do not perform this acceptance test
against shared or unconfirmed user data.
