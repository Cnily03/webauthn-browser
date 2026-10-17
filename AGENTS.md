<?xml version="1.0" encoding="UTF-8"?>
<project-guidance project="WebAuthn Browser" version="1">
  <purpose>
    Maintain the packaged Chromium desktop, software WebAuthn engine, local
    helper and FIDO report relay as separate, explicitly owned components.
    Prefer narrow, reviewable changes that preserve stored credentials and
    browser data. This document is repository guidance, not a runtime policy.
  </purpose>

  <language-and-names>
    <rule>Write project documentation, identifiers and code comments in English.</rule>
    <rule>Keep the web interface in Chinese. Preserve Chinese validation text delivered to that interface, multilingual test fixtures, glyph checks and captured user content.</rule>
    <rule>Use WebAuthn Browser, WebAuthn Helper and WebAuthn Helper Desktop as human-facing display names.</rule>
    <rule>Do not rename technical packages, executables, paths, native-host identifiers, extension identity keys, API fields or storage keys merely to change display branding.</rule>
    <rule>Preserve third-party licenses, copyright notices and vendored upstream text.</rule>
  </language-and-names>

  <architecture>
    <component path="src/main.rs">Thin executable entry; application assembly belongs in src/app.rs.</component>
    <component path="src/app.rs">Shared state, startup composition and owned controller instances.</component>
    <component path="src/http">HTTP routing, responses, static assets and secure download streaming.</component>
    <component path="src/auth">Passwords, authenticated sessions, CSRF and owner validation.</component>
    <component path="src/profiles">Profile access, remembered sessions, isolated browser state and engine ownership.</component>
    <component path="src/settings">Authenticator settings and administrative configuration.</component>
    <component path="src/browser">Approval broker, event stream, browser window lifecycle and navigation notices.</component>
    <component path="src/relay">Native proxy, helper relay, clipboard and report transport adapters.</component>
    <component path="src/storage">Persistence, backup preview/commit and migration boundaries.</component>
    <component path="src/authenticator">Software credentials, signing, attestation and browser emulation.</component>
    <component path="src/fido-relay">Shared library crate used by the gateway and helper; its control codec is also shared with the native hook. It is not a standalone daemon.</component>
    <component path="web">React, Material UI and noVNC integration; generated output is web/dist.</component>
    <component path="extension">Image-owned request broker, mode control, window operations and local-navigation observer.</component>
    <component path="runtime">Non-root service supervision, browser process ownership and private IPC.</component>
    <component path="helper/src">Domain modules for pairing, server, relay, logging, CLI and Desktop.</component>
    <component path="native-hid-hook">Linux userspace FIDO HID interposer with narrow report/control semantics.</component>
    <component path="tests">Cross-module, subprocess, API, packaging and simulated browser contracts.</component>
  </architecture>

  <development-style>
    <rule>Use explicit domain interfaces and pub(crate)/pub(super) boundaries; do not rebuild main.rs into a global namespace through blanket re-exports.</rule>
    <rule>Place unit tests at the end of their owning Rust module under cfg(test). Keep genuine process or cross-component integration tests separate.</rule>
    <rule>Add comments for ownership, ordering, cancellation, consent, protocol bounds and non-obvious recovery decisions. Avoid restating obvious assignments or adding speculative claims.</rule>
    <rule>Use blank lines to separate validation, state transitions, side effects and cleanup within long functions. Keep formatting changes separate from behavior changes when practical.</rule>
    <rule>Keep README.md a concise quick start. Put detailed design and operational limitations in linked domain documents; keep TESTING.md current rather than accumulating contradictory release histories.</rule>
    <rule>Use existing tracing/tracing-subscriber formatting for Rust logs. Do not hand-format timestamps or inject untrusted ANSI sequences.</rule>
    <rule>Use ASCII gitmoji tokens in commit subjects. Review the diff and run relevant checks before committing; do not stage unrelated generated files.</rule>
  </development-style>

  <runtime-and-storage>
    <file path="docker-compose.yml">The sole Compose configuration uses ./.data:/data, ./downloads:/downloads:ro, 8080:8080 and restart: unless-stopped.</file>
    <rule>Container /data is unchanged. Stop and back up an existing deployment before a user renames host ./data to ./.data. Never overwrite an existing destination or silently start an empty replacement profile.</rule>
    <rule>Never migrate, delete, recursively chmod or broadly clear an existing user profile as part of a code or documentation update.</rule>
    <rule>Keep browser history, cookies, user extensions and their settings, credentials and keys persistent. Image-owned extension assets must come from the current image; do not broadly delete shared extension storage.</rule>
    <rule>Keep the CJK font package and its build-time glyph check. Do not change the browser locale, Accept-Language or install an input method unless specifically required by a separate change.</rule>
    <rule>Compose explicitly selects --no-sandbox. Keep that exposure documented; do not add host devices, privileged mode, UHID mounts or host security changes to make a test pass.</rule>
    <reference path="docs/data-migration.md" />
    <reference path="docs/runtime-storage.md" />
    <reference path="docs/startup-troubleshooting.md" />
  </runtime-and-storage>

  <profiles-and-ownership>
    <rule>Keep the authenticator store and settings administration global. Each browser profile owns its Chromium data, display, VNC transport, clipboard, private IPC, request broker and native relay generations.</rule>
    <rule>Resolve editable, case-insensitive public profile names to immutable server-generated identities on the backend. Ordinary frontend DTOs, API paths, cookies and storage use names only; profile UUIDs are restricted to backend storage and administrative Settings. Never construct runtime or persistent filesystem paths from a supplied profile name.</rule>
    <rule>Keep default undeletable and unrenameable. Disabling multi-profile mode changes effective availability only: force default on and other profiles off without overwriting their saved enabled values.</rule>
    <rule>Scope browser HTTP, event streams and WebSockets to the selected profile. A global settings session or another profile's credential must not silently grant browser-engine authority.</rule>
    <rule>Grant engine ownership atomically to the first eligible viewer. Recheck its profile, viewer identity and generation around asynchronous operations; canceled or expired owners cannot affect a successor.</rule>
    <rule>Use real user activity for the configured idle deadline. Polling, keepalive, reconnect loops, page visibility and server events are not user activity.</rule>
    <rule>Remember profile access for a rolling 30-day inactivity window using revocable, profile-scoped credentials. Never persist raw passwords or live viewer, helper, relay or engine capabilities in localStorage.</rule>
    <rule>Mode-only availability changes must preserve valid remembered profile credentials and local menu records while revoking live control. Authentication failure or credential expiry must not erase menu metadata. Explicit local forget clears only that browser's target credential and metadata, never the server profile or other browsers' sessions.</rule>
    <rule>Only the active owner may resize a profile's display on connect or reconnect. Match the current requested viewport within validated bounds, including smaller or mixed-axis dimensions; a standby viewer must not resize another user's desktop. Optional sizing failures must not block browser lifecycle actions or cause a repeated restart; never swallow cancellation or claim unverified geometry.</rule>
    <rule>Preserve legacy default browser data in place. Explicit Settings deletion of a non-default profile must revoke live access, confirm its owned processes have stopped, and permanently remove only its immutable-ID storage directory. Journal pending deletions durably; never purge historical orphan data or delete data for disable or local forget. Manual and automatic cleanup may resume only explicitly requested deletions already recorded in the durable journal.</rule>
    <reference path="docs/profiles.md" />
  </profiles-and-ownership>

  <browser-lifecycle>
    <rule>Initial authenticated page entry sends ensure: preserve a live browser, consolidate supported normal windows and maximize one window; create or restore only when absence is confirmed.</rule>
    <rule>Manual reconnect sends restart: consolidate first, close the owned browser through its private pipe, confirm clean exit, retire old capabilities, launch with the existing profile and verify saved tabs before reporting success.</rule>
    <rule>Do not use an uncontrolled Chromium self-relaunch or a hard-kill fallback for normal browser restart. Failed-instance cleanup may force-stop only revalidated, exactly owned processes after its bounded graceful timeout; unknown ownership remains pending. Fresh processes require fresh FIDO control/report generations.</rule>
    <rule>Private CDP exposes only fixed readiness and close operations. Never add a debugging TCP endpoint or accept arbitrary caller-supplied CDP methods, scripts, tab IDs or URLs.</rule>
    <rule>Preserve parent fd3/fd4, map child pipe descriptors collision-safely, and keep the control pipe open after RPC failure while the browser lives. EOF can itself close Chromium.</rule>
    <rule>Reject ambiguous window inventories and unsupported privacy/window/group cases. Move existing tabs and groups; do not discard extra windows by closing their contents.</rule>
    <rule>Compare stable URL/order/pinned/group semantics across restart, not numeric IDs. Raw tab URLs and group titles stay out of gateway logs and persistent operation history.</rule>
    <rule>Saved tab restoration is not a guarantee for unsaved forms, page memory, active downloads, session-only cookies or unchanged sign-in state. Honor clear-on-exit privacy preferences.</rule>
    <rule>Operation scope, exact-next sequence, owner checks and bounded receipts prevent stale replay. Only definitely rejected ensure admission races may retry; never automatically resubmit an uncertain manual restart.</rule>
    <rule>Keep broker and admission locks out of asynchronous supervisor/extension waits. Preserve the documented lock order and revalidate authority after awaits.</rule>
    <reference path="docs/browser-lifecycle.md" />
  </browser-lifecycle>

  <authorization-and-transports>
    <rule>Software mode uses configured virtual authenticators. Native mode requires confirmed stock-browser ownership after proxy detach, independent of create/get request type.</rule>
    <rule>Approve the exact helper Origin explicitly. Remember approvals only for the helper process; explicit reject/revoke withholding survives fresh network/backend session IDs.</rule>
    <rule>Network loss or lease expiry may reconnect, but must not silently authorize a withheld Origin or replay authentication reports.</rule>
    <rule>Keep BLE and USB switches independent. Disabling one channel must not revoke the other channel or the browser pairing.</rule>
    <rule>Relay only supported FIDO traffic. Preserve strict report sizes, bounded queues, complete message bounds, generation ownership, renewal deadlines and cancellation teardown.</rule>
    <rule>Connection, scanning and report-ready states are distinct from authentication success. Log concise state transitions at INFO and periodic counters at DEBUG; never log reports, BLE payloads, QR material, private keys or capability tokens.</rule>
    <rule>Use configured virtual authenticators for software mode; do not fabricate native credentials or pattern-match relying-party operations to substitute software responses.</rule>
    <reference path="docs/identity-and-authorization.md" />
    <reference path="docs/helper-usb-fido.md" />
    <reference path="docs/fido-control-protocol.md" />
  </authorization-and-transports>

  <web-and-extension>
    <rule>Keep helper address/Connect usable during retries. Bound unopened WebSocket establishment to one second; an open socket awaiting human approval is not a failed connection.</rule>
    <rule>Persist mode/address preferences and the non-secret saved-profile menu in localStorage, not session capabilities. Profile access credentials use their scoped browser cookie policy. Preserve owned native-mode lifetime across ordinary SPA navigation without resetting the idle deadline.</rule>
    <rule>Use Material UI components and built-in icons with consistent geometry. Preserve compact floating controls and monospace AAGUID/helper address content.</rule>
    <rule>Local-navigation offers require trustworthy non-manual provenance, authenticated fresh delivery and an explicit click. Never auto-open or fetch a local target.</rule>
    <rule>Start the prompt's five visible seconds after entrance. Hover/focus pauses its remaining timer; cancellation and authority/navigation teardown still clear it.</rule>
    <rule>Separate Snackbar open state from retained content until exit, and guard old transition callbacks against replacement notices.</rule>
    <rule>When an extension asset or manifest changes, recompute its complete fingerprint and rerun packaged-asset, upgrade and strict handshake tests. Never acknowledge a stale or incompatible extension as ready.</rule>
    <reference path="docs/local-navigation.md" />
    <reference path="runtime/verify_extension.py" />
  </web-and-extension>

  <validation>
    <rule>Use pnpm@latest and install dependencies with --frozen-lockfile. Do not add an exact packageManager pin that overrides the selected latest release. Keep web/pnpm-lock.yaml authoritative; do not generate an npm package-lock.json.</rule>
    <command cwd=".">pnpm --dir web test</command>
    <command cwd=".">pnpm --dir web run typecheck</command>
    <command cwd=".">pnpm --dir web run build</command>
    <command cwd=".">cargo fmt --all -- --check</command>
    <command cwd=".">cargo test --locked --all-targets</command>
    <command cwd=".">cargo clippy --locked --all-targets -- -D warnings</command>
    <command cwd=".">cargo test --locked --manifest-path helper/Cargo.toml --features desktop --all-targets</command>
    <command cwd=".">cargo clippy --locked --manifest-path helper/Cargo.toml --features desktop,test-support --all-targets -- -D warnings</command>
    <command cwd=".">python3 -m unittest discover -s tests -p '*_test.py'</command>
    <command cwd=".">for test in tests/extension_*test.cjs; do node "$test"; done</command>
    <rule>Run relevant unit and integration tests first, then the aggregate checks. Run service/port-owning HTTP smoke scripts serially.</rule>
    <rule>Keep fake devices, synthetic credentials and test routes behind test-support. Never enable that feature in release helper binaries.</rule>
    <rule>Differentiate AST/static checks, jsdom styles, egui geometry, native ABI/process fixtures, actual Chromium execution and physical hardware acceptance.</rule>
    <rule>Do not bypass denied prerequisites or treat skipped checks as passed. Record exact limitations; macOS source checks are not macOS executable evidence.</rule>
    <reference path="TESTING.md" />
    <reference path="helper/README.md" />
    <reference path="native-hid-hook/README.md" />
    <reference path="tests/ctap2_fixture/README.md" />
  </validation>

  <release-and-packaging>
    <rule>Keep release filenames consistent: webauthn-helper-PLATFORM-ARCH and webauthn-helper-desktop-PLATFORM-ARCH, with .exe on Windows.</rule>
    <rule>Record real build commit, feature set, byte sizes and SHA-256 hashes in downloads/builds.json. Comment-only edits do not justify stamping existing binaries with a new build provenance.</rule>
    <rule>Bundle tracked source with an explicit empty downloads directory. Keep existing local ignored artifacts untouched, but do not include them in the default source ZIP. Docker builds must depend only on tracked source and pinned, verified build-time upstream downloads, never local ignored assets.</rule>
    <rule>Exclude .git, Git history bundles, data/.data, web/dist, node_modules, target directories, caches, logs and generated test credentials.</rule>
    <rule>Source packaging must not require a prebuilt web/dist directory. Docker compiles the web interface and native components from their source.</rule>
    <rule>Retain third-party license notices and official pinned extension/vendor provenance. Do not fabricate unsupported platform binaries.</rule>
    <reference path=".github/workflows/helper.yml" />
    <reference path="NOTICE" />
  </release-and-packaging>
</project-guidance>
