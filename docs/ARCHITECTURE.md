# Architecture

Rust gateway + native Chromium WebAuthenticationProxy extension + software ES256
signer. The original source is GPL-3.0-or-later; bundled upstream software keeps
its own licenses (NOTICE).

## Rust module boundaries

The backend entrypoint only declares domains and calls `app::run`. `app` owns
shared state and bootstrap/shutdown; `http` composes routes, assets and middleware;
`auth` owns sessions, cookies, CSRF and password checks; `settings` owns key CRUD.
`browser` owns mode/request/stream lifetimes; `relay` owns browser and helper
transports; `storage` owns persisted state/restore; `authenticator` owns software
configuration, attestation and signing. Domain dependencies use explicit imports
and crate/super visibility rather than re-exporting a global main namespace.

The helper uses `pairing` for consent/session/protocol, `server` for loopback HTTP
and Handle controls, and `relay` for BLE/FIDO/USB. CLI/Desktop remain thin UI
consumers of the same core. Its published API names remain compatible.
Unit tests live in final `#[cfg(test)] mod tests` blocks beside implementation;
test-only shared support contains fixtures, while actual subprocess/integration
fixtures remain under `tests/`. Module moves do not change stored data or wire APIs.

## Browser request boundary

The packaged MV3 extension uses `chrome.webAuthenticationProxy`, available on
Chromium 115+. It has no content scripts, page injection, externally-connectable
messages, website permissions, or browser-fetch endpoint. Chromium performs its
native secure-origin, RP/domain, and ancestor checks before sending the genuine
create/get request. Its injected `extensions.remoteDesktopClientOverride`
supplies the caller origin and same-origin ancestry status. Neither a form nor a
remote website can manufacture the native broker channel through the web API.

The extension forwards native request IDs and exact JSON through Chromium native
messaging. The pinned extension ID is declared in a system native-host manifest.
The small native host mode of the Rust binary connects to a private Unix socket
under `/data/run`; directory 0700, socket 0600. This authenticates by local UID
filesystem access, not a separate secure element or hostile-container boundary.
Processes with this UID can already read the stored software private keys.

CDP virtual authenticator environments are deliberately removed: Chromium
bypasses WebAuthenticationProxy when one exists. Production Chromium has no CDP
listener. There is no manual apply-to-tab step. All ordinary supported requests
are intercepted regardless of tab, and one central store owns signature counters.

## Global native mode and local hybrid discovery

The browser has two explicit global modes, selected before a website ceremony:
software interception and native Chromium handling. Selecting native creates an
owner-bound, renewable bounded lease independently of any request ID. The broker
cancels pending and claimed software requests across all tabs, sends a
generation-bound native-mode command, and waits for actual `detach()` confirmation.
Stock Chromium then owns both create and get, including its authenticator chooser,
phone QR, policy decisions and caBLE tunnel. No RP-based routing or fabricated
credential response replaces the native browser path.

The top-left navigation and bottom-left draggable/collapsible browser controls are
independent. The first control row selects mode and exposes engine state, browser
reconnect, Ctrl+Alt+Delete and fullscreen. Native mode adds downloads, a persistently
editable monospaced helper address and an always-enabled Connect button. Transient
loss uses a neutral internal spinner and one retry per second. Pairing and confirmed
native mode are both required for the green helper status; it says nothing about
radio scanning, proximity, QR availability or a completed authentication.

Mode generation compare-and-swap and the owner session ID protect changes and late
cleanup across tabs. A live page may renew only within existing authorization and
CSRF lifetimes. The extension also has a bounded local lease and acknowledges each
renewal with its actual detached state; server success is not an optimistic timer
update. Strict version/capability checks reject incompatible extensions, and the
existing controlled reload path remains available. Mode exit, authorization loss,
expiry or control failure clear transport and restore fail-closed interception.
Transient helper loss obtains a fresh one-use token without changing mode ownership.
Explicit helper refusal does not enter an unsolicited re-prompt loop.

Changing modes cannot migrate an in-flight WebAuthn ceremony. After cancellation,
a website must start a new operation. A detached native ceremony also cannot be
recalled merely by reattaching interception; cancel any native chooser still open
inside Chromium when stopping. The page never captures or invents a QR image.

The Rust helper has separate single-executable terminal and native eframe
desktop frontends sharing one library. Exact outer Origin approval, a one-use pairing token,
explicit local approval before automatic scanning, bounded frames and finite leases protect its BLE ingress.
Only real btleplug FFF9/FDE2 service data is accepted, never fabricated signatures,
credentials, user-verification flags, or proximity assertions. Adjustable ports
remain loopback-only and the actual selected listener address is shown.

The outer page relays bounded service data through authenticated, CSRF-protected
POSTs. A session owns one private Unix stream to the container's BlueZ-compatible
D-Bus service. The container starts its own non-root dbus-daemon; no host bus,
HCI device, privileged container, host Bluetooth policy, or firewall change is
required. BlueZ objects expire quickly and reset when that stream closes.
The interface exposes only the discovery properties Chromium needs; it does not
implement GATT, device pairing or a real radio. Synthetic interface addresses
identify ephemeral objects and do not assert the phone's MAC or distance.

The default radio transport is hybrid/caBLE BLE service-data discovery only.
It does not provide legacy FIDO BLE GATT or generic/all-class USB forwarding.
The settings-page software `usb` attachment type remains software emulation,
independent of the optional physical relay.

The session-gated [opaque FIDO report path](experimental-fido-relay.md) connects a
fresh userspace browser-HID generation to the owner-bound backend, outer-page
adapter and approved helper endpoint. Private supervisor IPC coordinates distinct
browser/gateway epochs, Prepare/Activate acknowledgements and renewable absolute
leases. The genuine libudev monitor adapter preserves real prerequisites and
forwards unrelated events. The helper's separate physical adapter accepts only
its supported FIDO usage/report profile only after a live exact-Origin-approved
pairing. Ordinary packaged startup prepares the trusted browser control channel
without activating a virtual device; Native authorization still gates Prepare/Activate. No kernel HID/UHID device, generic USB redirection or new device permission
is introduced. See [launcher ownership](fido-launcher-design.md) and
[helper restrictions](helper-usb-fido.md).

Native/mock ABI, report, HTTP, WebSocket and jsdom tests validate these components;
actual Chromium discovery, descendant raw-fork isolation and real hardware
interoperability remain unverified. Launcher readiness and attached endpoint status
are distinct and never imply successful USB authentication. Default software and
BLE behavior are unchanged.

This architecture relocates trusted BLE observation to the helper computer.
It is not equivalent to keeping all radio observation local to Chromium and is
not claimed to preserve the original native proximity security boundary.
Actual Chromium/phone interoperation remains unverified until hardware E2E.
Unit/mock tests and executable compilation alone cannot establish success.

`/downloads` lists every readable top-level regular file in the configured
directory, with escaped labels and byte-encoded URLs. Both `/downloads/{filename}`
and the legacy `/download/{filename}` stream attachments through the VNC guard.
A directory-bound `openat` with `NOFOLLOW` prevents symlink/path escape; no folder
recursion occurs. Changes are visible without restart. Compose mounts
`./downloads:/downloads:ro`. The separate legacy JSON manifest still validates
six known OS × CLI/Desktop targets and reports their size and SHA-256; it does
not restrict the general directory listing.

## Legacy native-client login forwarding (not used by global mode UI)

The retained compatibility API starts a user-clicked native-client **get** attempt;
**create** is explicitly unavailable. The global mode UI does not call this API.
The page does not render a QR code. The actual browser owns the authenticator and
phone chooser, its QR code, permissions, biometric UI, and cancellation.

`POST /api/requests/:id/native/start` atomically claims only a pending `select_key`
login and returns the original parsed options plus an unguessable attempt token.
The token, desktop session cookie, CSRF cookie, desktop authorization epoch,
proxy generation, and original bounded ceremony deadline bind the response.
Virtual key presence timeouts do not shorten the unselected native ceremony;
selecting a virtual key still narrows that key's normal deadline.

The outer browser receives the exact Chromium-generated
`extensions.remoteDesktopClientOverride`, never a constructed replacement for
signed client data. Unsupported browser extension parsing fails closed. HTTPS,
remote-desktop extension support, and Chromium's enterprise origin authorization
are prerequisites; ordinary browser permission prompts cannot grant enterprise
policy access. The application neither changes host policies nor falls back to
ordinary origin authentication or the software signer after an error.

`POST /api/requests/:id/native/finish` is bounded to 1 MiB and accepts exactly one
assertion JSON or DOM exception. It checks original challenge, client-data type
and origin/ancestry, RP/AppID hash, allowCredentials, credential ID, UP and required
UV. Signed bytes are never rewritten. The relying party still verifies signature
and counter. The broker consumes the attempt before forwarding through the
existing native extension `completeGetRequest`; duplicate, concurrent, canceled,
expired, disconnected, wrong-session and stale-epoch submissions cannot complete
another ceremony. Error names/messages are preserved for supported DOM errors.

Only transient in-memory forwarding is involved: this path never invokes
`signer`, writes the credential store, updates counters, or exposes options,
attempt tokens or assertion content through public requests/SSE/logs. Protected
POST responses use the existing no-store, session authorization and cookie-bound
CSRF checks. Gateway Host/Origin/Fetch-Metadata admission is deliberately absent
for arbitrary LAN/domain/proxy access, including WebSockets; this does not grant
browser CORS access or change the local helper's exact-Origin approval. Request
binding still prevents callers from replacing the recorded remote override.

Protocol references: [Chrome WebAuthenticationProxy](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy),
[Chromium origin authorization](https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/webauthn/chrome_web_authentication_delegate_base.cc),
[Chromium JSON response conversion](https://chromium.googlesource.com/chromium/src/+/main/components/webauthn/json/value_conversions.cc).
Real-phone/enterprise-policy end-to-end testing remains outstanding; mocks do
not establish that a particular browser/device will show a QR code.

## Authorization and completion

Browser IDs never authorize an outer-page action directly. Each operation gets a
fresh random approval ID, connection generation, immutable options, deadline,
and eligible key/account list. At most 32 operations are retained; browser abort,
cancel, disconnect, configuration changes, logout, or expiry invalidate them.
Each candidate has a configured 1–120 second presence deadline, bounded by the website timeout; it is checked before and after password verification. For virtual-only registration the overall request expires when all eligible candidate deadlines end; unselected login retains the bounded website deadline for native forwarding. A claimed operation cannot be claimed
again and remains cancellable while password hashing runs.

The outer noVNC-hosting browser opens a fetch-based SSE stream at
`/api/requests/events`, using desktop authorization and a cookie-bound CSRF token
in a header (never a URL). GET `/api/requests` remains a snapshot diagnostic API.
Every SSE frame is a complete authoritative queue snapshot. An instance-scoped
cursor carries up to 128 allowlisted lifecycle events; foreign, future, or stale
cursors trigger full resync rather than replay. No challenge, password, password
hash, private key, or signature is included in events. Stream messages cannot
approve anything; decisions use the explicit POST API.

A separate lease task owns the broker subscription, checks authorization on each
wake and every 15 seconds, and drops it on revocation even for a stalled reader.
At most 64 streams may run globally. Session rotation removes the old token;
logout, password changes, session expiry, and CSRF expiry end affected leases.
Each frame locks broker then session state and rechecks authorization before
serialization. Already transmitted bytes cannot be recalled. The client clears
passwords/dialogs on disconnect and on stale/canceled snapshots, reconnects with
an opaque cursor, and never replays a submitted decision.
It shows RP, origin, create/get, key/account choice, password fields when needed,
and a single-purpose stage dialog. No prompt is injected into the container website.
The first eligible choice is preselected; submission remains explicit. Each approval covers one operation
and one selected credential. There is no auto-touch or auto-UV flag.

The decision API advances select_key → setup_password (only when UV needs a
password that is absent) → verify_password → touch → signing. Every transition
is a distinct action. Preferred/required UV uses actual Argon2 verification;
discouraged UV skips setup/verification and never sets UV. First-use setup stores
a password but does not authorize UV or presence. Every supported WebAuthn
operation requires a separate touch. Ten attempts per key per minute are allowed;
a failed password consumes the operation. Passwords are not logged or returned.
Authorization is one-shot and tied to request, selection, key configuration and
password revision; cancel, expiry, key deletion/configuration changes and session
revocation invalidate it. This is application-controlled software verification,
not CTAP ClientPIN, biometrics, or a TPM.

After verification, broker cancellation/deadline and desktop authorization are
rechecked. Signing, counter update, atomic file save + fsync, and reply enqueue
are serialized. Failed storage means no success response. Browser cancellation
may beat a response already in transit; the extension discards canceled replies.
A credential or counter may be durably saved even if delivery loses that race.
There is no claim of an atomic transaction with a remote relying party.

## Cryptographic identity and compatibility

ES256/P-256 only, valid COSE/SPKI/authenticator and client data. None attestation
has `fmt=none` and an empty `attStmt`, but preserves the configured AAGUID in
authenticatorData. WebAuthn Level 3 separates the model identifier from attestation
conveyance; none no longer requires clearing it. The default model UUID remains
all-zero, which can also be explicitly chosen to omit a model identifier.
Optional packed self attestation uses the new
credential key to sign authenticatorData + SHA256(clientDataJSON), with no x5c
certificate chain. It is emitted only for direct/indirect RP requests and an
explicit per-key self setting. The model AAGUID accepts exact 32-hex or canonical 36-character UUID input at creation,
case-insensitively with surrounding whitespace trimmed. It serializes as a canonical
lowercase hyphenated UUID, representing the
user’s own software model. No vendor-identity presets or trust claims are offered.
None/omitted requests, and unsupported enterprise requests downgraded to none,
never emit an attestation signature or certificate. Their configured model UUID
is retained, even for self/basic-capable keys. This does not assert enterprise
attestation or manufacturer provenance. A unique UUID can correlate registrations;
an all-zero AAGUID does not hide a certificate sent for an explicit basic request.
Provider is a custom editable local display label, not a WebAuthn wire field or certified
vendor. A key's user-visible name is local metadata. Neither changing it nor an
AAGUID label makes a relying party trust the authenticator or display that name.
No known-vendor presets, hardware-policy bypasses, or fabricated trust claims are supplied.
Existing credential registration metadata is never recalculated or backfilled
after this correction. API previews use the same effective proof/AAGUID selection
as the signer and new registration snapshots.

Optional packed basic attestation uses a separate persisted P-256 signing key and
an X.509v3 leaf certificate with optional supplied chain. A per-device self-signed
identity can be generated, or a matching PEM certificate chain and unencrypted
PKCS#8 signing key imported at creation. The leaf public key must match that key;
subject, basic constraints, key usage, optional AAGUID extension and supplied
chain links are validated. Current validity is required at certificate import
and basic signing. Structural validation at store/backup loading allows expired
identities to retain their independent existing credential assertion keys. No
certificate regeneration or renewal occurs during registration. Public APIs and
events do not return attestation private material; explicit protected backups
include it. See the identity document for format bounds and trust limitations.

Device and USB labels describe returned `platform` / `cross-platform` attachment
and `internal` / `usb` transport hints. Both are software WebAuthn/FIDO2-style
keys and support discoverable credentials and password-authorized UV. They do not
create a physical USB device, U2F/AppID transport or hardware-backed key. The separate
experimental opaque FIDO relay above does not convert these saved software keys
into hardware credentials or change their security claims.

Supported: top-level and same-origin iframe ordinary create/get requests,
resident credentials, RP/allow-list filtering, exclude-list enforcement,
multiple keys/accounts, and native abort. Unsupported requests fail closed:
cross-origin iframes (proxy lacks trustworthy topOrigin), legacy AppID, algorithms
other than ES256. Chromium's proxy explicitly does not support conditional
mediation/passkey autofill. Advanced optional extensions are not advertised.

Old CDP-format IDs, PKCS8 private keys, RP IDs, user handles, and counters remain
in the same JSON store; supported ES256 credentials are consumed directly. Old
presence/UV booleans remain deserializable but are ignored for authorization.
Unsupported legacy key formats remain preserved and fail signing explicitly.

## Web and deployment boundary

Only Rust TCP 8080 is published. x11vnc listens on loopback; the WebSocket and
noVNC modules require desktop authorization. Settings access is independently
protected. The gateway deliberately has no Host allowlist or Origin/Fetch
Metadata admission check, so LAN addresses, arbitrary public domains/ports and
Host-rewriting proxies require no hostname configuration. HttpOnly SameSite
cookies, session-bound CSRF, JSON mutation validation and restrictive CSP remain
enforced; no permissive credentialed CORS policy is added. Cross-origin WebSocket
admission is also relaxed. Do not expose password-disabled gateway functions to
untrusted networks. The local helper retains its own Host checks and exact-Origin
approval. API responses redact secrets except explicit protected backup export.

Compose retains the explicitly selected `--no-sandbox` and `./.data:/data` bind
mount. Other launches preserve the Chromium sandbox unless explicitly disabled.
No privilege, host device, custom seccomp, or broader mount is introduced. The
entrypoint only initializes an empty dedicated data directory before dropping
to UID/GID 10001. Container administrators and same-UID code can access private
keys; the no-sandbox compatibility setting increases malicious-page risk.

If the native bridge disconnects while attached, requests fail closed. Extension
unload, browser shutdown, or attachment failure are separate Chromium lifecycle
events; readiness is false and the project does not claim control of unrelated
browser authenticators after Chromium detaches an unavailable extension.

## Official sources

- https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/authenticator_common_impl.cc
- https://chromium.googlesource.com/chromium/src/+/main/components/webauthn/json/value_conversions.cc
- https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/

## Configurations and reference scope

New registrations honor `resident_key_supported`: required resident credentials
exclude incompatible keys, preferred falls back to nonresident, and existing
credentials are never rewritten by toggling capability. The four new settings
have migration-safe defaults. AAGUID, attachment, resident support and attestation are immutable after
authenticator creation; signed registration metadata is persisted per credential.
Nickname, Provider display label, enabled state and runtime timeout are editable.
Provider edits revoke current confirmations without rewriting certificate subjects,
certificate bytes, cryptographic keys or historical credential snapshots. Server-side PATCH
validation rejects identity fields rather than relying on disabled controls.
See [identity and authorization](identity-and-authorization.md) for the field matrix.

The reference https://passkey.phphy.com/ is a physical device commissioning UI.
USB product descriptors, VID/PID, LED/GPIO, secure boot, and secp256k1 switches
cannot be implemented truthfully through WebAuthenticationProxy and are not
exposed as fake capabilities. Local labels do not change Chromium's chooser or
RP trust. Relevant standards:
- https://www.w3.org/TR/webauthn-3/
- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html

## Browser recovery and backup restore

The browser route has a floating collapsible navigation surface; settings retain
the expanded surface geometry. Authenticated, CSRF-protected browser operations
use a gateway-instance scope, exact-next sequence and per-action UUID. Initial
entry ensures one maximized window without restarting a live browser. Manual
reconnect consolidates normal-window tabs through the managed extension, requests
`Browser.close` over private inherited pipes, waits for the owned process to exit,
and launches the same profile with `--restore-last-session`. The new extension
connection must verify stable URL/order/pinned/group fingerprints before success.
Window-inspection ambiguity, unsupported privacy/window types, timeout and failed
restoration fail closed. X/Openbox/VNC are retained; VNC rebinding is independent.
No debugging TCP listener, arbitrary CDP endpoint, profile deletion or hard-kill
fallback is introduced. Saved tabs do not guarantee unsaved page state or retained
session-only cookies. See [browser lifecycle](browser-lifecycle.md) for descriptor
ownership, bounded replay protection and source/simulation validation limits.

Keys-only restore uses a validated preview, exact content and current-store
hashes, a session-bound expiring token, a pre-restore export, and explicit
confirmation. No private key or hash appears in previews. Imports reject
unsupported algorithms and malformed identities, preserve matching credentials’
higher local counters, and reject private-key conflicts. Restoration invalidates
in-flight requests. See [backup restore](backup-restore.md).

## Locally bundled Material UI frontend

`web/` is a real React + TypeScript application using `@mui/material` and
Emotion. Vite emits hashed assets under `web/dist/assets/` and an HTML entry point.
`web/dist/` is generated, not a second implementation. The Docker Node stage installs
exact dependencies from `pnpm-lock.yaml` with `pnpm install --frozen-lockfile`, then builds before
copying static output into the runtime. Node, pnpm, tests and dependency trees do
not run in the deployed image. noVNC remains Debian's locally installed ES-module
package behind the existing authenticated `/novnc/` route. Its dynamic import
uses the root absolute `/novnc/core/rfb.js`, never a CDN or an `/assets/` relative
path. All fonts use the operating system's installed fonts.

The Rust HTML handler replaces `__CSP_NONCE__` with a new cryptographically random
nonce for each response. Emotion's cache receives it and applies it to generated
style elements. The gateway retains same-origin-only scripts and connections,
no inline scripts/eval, denied framing, no-store, nosniff, and no-referrer. Dynamic
MUI layout/transition and noVNC dimensions need a scoped `style-src-attr
'unsafe-inline'` exception; `style-src-elem` still requires self or the response
nonce. React renders all external text as text, never injected HTML. No remote
fonts, runtime CDN, external script, or inline bootstrap script is required.

The UI uses Material UI dialogs rather than browser confirm boxes. Request
selection, setup, verification and touch remain separate views with separate
POSTs. Connection gaps, page exit, session changes, snapshot changes and local
expiry clear the active password inputs before showing a new authorization view.
Only read-only snapshots reconnect; mutations are never automatically retried.
Backup source content is held only for the active restore dialog and cleared on
close, conflict or session replacement; secret fields are never shown in preview.

Reference: https://mui.com/material-ui/guides/content-security-policy/
