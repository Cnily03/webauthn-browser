# WebAuthn Browser usage guide

A Chromium desktop and software WebAuthn authenticator behind one HTTP port, with
a Rust backend, React/Material UI frontend and persistent project-local `./.data`.

## Startup

**Migrate existing data before upgrading.** The `./.data:/data` bind mount hides
old container-local data rather than copying it. Keep the old container, stop it,
back up and copy its complete `/data`, then recreate the service. See
[data migration](data-migration.md). Only a first deployment can start directly:

```sh
docker compose up --build -d
```

The project uses `docker-compose.yml`. It publishes `8080:8080` on all host
interfaces and selects `restart: unless-stopped`. Configure passwords and review
network exposure before opening access.

Without Compose, a first deployment can build and run explicitly:

```sh
docker build -t webauthn-browser .
docker run -d --name webauthn-browser \
  -v "$PWD/.data:/data" \
  --tmpfs /data/run:uid=10001,gid=10001,mode=0700 \
  --tmpfs /tmp/webauthn-browser-cache:uid=10001,gid=10001,mode=0700 \
  -p 127.0.0.1:8080:8080 webauthn-browser --no-sandbox
```

The upper-left navigation and lower-left draggable/collapsible browser controls
are independent. Double-arrow buttons have accessible names and tooltips; Settings
keeps the navigation alignment space. Browser controls show mode, engine status,
Reconnect Browser, Ctrl+Alt+Delete and fullscreen. Canvas connection/recovery
status is separate and disappears only after actual connection.

Initial authorized page entry ensures one maximized window: preserve an existing
browser, consolidate supported normal-window tabs and focus it, or create a window
when its absence is confirmed. Manual reconnect gracefully closes Chromium, starts
the same profile with saved-session restoration, verifies URL/order/pinned/group
semantics and maximizes. Unsaved forms and clear-on-exit session data are not
promised. Failure is visible; see [browser lifecycle](browser-lifecycle.md).

Open `http://localhost:8080/` for the noVNC desktop or
`http://localhost:8080/settings` for security, browser profiles and authenticators. Only 8080 is public;
VNC listens on container loopback. Private inherited browser-control pipes expose
no TCP debugger. No host device, privileged mode or `.env` is required. Compose
passes `--no-sandbox` at runtime; `docker build` does not launch Chromium. Docker's
default seccomp is used, without a custom seccomp file.

This compatibility choice disables Chromium's sandbox. Chromium and the gateway
still run as non-root UID 10001 with Docker isolation, but a malicious page that
exploits the browser could read container keys, browser data and mounted `./.data`.
Use trusted content. The entrypoint briefly uses root to initialize only a fresh
dedicated directory, then drops privileges; it does not recursively change host files.

Access passwords are initially disabled. Configure the global Settings password
under Security and individual profile passwords under Browser settings as needed;
Unicode is supported without a complexity policy. Profile passwords must be
nonempty whenever the enabled protection switch is saved, even on an existing
protected profile. Switch protection off and save to allow passwordless access.
VNC uses web access control, not the old eight-byte VNC password
limit. With a password disabled, anyone able to reach that function can use it.
Compose exposes all host interfaces; the direct-run example above is loopback-only.
For remote access, use a trusted HTTPS reverse proxy, HTTPS-only/HSTS policy and
`AUTH_BROWSER_SECURE_COOKIES=true`.

The gateway does not filter Host, Origin or Sec-Fetch-Site, so LAN IPs, custom
hosts/ports and rewritten proxy Host values need no domain configuration.
`AUTH_BROWSER_ALLOWED_HOSTS` is obsolete. Optional passwords/session validation,
mutation CSRF tokens and JSON validation remain. The local helper independently
requires exact-Origin approval. Gateway admission also allows cross-origin
WebSocket attempts; this does not grant browser CORS access. Never expose a
password-free service to an untrusted network.

## Names and upgrade compatibility

The display name is **WebAuthn Browser**. The project executable and Compose
service remain `webauthn-browser`, the frontend package is
`webauthn-browser-frontend`, and helper binaries are `webauthn-helper` and
`webauthn-helper-desktop`. Download filenames append platform/architecture.
The canonical authenticator-management URL is `/settings#authenticator`; older
`#keys` bookmarks still work.

Display naming does not reset or migrate data. The service reads the same
`auth-browser.json` and Chromium profile, retaining `AUTH_BROWSER_*`, container
user `authbrowser`, native host `com.auth_browser.proxy` and fixed extension
identity. Credential APIs, backup format, AAGUIDs, certificates and saved Provider
labels remain unchanged. Old backups with no Provider retain the historical
`Auth Browser` default. `/opt/webauthn-browser` is the image installation path,
not persistent storage. Follow [migration](data-migration.md) before replacing an
old Compose service; never run old/new instances against one profile.

## Profiles and concurrent viewers

Browser settings contains the multi-profile switch and profile list. Each profile
has independent browser data, optional access protection and an idle timeout;
the authenticator library remains shared. Open `/profile/{name}` directly, or use
`/` to resume a remembered default or select a profile in multi-profile mode.
The profile icon follows the leftmost collapse button and hides with the
navigation links. It opens remembered profiles; its add action opens the
chooser. Expand a profile in Browser settings to edit it inline.

With multi-profile mode off, `/` opens `default`, every `/profile/*` page redirects
to `/`, and other profiles become
unavailable without losing their configured enabled flags or data. The default
profile cannot be renamed or deleted. Remembered credentials have a rolling
30-day inactivity limit; menu entries remain until explicitly forgotten. Mode
changes preserve valid remembered access. The menu marks the current profile
green, invalid authentication orange, and unavailable identities red. Right-side
status tooltips explain the distinction; detailed errors use the global notice.
Clicking the current row does nothing. Removing an inactive row needs a second
click within three seconds and clears only that browser's saved access.
Deleting a non-default profile in Settings is different: its confirmation
authorizes permanent deletion of all that profile's browser data after its
connections are revoked and runtime shutdown is confirmed. Back up needed data
before confirming; creating the same name later starts with fresh storage.

The first eligible viewer owns that profile's authentication engine. Other
viewers do not receive approval or native-helper authority. Actual user activity
extends the configured idle deadline (180 seconds by default); automatic network
traffic does not. On page entry or manual browser reconnection, the active
owner's current viewport sets the bounded VNC display size, including shrinking.
See [profile rules](profiles.md).

## Live text clipboard

A remote Chromium copy immediately attempts to write your local OS clipboard.
An X11 CLIPBOARD text request triggers a fresh outer-page
`navigator.clipboard.readText()` for paste, including shortcuts, the address bar
and native context menu. No advance synchronization or last-value cache is needed.
Only UTF-8 text up to 1 MiB is supported, not images, files, HTML or Linux PRIMARY
selection/middle-click paste. Selecting text alone does not alter the local clipboard.

- Use HTTPS or a browser-recognized localhost secure context, keep the page in
  front and allow the required clipboard access. Remote-IP plain HTTP cannot use
  the Clipboard API.
- A browser may remember permission rather than prompt every time. Each paste
  still calls the read API afresh. If a gesture is needed, click the paste icon (tooltip/accessibility name
  "粘贴剪贴板内容", paste clipboard content) to read the current content. Requests wait at most 30 seconds;
  Chromium may stop earlier. If permission inserts nothing, paste again remotely.
  Failure or denial never falls back to old content.
- If automatic write is blocked, retain the remote selection and use
  the copy icon (accessibility name "重新复制选中内容", copy selection again).
  That gesture starts a fresh browser
  write and remote Ctrl+C, without replaying failed text. Browsers without
  asynchronous ClipboardItem support need write permission followed by a new copy.
- Only one outer clipboard connection may own a desktop. Other windows show
  unavailable; close the other connection and reconnect. Leaving, locking,
  disconnecting or newer operations invalidates old read results.

An authenticated WebSocket and private Unix socket connect the X11 bridge.
Built-in noVNC/x11vnc clipboard synchronization is disabled. The application stores
no clipboard history, persistent cache or content logs and does not poll the local
clipboard. Required memory buffers exist only for the current read/write/network/
INCR transfer and are released on completion/cancel/disconnect/timeout. OS/browser/
destination applications still keep their normal data. Submitted Clipboard API
writes cannot be retracted; lifecycle checks stop subsequent app handling only.
See the [full clipboard test procedure](clipboard.md); unit tests do not prove
native-menu/permission/container end-to-end behavior.

## Software authenticators and approval

- Device type is a software WebAuthn authenticator with `platform`/`internal` hints.
- USB type is a software FIDO2/WebAuthn authenticator with `cross-platform`/`usb`
  hints, not a real USB device, U2F or CTAP ClientPIN implementation.
- Both support discoverable credentials and password verification, without claims
  of hardware, fingerprint, TPM or phone cross-device protection. Several can be
  enabled; choose key/account per request rather than applying one to a tab.
- Website registration/sign-in shows an approval overlay in the outer browser,
  with RP ID, request Origin, operation and candidate keys. Every request requires
  explicit allow/reject rather than simulated automatic touch. Nickname/type,
  username/display name, Provider and AAGUID are separate. Missing account names
  use existing user/credential IDs, not guessed text.
- Steps are selection → password setup if needed → password verification → separate
  presence confirmation. Required/preferred UV asks for a password. Initial setup
  requires at least six characters and still needs a separate verification step.
  Discouraged UV goes straight to presence. Wrong password, cancel, timeout or
  disconnect invalidates earlier approval; steps do not substitute for one another.

### Software and Native modes

Select a mode **before** the website starts registration/sign-in:

- Software simulation ("软件模拟") uses stored software keys and the selection,
  password and presence workflow.
- Native relay ("原生中继") waits for actual `webAuthenticationProxy` detachment,
  then stock container Chromium handles both `create` and `get`. The outer page
  does not replace results and the per-request key selector has no QR option.

Native mode adds a download button, monospace helper address and Connect. Downloads
open `/downloads` in a new tab; default address is `ws://127.0.0.1:10233`. The address
and Connect remain editable/actionable. Connection/approval/transient loss show an
inline spinner; green means both mode and helper pairing are acknowledged. These
states do not imply USB attachment or successful authentication.

An unopened WebSocket has a one-second connection bound; an opened socket waiting
for human approval is not interrupted by that timer. Address changes are sampled
every 200 ms and replace old transport; Connect immediately replaces the attempt,
even at the same address. Late callbacks cannot restore an older attempt. Retry
does not grant consent: explicit local rejection/revocation stays blocked until
allow-again in the helper, without duplicate approval prompts.

Native mode relays phone hybrid/caBLE BLE discovery and provides an experimental
FIDO USB report path after local approval. It is not generic USB or legacy FIDO
BLE GATT. A software key's `usb` label is unrelated to physical attachment. See
[Native-mode scope](inline-native-qr.md).

### Downloads

The global Downloads page (`/downloads`, without a profile selector) lists filenames,
filesystem birth times and readable sizes using Material UI. Unsupported birth
time is shown as a dash, never substituted with modification time. Navigation
between browser, Settings and Downloads preserves Native ownership. The page,
global listing and `/downloads/{filename}` files are public and require no
password, even when browser or Settings passwords are enabled. Publish only
files intended for everyone who can reach this server.

`/api/downloads` lists every top-level ordinary file, including documents, empty
files and helper binaries, without requiring a recognized name/format. Links use
`/downloads/{filename}`. The legacy `/download/{filename}` uses the same streaming
handler but retains its browser-password boundary.
The older `/api/companion/*` names remain authorization-equivalent aliases of
`/api/helper/*`. React escapes names and URL-encodes filenames. Downloads are
attachments with `application/octet-stream`, never inline HTML/SVG. Streaming has
no former helper-catalog 64 MiB cap. Files can be added/replaced/removed without restart.

- `AUTH_BROWSER_DOWNLOADS_DIR` selects the directory; default is `downloads` in
  the working directory. Images use `/downloads`, with read-only Compose bind
  `./downloads:/downloads:ro`. UID 10001 must be able to read it. Read-only prevents
  container writes, not downloads.
- A missing directory yields an empty listing and individual 404s without blocking startup.
- Subdirectories, symlinks (including the root), FIFOs and other nonordinary files
  are excluded. Traversal, nested paths and NUL are rejected. Unix backslashes are
  ordinary filename bytes. Held-directory descriptors and `NOFOLLOW` prevent
  symlink replacement from escaping the directory.
- The generic page contains no file metadata before authorization. Listing, file
  routes and the legacy catalog follow VNC access control: 401 until logged in
  when protected, otherwise the same exposure as the desktop.

The legacy `/api/helper/downloads` catalog admits only six known executable
platform names after format checks and publishes actual size/SHA-256. It is
separate from the general directory and has an immutable startup snapshot.

The default source archive includes an empty `downloads/` directory. Its runtime
contents are Git-ignored and are never Docker build inputs. Compose creates the
host directory when absent and mounts it; existing download files stay untouched.
Build helpers using [their instructions](../helper/README.md), or add intended files.
Generated `web/dist/` and compiler targets are not source inputs; build them locally
or through Docker. No historical Git rewrite is required.

`README.md`, `builds.json` and any other ordinary download files are equally
available to authorized visitors. Keep credential stores, logs, private keys,
pairing tokens and other private material out of this directory.

### Connecting the helper

1. Run the platform build of `webauthn-helper` (CLI) or
   `webauthn-helper-desktop` near the phone. Default listen address is
   `127.0.0.1:10233`, with fallback to an available port if occupied. Enter the
   actual displayed address. CLI needs no arguments; `--listen 127.0.0.1:18863`
   and `--help` are available. Standard Rust logs include time/level without
   pairing tokens. Port choice lasts only for the process. Desktop is titled
   WebAuthn Helper Desktop; Listen Address omits `ws://`. Start listens, Stop
   revokes pairing and closes the listener. BLE and USB default on and may be
   disabled independently without canceling the approved pairing. The page
   connects to the helper, not the reverse.
2. Choose Native relay and wait for engine acknowledgment. Pairing needs no active
   website request. Moving/collapsing controls creates no new authority. Mode
   changes cancel intercepted software requests; start the website operation again.
3. Verify the exact Origin in the helper prompt. CLI uses a temporary magenta
   border, cyan selected Approve/Reject choice with a `>` marker, arrows/Tab and
   Enter; default is Approve. Completion, rejection, timeout or disconnect clears
   the prompt and records a source event without tokens. Noninteractive input/EOF
   cannot silently approve. Desktop provides its own prompt. The real user grants
   any OS Bluetooth permission. Approved Origins live only in process memory;
   new Origins need approval, explicit rejection does not repeatedly prompt, and
   process exit clears memory. Each connection still has a new single-use token.
4. Wait for both Native mode and helper pairing before starting the site operation.
   Website requirements, saved credential transports, browser policy and devices
   determine Chromium's choices. Phone QR codes come from Chromium, never the
   outer page. No outer WebAuthn call or fabricated signature completes this flow.
   Keep the phone near the helper computer; pairing alone proves neither scanning
   nor authentication.
5. Mode ownership is bounded and renewable within valid login/CSRF authority,
   independent of a website request. Software switch, page exit, logout, revocation
   or expiry clears ownership and advertisements. Old-page cleanup cannot stop a
   newer owner. Ordinary transport loss retries with fresh tokens; expired sessions
   are cleared before a fresh selected-Native request. Mode requests have a one-
   second wait bound. If creation may have succeeded but its capability response
   was lost, wait for the exact response or lease expiry; status cannot claim it.
   An already-open Chromium native dialog must be canceled there when necessary.

Readiness requires strict version/capability validation and real attach/detach
ACKs. A connected control channel alone is insufficient. Stale-engine recovery
selectively reloads the extension without deleting the profile. Gateway/native-
host builds, extension version and mode-progress logs help locate failure.

The BLE path is phone advertisement → helper → outer page → authenticated gateway
→ private BlueZ/D-Bus → Chromium. Only bounded FFF9/FDE2 service data travels,
not device names, Bluetooth MACs, GATT data or keys. Phone/Chromium retain tunnel
and signing ownership. Container adapter/device IDs are interface objects, not a
claim of a nearby physical radio. Relaying remote advertisements changes the
proximity trust boundary and is not security-equivalent to local native Bluetooth.
Unit checks cannot prove a specific Chromium/phone combination authenticates.

The loopback-only helper requires exact-Origin approval and a one-time token;
CLI/Desktop use the same controlled core with no anonymous scan endpoint. Tokens
are excluded from remote URLs, persistence and logs. The backend validates VNC
session, CSRF, ownership generation, expiry, size and rate. Cleanup cannot retract
an advertisement already delivered to Chromium or undo completed authentication.

Mixed-content, Private/Local Network Access and OS Bluetooth permissions remain.
A browser-blocked local WebSocket cannot become connected through retries. The
project does not change firewall, certificates, browser policy/security flags or
host permissions. Helper addresses are loopback WS(S)/HTTP(S) only; the backend
does not connect to arbitrary URLs. See [helper requirements](../helper/README.md).
The old remote WebAuthn API remains for compatibility tests, but global-mode UI no
longer uses `remoteDesktopClientOverride`. Real platform/network/browser acceptance
still requires a supported environment.

## Identity settings and credential details

Authenticator lists use distinct USB/device icons. Credential rows show RP ID and
username; expansion reveals display name, Base64 user/credential IDs, registration
time/AAGUID, requested/actual attestation and other registration snapshots, counter
and discoverability. IDs can be copied and wrap; delete is separate from expand.
User IDs are opaque bytes, never decoded as names. New timestamps record service
creation time, not site-attested time; missing older metadata stays unknown.

Authenticated, CSRF-protected SSE carries registration, sign-in, cancellation,
password-step and presence-step state. Passwords appear only in one-shot POSTs,
never the stream. Reconnect synchronizes the current queue; cursors do not replay
approval. Only one competing tab can claim a request. Lock/password changes/session
expiry revoke subscriptions. Reverse proxies must permit long connections and
disable SSE buffering; the backend sends `X-Accel-Buffering: no`.

Settings distinguishes fixed identity from mutable behavior:

- AAGUID accepts 32 hex digits or 8-4-4-4-12 UUID, case-insensitively, trims edge
  whitespace and persists lowercase hyphenated form. AAGUID, attachment/transport,
  discoverability and attestation mode are fixed after creation; backend edits
  are also rejected. Create another authenticator for another identity.
- Nickname, local Provider label, enabled state and 1–120-second timeout can change.
  A shorter site timeout wins. Changes invalidate pending approval. Provider edits
  do not re-sign certificates, change subjects or rewrite registrations.
- Default none returns no attestation signature/certificate but retains configured
  AAGUID. Self signs with the credential key; basic uses an independent X.509 key.
  These are returned for direct/indirect only. Omitted means none; unsupported
  enterprise falls back to none. Confirmation shows requested and actual results.
- AAGUID is independent of attestation mode. All-zero is the default no-model
  choice; a unique custom UUID may correlate registrations. All-zero does not hide
  a basic certificate that is sent. Old registration metadata never changes.
- Use your own model UUID. Neither custom AAGUID nor Provider creates vendor trust,
  hardware protection or FIDO certification. Website brand names commonly use
  their own AAGUID mapping; no ProviderName return field forces that label.

Self has no `x5c`; basic uses a persisted independent attestation key and real
packed signature/chain. Generate a self-signed P-256 identity or import a leaf-first
PEM chain with matching unencrypted PKCS#8 key. A certificate alone cannot sign.
Identity validity is distinct from website trust. Certificates are not regenerated
per registration or automatically renewed; expiry blocks new certificate
attestation, not existing credential sign-in. See [identity and approval](identity-and-authorization.md).

Older certificates may trigger `BasicConstraints::ca / EncodedDefault` because
explicitly encoding default CA=false is noncanonical DER. New generation is fixed;
old DER and keys remain unchanged. Create a new identity for new basic registrations
and retain the old one for existing credentials. No automatic re-signing occurs.

USB Product Name, VID/PID, LED/GPIO, secp256k1 and secure boot shown by tools such
as [this device debugger](https://passkey.phphy.com/) are physical firmware features,
not software-authenticator controls. The experimental relay uses its restricted
FIDO descriptor without pretending to implement those capabilities.

Software signing uses Chromium's official WebAuthenticationProxy plus Rust, not a
`navigator.credentials` replacement. Chromium validates RP/Origin first and emits
real request/cancel events before approval. Ordinary top-level and same-origin
iframe requests are supported; cross-origin iframe, conditional autofill, U2F/AppID
and non-ES256 software requests are not. Native capabilities depend on Chromium and
the real authenticator. See [architecture](ARCHITECTURE.md).

## Experimental Native FIDO USB

The container-side hook is Linux x86_64 only. The source image builds it and
ordinary startup prepares its control channel, without USB/UHID host mounts,
privileged mode or an added sandbox exception. Start normally, select Native relay,
connect the helper and approve the exact Origin. No separate activation flag is
required. Software/unpaired state does not enumerate/open local HID. One matching
interface auto-opens; multiple require selection, with no silent device substitution.
Chromium and the authenticator retain PIN, touch and signing behavior.

`--disable-ble` and `--disable-usb` independently disable helper channels; Desktop
checkboxes match. Container `AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY=0` is an emergency
opt-out, not an ordinary-startup requirement.

- Linux/Windows implement the restricted unnumbered 64-byte FIDO profile. Development
  checks use builds/simulation. User reports of working transports and intermittent
  USB are separate from a completed hardware validation matrix.
- macOS has no physical USB adapter or supplied executable; no Apple SDK/build
  success is implied by historical source checks.
- BLE is hybrid/caBLE discovery, not every legacy BLE GATT authenticator.
- Static, mocked libudev/HID and actual local IPC tests do not claim real Chromium
  discovery/registration/sign-in. Genuine monitor permission failures stop USB
  visibly; software and BLE remain usable without bypassing the failure.

See [report relay](experimental-fido-relay.md), [helper USB](helper-usb-fido.md)
and [launcher lifecycle](fido-launcher-design.md).

## Bundled proxy extension

The image includes Manifest V3 Proxy SwitchyOmega 3 (ZeroOmega) 3.5.2 with its
official stable ID. Code updates with the image; user rules/settings remain in the
Chromium profile. No proxy credentials/configuration or host proxy changes are
injected. A fresh installation uses upstream's system default. See
[version, hashes, license and source](../vendor/zeroomega/README.md).

## Data, source and operational limits

Compose persists:

- `./.data/auth-browser.json`: keys, credentials, access/key-password hashes and settings
- `./.data/chromium`: browser profile and website data
- `./.data/config`: user configuration

Runtime `/data/run` and new XDG/Chromium disk caches use private tmpfs. Existing
caches are not erased. Bundled code is read-only image content with running-script
fingerprint validation; user extension configuration persists without deleting
shared data. See [storage boundaries](runtime-storage.md).

Recreating a container reuses the same verified data mount; deleting it loses
data. Keep it out of Git, shared archives and public build contexts; both ignore
files exclude it. Never share a profile between simultaneous containers. Software
backup includes unencrypted keys and replaces software keys/credentials only,
not access passwords or browser data. Validate/preview, save a pre-restore backup,
then separately confirm replacement. Changes require a new preview. Matching
credentials retain the higher local counter, but an old backup cannot guarantee
a site's current counter. See [backup and restore](backup-restore.md).

Direct execution without `--no-sandbox` keeps that sandbox and never disables it
automatically after failure. Compose explicitly selects compatibility mode.
Desktop failure leaves Settings/diagnostics available and readiness false. The
project does not modify the Docker daemon, host kernel or host network.

Rust gateway/engine source is in `src/`, React/TypeScript in `web/`, generated web
assets in `web/dist/`, and process management in `runtime/`. Tests and actual
checkpoint results are in [TESTING.md](../TESTING.md). Dependencies are locked;
Docker's Node stage builds real Material UI/Emotion/React assets without runtime
CDN use. For local development use Node 24, run `cd web && pnpm install --frozen-lockfile && pnpm run build`,
then start Rust from the root. System fonts are used, with no Google Fonts request.

Each HTML response has its own CSP nonce for Emotion styles. Scripts remain
same-origin without inline/eval; the positioning/noVNC exception is limited to
`style-src-attr`, not arbitrary external scripts/styles.

Original project code uses GPL-3.0-or-later; independent components retain their
own licenses, listed in [NOTICE](../NOTICE). Source delivery excludes Git history.
References: [WebAuthenticationProxy](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy)
and [Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
