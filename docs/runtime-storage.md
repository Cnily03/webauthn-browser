# Image code, user configuration and temporary runtime state

The service retains `/data/auth-browser.json`, `/data/chromium` and `/data/config`.
Upgrades do not clear browsing history, cookies, passwords, user-installed
extensions and their settings, Chromium security preferences, or virtual keys.

`default` continues using those browser/configuration directories. Additional
profiles use `/data/profiles/{immutable_id}/chromium` and a sibling `config`
directory. The shared JSON store also holds profile configuration and hashed,
revocable remembered-access records. Browser state is independent; the software
authenticator library remains global. Explicit Settings deletion permanently
removes only the selected non-default profile's complete immutable-ID directory
after confirmed runtime shutdown; disabling it preserves storage. A durable
deletion journal supports interrupted requests without purging historical orphan
directories. See [profile boundaries](profiles.md).

The boundary follows ownership and purpose: bundled extension installation code
comes from the current image, while user-installed extensions, extension settings
and other browser data persist. Chromium-managed profile metadata and caches do
not need to be deleted to update the engine. Fingerprint checks and selective
reload identify the current image; they are not a profile-cleaning mechanism.

## Temporary storage

- Compose mounts `/data/run` as tmpfs with UID/GID 10001 and mode 0700. Unix socket
  paths are scoped below `/data/run/profiles/{immutable_id}`; new sockets, runtime
  state and control files do not enter the host's persistent data directory.
- XDG caches and Chromium's `--disk-cache-dir` use the private
  `/tmp/webauthn-browser-cache/{immutable_id}` inside that tmpfs.
- Existing `/data/cache` and profile caches are neither deleted nor moved.
  Existing files under `/data/run` are hidden by the temporary mount, not purged.
- The authentication extension is installed at
  `/opt/webauthn-browser/extension`, owned by root, with directory mode 0555 and
  file mode 0444. Chromium runs as UID 10001; extension code is not copied to `/data`.

Docker creates nested mounts before the entrypoint runs, so a new `./.data` may
already contain only `run`. The entrypoint recognizes this as a fresh runtime
mount only if that child is empty, mode 0700, owned by the browser user, and on a
separate filesystem. It initializes the `/data` directory inode only, without
recursive changes. An ordinary existing directory named `run` gets no exception.

Direct `docker run` needs the same two tmpfs options; starting an image alone does
not create Docker mounts. Prepare dedicated empty `.data` and `downloads`
directories, or preserve the verified old data using the
[migration instructions](data-migration.md), before running:

```sh
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  --mount "type=bind,src=$(pwd)/.data,dst=/data" \
  --mount "type=bind,src=$(pwd)/downloads,dst=/downloads,readonly" \
  --tmpfs /data/run:uid=10001,gid=10001,mode=0700 \
  --tmpfs /tmp/webauthn-browser-cache:uid=10001,gid=10001,mode=0700 \
  webauthn-browser
```

This example keeps Chromium's sandbox. Compose's existing `--no-sandbox` is a
separate explicit deployment choice; see [startup troubleshooting](startup-troubleshooting.md).
These tmpfs mounts isolate temporary container storage and require no host-device
mount, privileged container or host security-policy change.

## Failed runtime resource reconciliation

The manager holds `/data/run/profiles-manager.lock` for its lifetime before
replacing its private control socket. Each profile generation has a private
`/data/run/profiles/{immutable_id}/resources.json` ownership manifest written
before process launch. A private `/tmp/webauthn-browser-resources/{id}.json` lease
retains exact owned X artifact identity across `/data/run` tmpfs replacement.
These files contain runtime identity, not passwords or browser data. Manager
startup runs one bounded reconciliation pass; a gateway-only restart keeps healthy
desktop workers and does not repeat generic startup cleanup. Its separate bounded
pass resumes durable disable/delete intents. Pending resources and failed
inventory checks receive bounded background retries with backoff.

Browser settings exposes **清理资源** for failed/orphan resources; background
recovery also retries unresolved resources. Confirmed resource cleanup removes
allowlisted transient sockets/status files and its manifest. Manual and automatic
retries also finish already-authorized profile deletions recorded in the durable
journal, only after confirmed shutdown. They do not initiate new deletions.
After bounded graceful shutdown, failed-instance cleanup may use pidfd SIGKILL
only for revalidated owned survivors before removing verified runtime resources.
A forced stop can lose unsaved state; normal browser restart remains graceful-only.
Unknown ownership, unsafe nodes or survivors remain pending. Other profile data, caches
and shared authenticator configuration are preserved. See [recovery rules](profiles.md#recovery-and-validation).

## Current-image engine and selective recovery

A normal Manifest V3 extension shares Chromium's default profile storage
partition with websites and user extensions. Its service-worker registration and
script cache can remain in that profile. The disk-cache option does not relocate
that shared Service Worker database, nor must it be emptied to update code.
Deleting Service Worker, Extension State, Preferences or Secure Preferences is
not an upgrade procedure.

The image fingerprints the manifest and packaged engine/recovery scripts with
SHA-256. The value is stamped into worker/recovery constants and compiled into
the Rust broker. In addition to version and capability validation, the ready
handshake must match `extensionBuild`. A stale running script cannot gain a new
identity by reading a changed digest file. This detects stale code; it is not
remote attestation against malicious code.

On mismatch, the service refuses authentication readiness, revokes old requests,
and attempts targeted `chrome.runtime.reload()` through the extension itself.
Each recovery cycle allows at most two attempts, each with a 15-second confirmation
window. A temporary first-load/reload failure can use the second attempt. After
both fail, automatic retries stop. An explicit user recovery or a new owned
browser process can start another cycle; repeated clicks during an active cycle
and ordinary status polling do not increase its budget. Manual restart has the
separate [browser lifecycle](browser-lifecycle.md) preconditions and may fail if
the current engine cannot safely prepare its tabs.

Each recovery URL contains only a random hexadecimal cycle/attempt and a short
expiry, never an RP Origin, credential or authorization token. The recovery page
checks the exact format and expiry and records a single-use attempt marker.
Expired/restored pages, late callbacks and earlier markers for the same build
cannot start another reload loop or claim readiness. The supervisor waits for
both monotonic and wall-clock expiry before retrying to avoid overlapping attempts
when the clock changes.

Only a fresh valid handshake restores readiness. No profile file is edited and
no ownership of shared database records is guessed. Real Chromium reload behavior
still needs an old-profile/new-image end-to-end test; unit/VM checks do not replace it.

After changing packaged extension source, explicitly restamp it, then rebuild
Rust and the image. Ordinary startup verifies assets without rewriting them:

```sh
python3 runtime/verify_extension.py --stamp extension runtime/com.auth_browser.proxy.json
```

Sources: [Chromium storage-partition selection](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/browser/extension_util.cc),
[scope of isolated extension storage](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/extensions/extension_util.cc),
and [same-version component-worker recovery](https://chromium.googlesource.com/chromium/src/+/e3e7c1ea6023efac4775ab4bb9b279d274c5f022%5E!/).

Selective recovery references: [runtime.reload](https://developer.chrome.com/docs/extensions/reference/api/runtime#method-reload),
[extension deactivation/reload](https://chromium.googlesource.com/chromium/src.git/+/HEAD/extensions/browser/extension_registrar.cc),
and [unpacked worker update tests](https://chromium.googlesource.com/chromium/src/+/refs/tags/143.0.7491.0/chrome/browser/extensions/service_worker_registration_apitest.cc).
A page's `ServiceWorkerRegistration.unregister()` is not equivalent:
[MayDeleteServiceWorkerRegistration](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/extensions/chrome_content_browser_client_extensions_part.cc)
protects enabled, version-valid extension root workers; the extension layer owns
unregistration and re-registration for its lifecycle.
