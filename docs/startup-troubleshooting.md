# Startup troubleshooting

## Private D-Bus: `rule cannot be per-user because it has bus-global semantics`

This is a policy-scope error in the application's `runtime/dbus-system.conf`,
before Chromium starts. It is unrelated to host sandbox, seccomp or Bluetooth
permissions. D-Bus `<allow user="..."/>` controls who can connect to the whole bus
and cannot appear inside `<policy user="...">`.

The corrected configuration puts `<allow user="authbrowser"/>` after
`<deny user="*"/>` in `<policy context="default">`. Per-user policy retains only
`org.bluez` ownership and messaging permissions. If patching an old source tree,
move only that rule; do not allow every user. The bus still listens only on
container-private `/data/run/dbus-system.sock`, with no host-bus mount or host
security-policy change.

After safeguarding data with the [migration procedure](data-migration.md), rebuild
only this service:

```sh
docker compose up --build -d --no-deps webauthn-browser
docker compose logs --tail 100 webauthn-browser
```

Parser regression, requiring `dbus-daemon` and `dbus-send`:

```sh
python3 tests/dbus_policy_test.py
```

The temporary test configuration maps the container username to the current UID;
otherwise a missing username can make D-Bus ignore the policy and mask the bug.
It tests the corrected configuration and original error. Real Unix-socket
startup, GetId and name-ownership tests explicitly skip under EPERM; that is not
a complete desktop pass. See the [dbus-daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).

## Docker: `/proc/.../ns/net -> /var/run/docker/netns/...: no such file or directory`

This occurs while Docker creates/joins the network namespace, before the app
starts. A single line does not distinguish stale runtime state, an exited process
or another daemon/network fault. Chromium flags cannot be assumed to fix it.

Start with read-only checks:

```sh
docker compose ps -a
docker compose logs --tail 100 webauthn-browser
docker version
docker info
docker inspect --format '{{json .State}}' CONTAINER_ID
```

Use the exact verified ID from `ps -a`. If data has not yet been copied, starting
that same container with `docker start CONTAINER_ID` does not recreate it or apply
new mounts/commands. If it still fails, retain the container and error time and
inspect the matching Docker daemon logs. Do not restart the global Docker daemon,
prune networks/system state or delete `/var/run/docker/netns` based on this line;
those actions can affect other projects.

Applying a new image requires service recreation only after a complete verified
[data migration](data-migration.md). No host operation or successful repair of a
user's Docker network is implied by these instructions.

## Chromium namespaces and sandbox

Compose explicitly selects `command: ["--no-sandbox"]`. This disables Chromium's
browser sandbox while retaining Docker's default seccomp and the non-root browser
user. No custom seccomp file is required. See the security warning in the README.

Direct image execution without that argument keeps Chromium's sandbox. A
`Failed to move to new namespace … Operation not permitted` failure can involve
seccomp, AppArmor or host user-namespace policy; the line alone does not identify
which. The application never automatically relaxes permissions or switches modes.

## Management and health

- `/settings` remains available when the desktop fails, allowing runtime inspection,
  security/key management and backups.
- `/healthz` means the gateway is alive. `/readyz` returns 503 and Docker's
  HEALTHCHECK fails if the desktop or authentication engine is not ready.
- `/api/runtime` follows Settings-password authorization and reports status and
  sandbox mode, without exposing raw browser logs or credentials.
- Backup includes only saved/received credential events, not events lost before
  delivery during a crash. Authentication, CSRF and download confirmation remain.

## Xvfb, Openbox and XIO

The image precreates root-owned `/tmp/.X11-unix` with mode 1777. A separate `/tmp`
tmpfs can hide it; a non-root recreation may produce ownership warnings on some
X versions. Default configuration does not mount that extra tmpfs. An Openbox
menu file is supplied. XIO after desktop cleanup is usually a consequence of
shutdown, not the cause of a Docker network-namespace error.

## Initial entry and Reconnect Browser

Initial authorized page entry sends `ensure`: preserve live Chromium, consolidate
supported normal-window tabs and maximize. A confirmed windowless background
process gets one window from the authenticated extension. Manual Reconnect Browser
("重新连接浏览器") sends `restart`: consolidate first, request graceful Chromium
close over supervisor-owned private pipes, wait for process exit, launch the same
profile with `--restore-last-session`, verify saved-tab semantics and maximize.
Status polling and VNC transport reconnection do not invoke manual restart.

This restores saved tabs, not guaranteed unsaved forms or application memory.
The close path skips beforeunload warnings. Session cookies and clear-on-exit data
follow browser preferences, so sign-in may be needed again. No privacy preference,
cookie database or profile is rewritten, and timeout has no force-kill fallback.
See [managed browser lifecycle](browser-lifecycle.md).

Failed/timed-out/incomplete window detection or unrecognized WM_CLASS produces a
bounded error without treating uncertainty as closure. Minimized windows, other
desktops and desktop `-1` are considered. A new owned process starts only when the
tracked browser has exited/is absent and wmctrl plus both EWMH client lists
confirm an empty inventory. A living windowless process instead uses the extension
to create a window. Unknown other windows conservatively block recovery; arbitrary
window recognition is not promised. A live auxiliary Chromium window launcher
also blocks manual restart before close/capability retirement.

Regressions: `python3 tests/browser_reconnect_test.py`,
`python3 tests/browser_control_test.py`, `python3 tests/browser_cdp_test.py`, and
`node tests/extension_window_test.cjs`. These exercise actual owned Python
subprocesses and modeled window-manager/Chrome APIs, not real Chromium, an X
desktop or a personal profile in this environment.

## Engine crashes, disconnects and D-Bus addresses

- If the Rust gateway/signing engine exits, the supervisor cleans up and restarts
  only its owned process group with 1, 2, 4, 8, 16, then 30-second backoff. One
  minute of stable connection resets it. Chromium, tabs, profile and desktop are
  preserved; the management page briefly disconnects while the gateway restarts.
- Native-messaging loss or heartbeat timeout reconnects the host without restarting
  a live browser. In-flight approvals/signing/registration are invalidated and are
  never replayed; retry the website operation after recovery.
- Chromium nonzero/signal exit uses bounded automatic crash recovery. Normal last-
  window closure is not a crash; a fresh authorized ensure can restore it. VNC
  departure, GCM `DEPRECATED_ENDPOINT` or ordinary D-Bus warnings do not prove a
  crash. Container shutdown does not restart children.
- Native mode retains only its existing remaining lease during host/gateway
  reconnect. A transport break does not prematurely reattach the global software
  proxy or renew/revive revoked phone pairing. Proxy mode resumes after actual
  expiry or explicit stop.
- `Could not parse server address: Unknown address type` is an address parse
  error, not proof that the authentication engine crashed. Runtime explicitly
  sets `DBUS_SESSION_BUS_ADDRESS=unix:path=/data/run/dbus-session.sock` and runs a
  supervised private session bus. System bus remains separate at
  `/data/run/dbus-system.sock`; host D-Bus is neither read nor mounted.
- `org.freedesktop.UPower ... ServiceUnknown` means this minimal container lacks
  UPower. It is not an address-format error or restart signal. Readiness requires
  the actual proxy/native control connection to recover.

## Stale authentication extension after an image upgrade

A newer native-host build with `browser ready; extension=legacy/unknown`, requests
but no heartbeat/mode progress indicates that the ready frame lacks current engine
metadata. The earlier v27 `extensionVersion` sender/reader names already matched;
this was not a Rust field-renaming loss. Recovery after clearing data supports a
persistent-state explanation but does not identify a particular cache. Deleting
data is not an upgrade procedure.

The image build and prelaunch verifier check packaged manifest/scripts/recovery
page, fixed extension ID and native-host allowed_origins, then print version and
asset SHA-256. Ready must match the image's `extensionBuild`, version `1.0.29`,
protocol `1`, required heartbeat/generation/mode/lease capabilities and consistent
mode/attached state. Bare ready or a connected legacy control channel is insufficient.

An incompatible handshake invalidates software requests and phone pairing. The
supervisor opens only the fixed internal upgrade page, which checks the executing
worker constant and selectively calls `chrome.runtime.reload()` when needed.
Each cycle permits two 15-second attempts; expired pages and late callbacks cannot
reload. Active-cycle repeats and status polling do not grant more attempts.
No management permission, debugging TCP port or profile-database rewrite is added.
Settings, cookies, login data, tabs and saved authenticators are not erased. During
the brief detach/reload interval Chromium returns to native WebAuthn handling;
this is not uninterrupted interception. Wait for recovery before retrying sign-in.

Only a fresh valid handshake restores ready. Failed attempts stop with a clear
status rather than infinite reload or automatic authentication replay. Missing
upgrade assets or an old installation path can defeat automatic reload. Preserve
`/data`, back up and recreate this service from current source; inspect fixed ID
`hjfbndgjlhfjaplmakeicgoibanbncaf` in container Chromium's `chrome://extensions`
and manually reload the installed authentication extension if needed. Do not reset
cookies/passwords or remove a personal profile. A current working extension is
not automatically reloaded. See [storage and selective recovery](runtime-storage.md).

References: [extension reload](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#reload),
[WebAuthenticationProxy attach lifecycle](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy#method-attach),
and [Chromium worker reuse/deactivation](https://chromium.googlesource.com/chromium/src/+/main/extensions/browser/service_worker/service_worker_task_queue.cc).
Real old-profile/new-image Chromium upgrade acceptance was not run here; asset,
VM and mock checks do not replace it.
