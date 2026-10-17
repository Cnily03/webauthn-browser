# Managed browser lifecycle

## User actions

All operations below apply to one selected [profile](profiles.md). Browser data,
supervisor state, displays, VNC and native capabilities are not shared between
profiles. The active engine owner may resize that profile's display to the
current outer viewport on page entry and manual reconnection, including shrinking
either axis.
Standby viewers cannot resize it; ordinary window resizing alone does not send
continuous display changes.
Sizing is best-effort. Invalid optional dimensions or a RandR sizing failure do
not block the requested lifecycle operation. Inspection never changes geometry.
Cancellation, expired ownership and real browser shutdown/startup failures remain
hard failures; a sizing error never authorizes a second restart. A partially
applied resize is not reported as restored or successfully verified.

- Initial authorized outer-page entry sends `ensure`. A live browser stays alive.
  Existing normal-window tabs are moved into one window, which is maximized and
  focused. A confirmed empty live browser gets one fixed `about:blank` window
  through its managed extension. A confirmed exited browser is launched with
  its existing profile and `--restore-last-session`.
- Manual reconnect sends `restart`. The extension first consolidates normal
  windows, then the supervisor requests whole-browser shutdown, waits for the
  owned process to exit and for a confirmed empty window inventory, and launches
  a new owned process. Success requires a fresh extension connection and matching
  saved-tab fingerprint, followed by one maximized window.
- VNC reconnection, status polling, Settings visits and automatic ensure do not
  issue the manual restart command. The outer page rebinds its VNC transport
  separately; it does not remount the native-mode controls merely to reconnect.

The browser API requires profile access, current engine ownership and CSRF
protection. Browser endpoints below use the `/p/{canonical_name}` prefix. An
authenticated GET `/p/{canonical_name}/api/browser/reconnect` obtains `operation_scope` (a public gateway-instance
UUID) and `operation_sequence` (the exact next u64 value as a decimal string).
POST to that path includes these two fields plus `action:"ensure"|"restart"` and
`request_id:UUID`. Replies echo the correlation fields plus `window_count:1`,
`engine_ready` and `restarted` (false for ensure, true for restart).

One operation runs at a time per profile. A monotonic high-water value for that
browser prevents replay without storing unbounded lifetime history. The backend
retains at most 128 recent terminal receipts plus the inflight operation; exact
cached retries require all request fields and the authenticated owner to match.
After receipt eviction, an old sequence is rejected rather than treated as new.
A new gateway instance has a new scope, so earlier commands remain invalid. The
GET does not reserve a sequence: competing callers can receive the same value,
and only one exact-next admission succeeds. A stale or busy initial `ensure` can
obtain a fresh intent using a bounded retry; an uncertain/manual `restart` is
never automatically retried. There is no 128-actions-per-session lifetime limit.

Jobs have a shared 55-second limit and check authorization around asynchronous
phases. The gateway drops its private supervisor connection when authority or
the deadline expires; the supervisor checks connection liveness between close,
wait and replacement-launch phases. Cancellation after an irreversible browser
close may leave the browser closed until a fresh authorized ensure, rather than
silently starting a replacement after logout.

## Tab and window handling

The packaged extension declares `tabs` and `tabGroups` for this feature. It reads
normal-window tab state, then uses [`tabs.move`](https://developer.chrome.com/docs/extensions/reference/api/tabs#method-move)
and [`tabGroups.move`](https://developer.chrome.com/docs/extensions/reference/api/tabGroups#method-move)
to move existing contents. It never closes tab contents or calls `windows.remove`
to discard extras. Empty source windows disappear as Chromium moves their last
tab. Target-window pinned tabs remain first, followed by other pinned tabs and
then ordinary tab/group blocks in deterministic source-window order. Groups
move together, preserving their titles, colors and collapsed state. The prior
target active tab is restored before maximization.

A preflight rejects incognito, popup/app/devtools or shared-group cases, pending
navigations, oversized inventories (16 windows / 512 tabs), and an extension/X
window-count mismatch. This also rejects hidden incognito windows unavailable to
the extension rather than assuming they are absent. A concurrent change or API
failure stops subsequent mutations. Already completed tab moves may remain in
place, but unmoved tabs are never closed and a failed consolidation does not
advance to browser shutdown. An in-progress Chrome API call retains the
single-flight lock until it settles, even after cancellation, so a delayed move
cannot overlap a newer control operation. A permanently stuck API fails closed
instead of accumulating concurrent mutations.

The before/after fingerprint includes ordered URL, pinned state and stable group
semantics, not numeric tab/window/group IDs, which change after restart. Only a
SHA-256 digest and counts cross the native control channel; raw URLs, group titles
and page state are not logged or stored in backend history. Verification failure
is reported as failure, never as restored success.

## Process and descriptor ownership

The supervisor launches the fixed packaged native ELF directly with
`--remote-debugging-pipe`, including when experimental USB is opted out. The
Debian shell wrapper is unsuitable for retaining the private pipe descriptors.
There is no debugging TCP listener or external arbitrary-CDP endpoint. The pipe
adapter exposes only `Browser.getVersion` and `Browser.close`, with bounded
messages, request IDs and timeouts. Chromium reads requests on child fd3 and
writes responses on fd4, using NUL-delimited JSON.

`posix_spawn` file actions perform all descriptor mapping in the child, preserving
parent fd3/fd4. Explicit FIDO capabilities are duplicated to collision-safe high
FDs; unrelated inherited descriptors are closed. Each browser has its own process
group and a supervisor epoch. Restarts require an epoch match. The previous FIDO
control/report generation is retired before the fresh browser receives a new
one; a self-relaunch cannot inherit the old capability. This is ordinary process
ownership, not a new sandbox boundary.

The parent pipe remains open for the whole browser generation: Chromium treats
pipe disconnect as a close request. A failed/timed-out request therefore retains
the pipe while the process lives. Restart also rejects a still-running auxiliary
Chromium launcher before close or capability retirement, avoiding a competing
singleton handoff. After a close request, actual process exit and
empty window evidence are required; an ACK alone is insufficient. Timeout has no
SIGKILL fallback. Normal container shutdown retains its existing cleanup policy.

Window enumeration validates `wmctrl -lx` rows, including minimized windows and
desktop `-1`. Unknown classes or malformed rows fail closed. An empty result is
cross-checked against present, explicitly empty `_NET_CLIENT_LIST` and
`_NET_CLIENT_LIST_STACKING` properties. Restoration requires exact maximized
atoms, absence of hidden/fullscreen state and matching active window. See
[wmctrl source](https://sources.debian.org/src/wmctrl/1.07-7/main.c/) and the
[EWMH client-list specification](https://specifications.freedesktop.org/wm/1.5/ar01s03.html#idm139870830058432).

## Saved-session limits and evidence

This uses `Browser.close` plus supervisor relaunch, not Chromium's native
`AttemptRestart`. The [browser close delegate](https://chromium.googlesource.com/chromium/src/+/5086bb4239aca3ab7a0ed13d8bdbe796a52c6edc/chrome/browser/devtools/chrome_devtools_manager_delegate.cc)
uses `ExitIgnoreUnloadHandlers`: beforeunload/download warnings are skipped.
The [close manager](https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/lifetime/browser_close_manager.cc)
flushes session services before closing windows, supporting saved-tab restoration.
Native restart additionally force-keeps session data; this implementation honors
session-only cookie and clear-on-exit settings. Unsaved forms, page memory,
incognito contents, canceled downloads and unchanged signed-in state are not
promised. Browser privacy preferences and profile databases are not edited.

The [pipe lifecycle source](https://chromium.googlesource.com/chromium/src/+/refs/tags/140.0.7275.0/chrome/browser/devtools/remote_debugging_server.cc)
and [NUL-framing implementation](https://chromium.googlesource.com/chromium/src/+/main/content/browser/devtools/devtools_pipe_handler.cc)
provide the private transport contract. These lifecycle references are official
current or explicitly pinned other revisions, not a claim that every linked file
was obtained for Chromium154. The image uses Debian-maintained Chromium and
checks the installed ELF; its exact packaged version depends on the image build.

Validation includes actual owned Python subprocess peers for pipe mapping,
fragmentation, timeout, stale replies, exit ordering and fresh-process handoff,
plus modeled window-manager and extension APIs. It has not launched real Chromium,
merged personal tabs or verified real session restoration in this environment.
