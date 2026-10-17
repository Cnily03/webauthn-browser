# Browser profiles and engine ownership

Profiles separate browser history, website cookies, installed extensions and
extension settings. Each enabled profile has its own browser and remote desktop.
Software authenticators and their credentials remain shared across profiles;
profile isolation does not create a separate authenticator vault or administrator.

## Configuration

Settings separates **Security settings** from **Browser settings**. The latter
contains the multi-profile switch and profile management. The Web UI labels remain
in Chinese.
Security controls the global management password; Browser settings controls
profile access passwords, including the existing default desktop password.

Each profile has a case-insensitive name, a saved enabled flag, an optional access
password and an engine idle timeout in seconds. The default timeout is 180 seconds.
The service supports up to 16 configured profiles, including `default`, and idle
timeouts from 1 to 86,400 seconds.
Names use the GitHub repository-name character set: ASCII letters, digits,
periods, underscores and hyphens, with a maximum length of 100 characters.
The literal names `.` and `..` and names ending in `.git` or `.wiki` are rejected.
Names resolve to immutable internal identities, so a rename does not relocate
browser data or select a different authentication engine.

The `default` profile always exists and cannot be renamed or deleted. In
multi-profile mode its password, enabled flag and idle timeout are configurable.
Turning multi-profile mode off makes `default` effectively enabled and every
other profile effectively disabled. This does not overwrite the saved enabled
flags. The UI disables those switches until multi-profile mode is enabled again.

Expand a profile row to edit its settings inline; canceling or collapsing discards
unsaved edits and clears transient password input. Creation and deletion keep
their separate dialogs. The editor uses one access-password switch. While it is
enabled, saving requires a nonempty password, including edits to an already
protected profile; saved passwords are never read back or prefilled. Switching
protection off and saving removes the password. The disabled input stays mounted.
The API retains its omitted-password semantics for non-form updates.

## URLs and remembered access

- In multi-profile mode, `/` selects a remembered default and resumes it when
  access is valid. An expired protected default shows its fixed-name password
  gate. Without a remembered default, the page asks for a profile name and
  password. The menu add action opens `/` with an explicit chooser intent.
  Leave the password empty when the chosen profile has no password.
- `/profile/{profile_name}` selects that profile directly. If it requires a
  password, the login form shows its fixed name and requires a nonempty password.
  A profile without a password opens directly.
- With multi-profile mode disabled, `/` is the canonical default Browser page.
  Every `/profile/*` page redirects to `/` before profile lookup or login; the
  same default profile data and scoped credential are used. Other profiles remain
  unavailable through their internal APIs.

Protected access is remembered using a profile-scoped HttpOnly credential. The
server expires it after 30 days without use and refreshes that window after valid
use. Passwordless profiles can be entered without a credential. Both kinds are
remembered in the local menu, which stores names, usage metadata and
an optional invalid-authentication hint, never passwords or engine capabilities. Menu records do not expire or
disappear on authentication failure. Mode changes preserve them and valid saved
credentials; effectively disabled profiles remain inaccessible until enabled.
Actual password changes and explicit revocation still invalidate credentials.
Credentials already revoked by an older release cannot be recovered; sign in once
again, then later mode changes preserve valid remembered access.

In multi-profile mode, the collapse button stays leftmost. The profile icon
follows it inside the collapsible navigation region, so it hides with the links.
Its menu marks the actual selected profile green, independently of engine
ownership; clicking that current row does nothing. Invalid authentication marks
a remembered row orange; missing or disabled identities are red. Right-side
Material UI tooltips distinguish the two states. An invalid credential can still
open that named profile's login form; a missing or disabled name stays blocked.
If a name is reused, access is evaluated afresh and the old credential cannot
authorize the replacement. Successful access clears the prior failure;
other rows have no dot. Menu errors use the global error notification.

Hovering or keyboard-focusing an inactive row reveals “移除此配置”. The first
click arms its red removal icon for three seconds; a second click within that
window forgets the local record and this browser's scoped credential. Timeout or
menu closure cancels confirmation. The current row cannot be removed. This does
not delete the server profile or affect other users.

Public Browser destinations use `/profile/{name}` in multi-profile mode and `/`
in single-profile mode. Downloads always uses the global `/downloads` page,
without a profile selector or password; its global listing and files are public.
Ordinary profile discovery, access routes and browser
storage use names only; profile UUIDs remain in backend storage and administrative
Settings. The backend resolves `/p/{canonical_name}` to an immutable identity and
checks each credential against that identity and its authorization revision.
Renaming leaves the existing data directory in place, invalidates old-name access,
and requires login under the new name. Reusing a name never transfers an old
authenticated credential to the replacement profile. The add action opens `/`
with an explicit chooser intent.

Existing saved menu entries migrate to name-only metadata. Old UUID-scoped
HttpOnly cookies cannot be sent to the new name-scoped route without exposing
those identifiers again, so this upgrade requires one fresh sign-in for protected
profiles. Old cookies are unused and expire naturally. No passwords are migrated.
Switching profiles changes the page's browser context; outstanding callbacks and
live capabilities from the old page cannot be retargeted to the new profile.
The user menu is hidden in single-profile mode. Password/profile login screens
retain the same navigation links without acquiring browser-engine authority.
Settings remains governed by the independent management session: changing a
profile or mode does not replace Settings with a browser-password prompt.

## Concurrent viewers

Multiple users can open one profile. Engine ownership is awarded atomically to
the first eligible viewer; other viewers may continue viewing the desktop read-only.
Only the owner can receive and answer authentication requests or control the
native helper relay. A remembered profile login does not itself reserve ownership.
After transport loss or authority revocation, the read-only view hides **接管控制**
until current profile availability and authentication are revalidated. Deleted,
disabled and unauthorized profiles do not offer takeover. Valid disconnected or
idle-expired viewers can still explicitly reacquire; validation never reacquires
control automatically.

The configured idle timeout measures actual user activity. Connection heartbeats,
status polling, automatic retries and incoming server events do not extend it.
Expiry releases the engine; it does not erase the browser profile or its website
sessions. Owner changes invalidate old approval, clipboard and native transport
generations so delayed messages cannot authorize work for a successor.

On remote connection and explicit browser reconnection, the current owner sends
fresh outer page viewport dimensions. The profile display matches this bounded
size, growing or shrinking each axis as needed. Ordinary outer-window resizing
alone does not change the display; page entry or manual reconnection applies it.
Standby viewers cannot resize it. Browser restart and tab restoration retain
the rules in [browser lifecycle](browser-lifecycle.md).
Viewport sizing uses CSS pixels and is bounded to 640–3840 pixels wide and
480–2160 pixels high. Each Xvfb starts with backing capacity for the maximum,
then attempts its initial 1440×900 logical mode before the desktop starts. Later
resizes change the existing display and verify its reported dimensions.
Sizing is optional: invalid dimensions or a RandR failure keep browser startup,
restart and maximization available using the display's current geometry. An
unconfirmed or partially applied resize is not reported as a successful change.
Owner cancellation, deadlines and browser lifecycle failures are still enforced.
This uses the mode-validation and screen-size callbacks in the packaged
[Xvfb source](https://sources.debian.org/src/xorg-server/2:21.1.7-3%2Bdeb12u12/hw/vfb/InitOutput.c)
and the mode/framebuffer application order in
[xrandr](https://sources.debian.org/src/x11-xserver-utils/7.7%2B9/xrandr/xrandr.c).

## Data and runtime boundaries

The legacy default profile keeps `/data/chromium` and `/data/config`. Other
profiles use `/data/profiles/{immutable_id}/chromium` and their own configuration
directory. Profile names are never filesystem path components.

Private sockets, status files, displays, clipboard bridges and relay state are
separate for each running profile. Temporary runtime state is under
`/data/run/profiles/{immutable_id}` and is not part of the persistent backup.
Bundled engine and ZeroOmega code still comes from the current image; extension
configuration belongs to its browser profile.

The global store includes profile configuration and revocable remembered-access
records, alongside the shared software authenticator library. Back up the entire
stopped data directory to preserve all browsers and configuration. An authenticator
export alone is not a profile backup. See [storage](runtime-storage.md) and
[migration](data-migration.md).

Explicitly deleting a non-default profile in Settings revokes access, disconnects
viewers and stops its owned runtime before permanently removing the complete
`/data/profiles/{immutable_id}` directory, including browser data and configuration.
The confirmation warns that deletion cannot be undone. Back up data first if it
is needed. The shared authenticator library and other profiles are unaffected.
Creating the same name later creates a new identity with fresh storage.

The durable `pending_profile_deletion` journal lets interrupted new deletion
requests resume after a restart, automatic retry, manual **清理资源**, or an explicit
retry of the same DELETE request.
Unconfirmed process shutdown or storage removal leaves deletion pending;
it must not be reported as successfully completed. Disabling a profile or
multi-profile mode and local menu forget do not delete browser data. Resource
cleanup may finish only deletions already authorized and recorded in that journal;
it never starts a new profile deletion. Historical orphan directories without a new explicit deletion
record are not purged automatically.

Profiles isolate normal application state and routing, not mutually hostile code
inside one container. They share the service's operating-system user and global
authenticator store. The existing deployment and Chromium sandbox limitations
continue to apply.

## Recovery and validation

The profile supervisor can recover its owned Chromium process. Failed or orphaned
runtime resources are reconciled once before the manager launches the gateway,
automatically on failure, and on demand through **清理资源** in Browser settings.
Pending cleanup and failed inventory checks receive bounded background retries
with backoff. A gateway-only restart does not repeat container-start cleanup.
Manual cleanup requires global Settings authorization and CSRF protection, skips
healthy profile stacks, and does not change profile configuration or remembered
credentials. A bounded pass reports unresolved resources instead of claiming success.
The cleanup response snapshots configured profiles at admission: `cleaned` +
`pending` + `skipped` equals `profile_count`, including default, disabled and
never-started configurations. Concurrent profile changes do not alter that
denominator. Historical deletion jobs are excluded from these three counts;
completed persistent deletions remain separately reported as `deleted_profiles`.
After the durable deletion journal is cleared, completed runtime receipt and
profile-context bookkeeping is retired. A lost acknowledgement is retried without
reintroducing deleted profiles into the configured-profile counts. Only bounded
unacknowledged completion receipts remain for crash-safe retry.

The manager holds a lifetime lock and records each process generation in its
private runtime directory before launching it. Recovery verifies generation,
process identity and ownership; it never targets an arbitrary PID or a newer
profile generation. Failed live workers first use their existing graceful stop.
Verified owned survivors may receive SIGKILL through pidfds after the bounded
graceful-stop deadline. Each process identity and generation must be revalidated
before signaling; unknown ownership remains pending. This recovery path does not
change normal Reconnect Browser, which remains graceful-only. Forced termination
can lose unsaved page state and session-only state. Resource cleanup preserves
browser files, cookies on disk, authenticator configuration and user data except
the complete directory of a profile whose explicit deletion is already journaled. The response counts
completed prior deletions separately and reports unresolved resources as pending.
Settings shows concise, deduplicated reasons for pending cleanup, such as
unconfirmed ownership, timeout or unavailable manager IPC, without exposing
internal profile IDs or raw filesystem errors.

Configuration and pending cleanup intent are saved before a requested stop.
The `pending_profile_cleanup` field in the shared store records immutable profile
IDs; only confirmed receipts clear it. A lost successful reply can be retried for
that exact stopped generation, never against a newer live runtime. Unknown
ownership, unsafe runtime files, unavailable process inspection or surviving
processes keep cleanup pending and the affected slot reserved. Stop replies retain
the 60-second gateway budget; manual reconciliation is a separate bounded pass.

Profile unit/process fixtures cover state, path and transport isolation; the
HTTP smoke covers real gateway login, persistence and access boundaries. These
checks do not establish real Chromium multi-desktop behavior or physical helper
interoperability. See [validation results](../TESTING.md).
