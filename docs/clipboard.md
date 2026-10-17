# On-demand clipboard: implementation and validation

## Transport

- The supervisor starts `runtime/clipboard_bridge.py` after Xvfb. Debian's
  python3-xlib XFIXES support observes CLIPBOARD ownership changes and ignores PRIMARY.
- Copy requests UTF8_STRING from the remote owner and retakes CLIPBOARD ownership,
  preventing Chromium from pasting its own stale cached selection next time. Only
  the current copied text is forwarded to the outer page.
- For paste, TARGETS answers supported types without reading the local clipboard.
  A real text SelectionRequest sends a fresh-ID read request. Only its matching
  response completes that conversion.
- `/api/clipboard/ws` validates the optional VNC-password session and generation,
  then relays bounded JSON through private `/data/run/clipboard.sock`. It exposes
  no additional public port and uses no CDP. Like other gateway routes, it does
  not reject Host, Origin or Sec-Fetch-Site, including cross-origin WebSockets.
  Do not expose a password-free service to an untrusted network.
- React `LiveClipboard` retains no last value. A failed read leaves only its
  request ID. Copy retry uses a gesture-created ClipboardItem Promise and a new
  remote Ctrl+C rather than replaying failed content.
- Plain text is limited to 1 MiB UTF-8 and the JSON wire to 6 MiB + 1024 bytes.
  Large transfers use bounded, timed INCR. Images, HTML, files and PRIMARY are
  unsupported. Content is not written to logs, disk or browser storage.

A submitted Clipboard API operation cannot be canceled. Generation checks discard
old asynchronous results and subsequent handling but cannot retract a write
already handed to the OS. Normal clipboard and destination-page storage are also
outside this application's control. See [MDN Clipboard API](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API)
and [W3C Clipboard APIs](https://www.w3.org/TR/clipboard-apis/).
The built-in noVNC text channel is disabled with x11vnc `-nosel`, avoiding its
internal cache and older Latin-1 protocol path; see the [noVNC API](https://novnc.com/noVNC/docs/API.html).

## Recovery and browser permissions

Remote Copy writes the current text to the local clipboard immediately when the
browser permits it. Remote Paste requests the local clipboard only for that paste.
The browser handles its own permission prompt. If it requires a new gesture after
rejecting a read, click the small paste icon; denied writes offer the copy icon to
copy the current remote selection again. No clipboard history or background reads
are used to work around browser permissions.

The clipboard has a separate WebSocket from the remote desktop. If that socket
closes while the desktop remains connected, it now reconnects automatically with
500 ms exponential backoff capped at 10 seconds. A successful handshake alone does
not reset backoff: the connection must survive 30 seconds. An unopened socket is
bounded to one second and ticket admission to ten seconds. Every scoped retry
obtains a fresh single-use ticket. Clipboard recovery does not restart Chromium,
reload tabs or reconnect VNC. A copy/paste interrupted by failure must be repeated;
its text or pending permission request is never replayed after recovery.

The bridge also recovers a lost X connection with a fresh display/session and
250 ms exponential retry delay capped at five seconds. A session surviving one
minute resets that delay. Teardown first drops all pending requests, partial
messages, copy captures and INCR transfers; it closes the broken connection
without issuing further X requests. SIGTERM/SIGINT cancels retries, including
when X is unavailable during startup. No text is replayed into the replacement
session. A dead Xvfb process still belongs to the broader desktop recovery path;
a clipboard traceback during container shutdown alone does not identify why a
new container's browser failed to connect.

If the clipboard process itself exits while the desktop is active, its supervisor
restarts only that process with a one-second retry delay doubling to 30 seconds.
One minute of a live process and socket resets the delay. Intentional desktop
shutdown cancels recovery; an exited Xvfb, window manager or VNC service retains
the existing desktop failure handling. Clipboard-only recovery does not rotate
browser/profile epochs, detach the engine or touch stored browser data.

The relay sends transport-only Ping frames every 15 seconds. A missing matching
Pong at the next interval closes the private bridge connection, releasing a dead
controller instead of leaving reconnects permanently blocked. These frames do not
renew the profile's user-idle deadline. Changing owner generation replaces only
the clipboard controller; changed viewer identity, logout, pagehide and unmount
block stale callbacks and cancel queued reconnects. Explicit ticket authentication
or authorization failure stops retries until the owning session is reestablished.

## End-to-end checks on a Docker-capable host

1. Run `docker compose up --build -d`. Open the browser page on localhost or
   trusted HTTPS, keep it foregrounded, and verify bridge startup without logging text.
2. Copy Chinese text, emoji, multiple lines, an empty string and text near 1 MiB
   from the remote page/address bar. Verify pasting into a local text editor.
   Merely selecting text must not change the local clipboard.
3. Copy A then B locally. Check fresh values via remote Ctrl+V, Shift+Insert,
   native Paste, Paste as plain text and the address bar. B must not become A.
4. Exercise initial permission allow/deny, dismissed prompts, remembered consent
   and revoked browser permission. If a gesture is required, use the paste icon (tooltip/accessibility name "粘贴剪贴板内容",
   paste clipboard content). A prompt older than 30 seconds must not submit. Chromium
   may time out earlier; initiate a new remote paste if consent inserts nothing.
5. Block automatic write permission, copy remotely, change the selection, then
   click the copy icon (accessibility name "重新复制选中内容", copy the
   selection again). It must copy the new
   selection. Missing selection/timeouts must request retry, never offer old content.
6. While a read permission is pending, exercise new copy/paste, reconnect, lock,
   Settings, Back/Forward and page close. Later approval of the old request must
   not forward stale text into a new session. Separately record the unavoidable
   limit on already-submitted OS writes.
7. A second outer tab must be refused a second clipboard connection. After the
   first closes, the second can reconnect. Text is not broadcast to multiple tabs.
8. Check Chrome, Firefox and Safari over HTTPS. Plain HTTP on a remote IP must
   show an unavailable state without reusing text. Record each browser's own
   permission and gesture behavior separately.
9. Leave the page connected and inactive beyond the reverse proxy's usual idle
   timeout, then copy/paste in both directions. Drop only the clipboard socket
   while leaving VNC alive; it must recover without a page reload or tab restart.
   Blackhole a socket and verify the heartbeat frees the old controller, then
   restore connectivity. Pending reads from before recovery must not replay.
10. Change owner generation, switch profiles, lock/logout and restore via
   Back/Forward while admission, a retry or browser permission is pending.
   Old callbacks and fallback clicks must not touch the successor's clipboard.
11. Simulate disconnect, requester exit, unsupported UTF8 targets, large INCR,
   overflow and bridge restart. Failure must leave an empty/failed conversion,
   never replay a previously successful value.

The development environment could not run Docker and Chromium was blocked by
existing launch permissions. These real interactions are not claimed as passed.
Python mocks, Rust protocol tests and React/jsdom cover logic and lifecycle; the
complete transport still needs the checks above.
