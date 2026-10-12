# Local navigation offers

The managed Chromium extension observes top-level navigation to an exact HTTP or
HTTPS host of `localhost` or `127.0.0.1`. A currently authenticated outer browser
can receive a toast reading “在本机浏览器打开 <URL>” (open this URL locally),
with Open (“打开”) and Cancel (“取消”) actions. Nothing opens automatically.
Clicking Open navigates the user's own browser to the observed URL. The
container does not fetch it, change the redirect, or proxy the request.

## Evidence and permissions

The observer uses official [`webNavigation`](https://developer.chrome.com/docs/extensions/reference/api/webNavigation)
transition metadata and new-target events. Committed links, forms, bookmarks and
explicit client/server redirects can offer a target. Directly typed local URLs,
omnibox-generated searches, reloads and history traversal do not. A public URL
that was typed and then explicitly redirects to a local target can qualify when
the observer retained evidence of that external navigation start.

For a link or script that reaches a closed local port, waiting for `onCommitted`
is insufficient. The read-only [`webRequest`](https://developer.chrome.com/docs/extensions/reference/api/webRequest)
`onBeforeRequest` observer accepts only `main_frame` requests whose destination
matches one of these four filters:

- `http://localhost/*`
- `https://localhost/*`
- `http://127.0.0.1/*`
- `https://127.0.0.1/*`

A nonopaque HTTP(S) initiator supplies source evidence. The request is correlated
with `webNavigation`'s full destination URL, retaining its query and fragment.
This can emit an offer before a connection is refused. New-window/tab evidence
from `onCreatedNavigationTarget` is also sufficient before a network failure.

The source manifest declares `webNavigation`, `webRequest`, and HTTP(S) source
host access (`http://*/*`, `https://*/*`). This broader host access is necessary
for Chromium to expose an arbitrary website's initiator, even though the listener
is restricted to local destinations. Pinned Chromium commit
`73c14f6228d7cd537c855007e8f88678969cc0eb` establishes both relevant checks:

- [`web_request_permissions.cc`, lines 133–145](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/extensions/browser/api/web_request/web_request_permissions.cc)
  exempts navigation requests from the extra initiator-host admission check.
- [`web_request_event_details.cc`, lines 280–287](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/extensions/browser/api/web_request/web_request_event_details.cc)
  separately redacts the initiator unless its host is permitted (or the initiator
  is opaque). Destination-only permission therefore does not solve arbitrary-site
  provenance.

For same-document changes, pinned
[`web_navigation_tab_observer.cc`, lines 62–66 and 244–271](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/chrome/browser/extensions/api/web_navigation/web_navigation_tab_observer.cc)
skips `onBeforeNavigate` and routes each completion to one history-state or
fragment event. The shared
[`DispatchOnCommitted` serializer](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/chrome/browser/extensions/api/web_navigation/web_navigation_api_helpers.cc)
includes document identity and the navigation handle's transition qualifiers.
No separate network request is required for those events.

The separate [managed browser lifecycle](browser-lifecycle.md) also uses `tabs`
and `tabGroups`; those grants are not needed to inspect navigation request bodies.
No `webRequestBlocking`, response/request headers, request bodies, cookies,
content scripts, debugger permission, or page-accessible messaging is used.
Missing, opaque or redacted initiators never count as source evidence.

## Race and lifetime rules

- Native-port negotiation creates a fresh navigation scope tied to the current
  mode generation. It works in both software and Native modes.
- Browser event timestamps and per-tab high-water marks reject delayed older
  callbacks. A request's timestamp cannot predate its navigation start.
- Each cross-API correlation is consumed once. Overlapping unfinished
  navigations to the same local target fail closed rather than applying an old
  script request's initiator to a newer manually typed request.
- Created-target, early request evidence and the matching commit are deduplicated.
  Another top-level navigation or closed target clears the offer.
- Pending URL state is bounded to 64 tabs and five seconds. URL-free per-tab
  announcement/high-water metadata persists until tab close or scope reset to
  suppress slow duplicate commits; excess concurrent tabs fail closed. The backend accepts
  URLs of at most 8,192 UTF-8 bytes and uses a 16-entry live-only notification
  channel. It rechecks scope, generation, authorization and monotonic expiry
  before serializing for each subscriber.
- The authenticated CSRF-protected request SSE stream sends the usual snapshot
  first, then separate `local_navigation` and `local_navigation_clear` events.
  URLs never enter approval snapshots, status polling, persistent storage,
  lifecycle history, event IDs or logs. New subscribers cannot replay offers.
- Offer IDs combine the public stream identity with a monotonically increasing
  counter. They disclose no private extension scope or URL.
- Delivery freshness and visible lifetime are separate: the backend only sends
  offers within five seconds of extension detection and silently drops expired
  pending URL data. It never sends a timed clear solely because this delivery
  window elapsed. Queued expired events still cannot become new offers.
- A fresh received offer gets five seconds of display time after its entrance
  transition finishes. Hover or keyboard focus
  pauses its remaining countdown for as long as necessary; clicking during the
  pause still opens that exact URL. Leaving hover/focus resumes the countdown.
  Explicit newer navigation, target-tab close, logout, stream loss, route change
  and mode-generation change still clear it. The extension retains only a
  URL-free active-tab marker after its five-second URL cache expires, enabling
  these later invalidations without retaining the target URL there.
- Already transmitted network bytes cannot be recalled; arbitrary network
  buffering is not a strict end-to-end wall-clock delivery guarantee. The UI
  display countdown does not weaken server-side queued-event freshness.

## Boundaries

This offers an ordinary GET navigation in the user's browser. It does not replay
a form's POST body, container cookies, credentials, or browser session. The URL is
preserved as supplied by Chromium's event, including its query and fragment;
Chromium may already have normalized it before issuing the event.

Top-level `history.pushState`/`replaceState` and fragment/location changes are
observed through `onHistoryStateUpdated` and `onReferenceFragmentUpdated`, using
the same transition exclusions. They create fresh notification generations, so
an earlier full-navigation offer cannot suppress them. Document IDs and event
timestamps suppress duplicates, stale-document callbacks and overlapping full
navigation races. Manually typed local/hash targets and history traversal remain
excluded. Failed same-tab redirects without trustworthy initiator or new-target evidence may produce no
offer. API ordering that cannot be correlated unambiguously is suppressed.
Browser/extension clock skew can also cause conservative freshness rejection.
A later script navigation from a page initially opened by typing is classified by
its own source evidence; the extension cannot infer the user's original intent.

`extension/local_navigation.js` is a packaged, fingerprinted asset loaded only by
the extension worker. The manifest version remains `1.0.29`; all executable
assets and permissions contribute to the image fingerprint. Existing-profile
recovery requests a bounded extension-only reload when the image stamp differs.
Static and VM tests cover packaging, observer wiring and that reload contract.
No running Chromium installation or permission prompt was accepted in this work.
Whether a particular existing unpacked-extension profile needs an additional
permission/reload action has not been observed in Chromium here.

## Reproduce without a browser or local server

```sh
node tests/extension_navigation_test.cjs
for test in tests/extension_*test.cjs; do node "$test"; done
python3 -m unittest discover -s tests -p 'extension_upgrade_test.py' -q
cargo test browser::
```

These exercise simulated extension callbacks and real authenticated backend SSE
handlers. They do not establish browser or device interoperability.
