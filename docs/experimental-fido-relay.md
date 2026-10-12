# Experimental opaque FIDO report plumbing

Status: automatically prepared, session-gated launcher, renewable generation control and opaque report adapters, validated with native/HTTP/WebSocket simulations. This is not a verified Chromium USB feature; real-device/browser interoperability remains unverified. CLI/Desktop FIDO USB defaults on but discovery/open require a live Origin-approved Native pairing. Existing software authentication and native hybrid/BLE flow remain the defaults.

## Connected path and ownership

The implemented adapter path is:

```text
owner-authorized fresh SOCK_SEQPACKET endpoint
  <-> session-gated browser hook generation controlled by private supervisor IPC
  <-> bounded native packet adapter
  <-> existing owner-bound native helper session
  <-> authenticated /api/helper/fido HTTP handlers
  <-> outer-page FidoRelay adapter
  <-> existing locally paired helper WebSocket
  <-> explicitly attached local opaque endpoint
```

`src/fido-relay/` is a library crate, not a standalone executable. The backend
and helper both depend on this one package; the native hook source-includes only
its MIT-licensed std+libc control codec. Keeping the Cargo package boundary lets
all consumers share the same protocol without copying it. The crate provides immutable
64-byte reports, canonical base64 wire types, monotonic sequence numbers, bounded
report endpoints, and Linux anonymous packet-socket adaptation. It does not
implement a parallel authorization system, CTAP, RP selection, keys, credential
storage, or signing.

The supervisor automatically prepares the verified packaged native Chromium ELF/hook path. No separate enable flag is required; explicit `AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY=0` is an emergency opt-out. It creates private control channels, not a startup report device. Only an authenticated open for a live native helper session can provision a fresh report endpoint. Prepare and Activate acknowledgements are followed by owner/token/mode revalidation. `attach_native` remains the separately supplied-endpoint adapter used in integration tests. See [private control protocol](fido-control-protocol.md) and [launcher contract](fido-launcher-design.md).

The helper supports the local Rust API `Handle::attach_experimental_fido(session_id, endpoint)` for supplied endpoints. Its physical adapter defaults on; `--disable-usb` or the Desktop USB checkbox can opt out. After exact-Origin approval and live pairing, one matching FIDO interface opens automatically; multiple candidates require stable explicit selection. Startup alone never discovers or opens USB devices without that live approved pairing. See [physical adapter scope and fake-only validation](helper-usb-fido.md) for the strict descriptor profile, private I/O child, cancellation, and platform limits.

Each helper attachment generates a fresh opaque `relay_id`. Its `fido_available` message also carries the exact paired `helper_connection_id`. The page binds this advertisement to its current WebSocket attempt and starts only if backend status independently advertises an actual native endpoint or launcher control readiness and Chromium's existing native mode is confirmed. Launcher readiness alone never creates a helper advertisement. There is no “USB connected” claim based on these transport capabilities.

## Protocol and bounds

All wire messages use version 1 and one exact relay ID:

- `fido_available`: emitted only after a supplied local attachment; includes relay ID, paired connection ID and bounded remaining lifetime.
- `fido_open`: echoes the helper's fresh relay ID and shortens, never extends, its remaining lifetime.
- `fido_ready`: confirms the helper accepted that exact open.
- `fido_report`: one direction-specific sequence number and exactly 64 canonical-standard-base64 bytes.
- `fido_renew` / `fido_renewed`: strictly increasing lease sequence, same relay and endpoint, and a bounded grant capped at current pairing authorization.
- `fido_close`: ends only that matching relay.

The backend reuses the existing native session ID, cookies, CSRF token, authorization epoch, mode generation and lease:

- POST `/api/helper/fido/open`: binds the helper relay/connection IDs to a supplied or freshly prepared/activated native endpoint.
- POST `/api/helper/fido/renew`: revalidates the original owner/session/mode and exact relay binding before and after a matching native renewal acknowledgement.
- POST `/api/helper/fido/exchange`: revalidates ownership and all bindings on every exchange; accepts at most eight reports and drains at most eight. It also has a strictly increasing exchange sequence, separate from the two report sequences.
- POST `/api/helper/fido/cancel`: releases only the exact owner and relay binding.

Bodies are limited to 4096 bytes. Individual helper FIDO wire frames are limited to 2048 bytes. Report endpoints queue at most 258 reports per direction: two [maximum-size CTAPHID messages](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#message-and-packet-structure) (129 reports each), bounded to 16,512 raw report bytes per queue. Saturation terminates the relay instead of dropping a report and continuing. Backend exchange calls are limited to 100 per second; the page normally polls serially about every 20 ms. There are no simultaneous exchange requests, uncertain-exchange retries, or report replay on reconnect.

Each grant lasts at most 30 seconds, bounded further by existing native/local authorization. An unopened helper offer is renewed under the same live Native/pairing gates while waiting for genuine browser-monitor readiness, without forwarding reports or activating a native device. Its helper renewal counter continues across open; the fresh native generation has an independent monotonic renewal counter. The page renews a healthy authorized attachment halfway through its current grant, first obtaining the helper acknowledgement and subtracting observed transit time, then requesting the backend/native acknowledgement. Renewal preserves the endpoint, device generation and report sequences. An unconfirmed renewal never extends the old deadline. Backend expiry is independently checked every 50 ms and bound to a unique attachment identity, so an abandoned page cannot keep an endpoint alive. Helper expiry and ownership are checked before forwarding. Cancel, authorization loss, mode exit, helper token refresh, socket disconnect, page teardown and endpoint drop release the relevant transport. Re-pairing or reconnecting needs a fresh attachment and relay ID. Already transmitted bytes cannot be recalled.

The Linux packet adapter uses only anonymous `AF_UNIX/SOCK_SEQPACKET` pairs. Each packet is one exact 64-byte report; malformed packet lengths fail closed. The packaged userspace hidraw hook converts Chromium's 65-byte output convention (report ID zero plus payload) to these 64-byte packets. No kernel HID/UHID/USB device, host mount, ptrace setting, or sandbox change is introduced.

## Verification and reproducible commands

Using the repository's existing Rust toolchain/cache:

```sh
cargo test --offline --manifest-path src/fido-relay/Cargo.toml
cargo test --offline relay::fido_relay::tests
cargo test --offline --manifest-path helper/Cargo.toml --features desktop
cd web && pnpm test && pnpm run build
```

The backend cross-adapter regression `packet_backend_http_helper_websocket_complete_adapter_path` executes an actual anonymous packet socket, actual backend HTTP handlers through the router, and an actual loopback helper WebSocket. A Rust driver models the outer-page forwarding. It does not execute the React/TypeScript adapter in a browser; frontend tests separately execute that adapter and its component lifecycle.

An additional opt-in ignored test runs the packaged LD_PRELOAD hidraw hook as a C subprocess. Build the source-only `native-hid-hook` first, then run from this repository:

```sh
AUTH_BROWSER_TEST_HID_PRELOAD=/absolute/path/webauthn-browser/native-hid-hook/target/debug/libuserland_hid_hook.so \
  cargo test --offline preload_backend_http_helper_websocket_complete_adapter_path -- --ignored --nocapture
```

Its disposable C driver opens the synthetic hidraw node, writes a 65-byte report, receives a 64-byte reply, and verifies the exact bytes after the full native → backend HTTP → helper WebSocket → explicitly attached endpoint round trip. The fixture bytes are opaque test markers, not authentication success. The driver uses a child-only inherited FD at 198; it does not alter the parent's environment or install the preload globally.

The self-contained `tests/ctap2_fixture/` disposable CTAPHID/CTAP2 fixture produces ephemeral signed responses for synthetic-RP acceptance tests. Its independent signing tests are separate evidence; this report-adapter round trip uses opaque markers and does not claim to have exercised signed CTAP responses through the whole page/relay path.

## Outstanding acceptance work

The [launcher integration decision and minimum production contract](fido-launcher-design.md) traces the pinned browser-process HID path and explains why adding inherited FDs alone is insufficient. It separates implemented source control/generation ownership from the remaining real-browser and descendant-process acceptance observations.

- Start the ordinary packaged container/helper in a compatible environment, select Native and approve the exact Origin. Verify that the initial browser received its intended control capability. No separate USB activation flag is required, and enabling a report session does not silently restart an existing browser.
- Execute the real outer-page adapter and unmodified Chromium together, verify genuine HID discovery/parser acceptance, then CTAPHID create/get with a disposable authenticator. A physical USB key is not required for that disposable acceptance fixture.
- The previously attempted Chromium 154 launch fails at its unchanged singleton socket operation with EPERM; real libudev monitoring also returns EPERM. This work does not repeat or bypass either blocked operation.
- The hook's valid-pointer, fork-handler ordering and process-inheritance limitations still apply. Report transport does not remove them.
- Released Linux/Windows helpers include the physical adapter and renewals. Any later helper/shared-source change requires rebuilding the four executables and refreshing ignored `downloads/builds.json` hashes before packaging; consult the current [test manifest](../TESTING.md) and release-local download manifest rather than assuming an older binary matches edited source. No macOS executable or device interoperability is implied by a source check.

The disposable fixture can be checked without a browser:

```sh
python3 tests/ctap2_fixture/tests/hook_roundtrip.py
```

`AUTH_BROWSER_TEST_HID_PRELOAD` may explicitly select an already-built normal
release library. `tests/ctap2_fixture/future_browser_acceptance.py` is the separate
normal-sandbox browser acceptance runner; its default is no-launch. Running it
requires an appropriate authorized environment and does not change host security.
