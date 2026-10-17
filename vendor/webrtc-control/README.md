# Image-owned WebRTC Control

The image installs the official **WebRTC Control 0.3.5** (Manifest V3), offered
by **Grephy**, with stable Chrome extension ID
`fjkmabmdepjfammlpliljpnbhleegehm`.

Primary identity sources:

- [Chrome Web Store listing](https://chromewebstore.google.com/detail/webrtc-control/fjkmabmdepjfammlpliljpnbhleegehm)
- [Publisher homepage](https://mybrowseraddon.com/webrtc-control.html)

`release.json` pins the exact versioned Google Web Store CRX blob and SHA-256.
The blob URL was obtained from Google's official extension update endpoint for
that ID. The build-time installer verifies the complete downloaded bytes, the
publisher's CRX3 RSA/SHA-256 signature, the signed extension ID and the public-key
identity before extraction. It also requires the expected name, version, MV3
manifest and service worker. It fails closed if the pinned blob disappears or
changes; it does not silently fetch the latest release or use a mirror.

The original archive omits a manifest key. The installer adds the verified public
key so unpacked loading preserves the official ID across image rebuilds. It
omits the reserved `_metadata` directory from unpacked assets, retaining the
original CRX and release lock under
`/opt/webauthn-browser/licenses/webrtc-control`. No extension implementation is
replaced or rewritten. Code is root-owned, read-only image content under
`/opt/webauthn-browser/extensions/webrtc-control`.

Docker fetches the official package during build. No local `downloads` directory,
ignored artifact or runtime network fetch is needed. Source distributions contain
only the installer, tests and provenance metadata, not the downloaded package.
The Chrome artifact does not declare a redistribution license; this project does
not assign its own license or the license of another browser's package to it.
Third-party terms remain applicable. Review the publisher's terms before
redistributing a built image containing the extension.

The same extension path is loaded for every browser profile alongside the
WebAuthn engine, ZeroOmega and user-installed extensions. Existing Chromium
profiles and extension storage are not edited or cleared. Options remain
per-profile under the stable extension ID, including across image updates.
Upstream defaults apply only to fresh extension storage: protection is enabled,
`webRTCIPHandlingPolicy` is `disable_non_proxied_udp`, script injection is enabled,
and the optional media-device/additional-object switches are off. This can affect
WebRTC calls or peer connections; users can toggle the extension or change its
options. No application-wide WebRTC policy or replacement privacy code is added.

Validation includes a real official download/signature/install, signed fixture
failure tests, read-only output and profile-preservation contracts. Actual
Chromium startup, toolbar/options behavior, multiple profiles and configuration
persistence across container recreation still require deployment acceptance.
