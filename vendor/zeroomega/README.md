# Image-owned Proxy SwitchyOmega 3 (ZeroOmega)

Pinned upstream: [ZeroOmega v3.5.2](https://github.com/zero-peak/ZeroOmega/releases/tag/v3.5.2).
This is the Manifest V3 successor; the original SwitchyOmega is unmaintained and
Manifest V2 is unsupported by current Chromium.

`release.json` pins the official Chromium ZIP and corresponding source ZIP by
SHA-256. The release's published checksum matches the Chromium ZIP. Its public
manifest key was extracted from the official CRX, whose CRX3 RSA/SHA-256 signature
was verified; its derived ID matches the [official Store listing](https://chromewebstore.google.com/detail/proxy-switchyomega-3-zero/pfnededegaaopdmhkdmcofjmoldfiped).
The official ZIP omits the key, so the installer adds only this public key to
`manifest.json`. No private key, credential, proxy rule or user option is supplied.

Build-time installer: `runtime/install_zeroomega.py`. It prefers the ignored
`downloads/zeroomega` cache; a Git-only checkout downloads only the pinned official
URLs during image build and verifies their hashes. A corrupt local cache fails
closed. No update/download occurs at browser startup. Installed assets are
root-owned, read-only under `/opt/webauthn-browser/extensions/zeroomega`; the engine
remains under its original image path, and user-installed extensions are not
excluded. The stable official extension ID keeps its user configuration in the
existing Chromium profile across image recreation. Existing configurations are
not reset; fresh upstream configuration uses the system profile, with no supplied
proxy server. Selecting/configuring proxies remains a user action.

GPL-3.0 license and authors are preserved here and in the installed package.
The image additionally contains the exact corresponding source ZIP, release lock,
COPYING and AUTHORS under `/opt/webauthn-browser/licenses/zeroomega`. The source
archive includes upstream build scripts/instructions. Both archives are retained
in the local ignored downloads tree for a future authorized source bundle.

Verified: archive hashes, signed CRX identity, real ZIP installation, readonly
modes, source/notices retention, image loader coexistence and failure-path tests.
Actual Chromium launch/extension configuration persistence through a container
upgrade still requires browser acceptance; do not substitute these tests for it.
