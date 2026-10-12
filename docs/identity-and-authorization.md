# Model identity, website fields and approval

## One software authenticator, many website credentials

A key created in Settings is a software-authenticator configuration. Provider is
an editable local label; AAGUID identifies the model. Every successful website
registration creates an independent P-256 credential key pair, even within one
software authenticator. Its ID, private key, RP, counter and registration identity
persist. Later sign-in signs a fresh challenge with that original credential key;
it does not replace the key or its registration metadata.

`self` means packed self attestation: the new credential key signs its own
registration attestation. It includes no X.509 certificate or `x5c` chain and
proves possession of the credential private key only.

`basic` means packed certificate attestation: an independent attestation key and
X.509 certificate are generated or imported when creating the authenticator.
Registration uses that attestation key and returns `x5c`; subsequent sign-in still
uses the original website credential key. A locally generated self-signed
certificate is not packed self attestation and does not establish trusted vendor
provenance. Import validity, valid signatures and website trust are separate
judgments; websites apply their own roots and policies.

## Configurable fields

| Field | When configurable | What the website receives |
| --- | --- | --- |
| Provider | At creation and later | Local UI label only; no ProviderName protocol field. A site may map AAGUID to its own brand metadata. |
| AAGUID | Own 32-digit hex value or UUID at creation; then fixed | Configured authenticatorData AAGUID in every new registration, including none. All-zero omits a model identifier. |
| Authenticator type | Device or USB at creation; then fixed | platform/internal or cross-platform/usb hints, not physical USB hardware. |
| Attestation mode | none, self or basic at creation; then fixed | Actual fmt/attStmt also depends on the site's request. Local settings do not force a site to accept attestation. |
| Discoverable-credential capability | At creation; then fixed | Combined with residentKey requirements. Unsupported required capability fails. |
| Display nickname | Editable | Local management/approval label; no change to registered identity. |
| Enabled state | Editable | Candidate availability; no change to stored credentials. |
| Confirmation timeout | Editable, 1–120 seconds | Local wait capped by a shorter site timeout; not an identity field. |
| RP, Origin, challenge, user data | Bound to the real website request | Cannot be arbitrarily overridden without losing request/account binding. |
| UP and UV | Derived from real confirmation/password actions | No manual success flags. UV discouraged skips password verification and returns UV=false. |
| Credential ID, public key, signature, counter | Generated or advanced by the engine | No arbitrary-value overrides. Signatures use real private keys; counter overflow fails. |
| Algorithms, backup flags, extensions | Limited by implementation | ES256 only; no fabricated synchronization, hardware protection or unsupported extensions. |

AAGUID accepts exactly 32 hexadecimal characters or an 8-4-4-4-12 UUID,
case-insensitively. Leading/trailing Unicode whitespace is removed. Braces, URNs,
misplaced hyphens, nonhex characters and trailing garbage are rejected. Parsing
must produce exactly 16 bytes; storage and APIs use lowercase hyphenated UUIDs.
All-zero is a valid explicit privacy choice, not a vendor-identity check. Use your
own model UUID rather than borrowing a known vendor ID; no impersonation presets
are offered.

The backend PATCH API also rejects edits to fixed identity fields. Create another
authenticator for a different identity; doing so does not rewrite existing keys.
Changing Provider invalidates pending approvals to avoid approving under a stale
label, but does not change certificate subjects/DER, protocol identity or stored
registration snapshots. Older storage receives defaults for missing new fields
while retaining IDs, keys, RPs, counters and registration information.

## Certificate creation, import and lifetime

Basic mode supports locally generated identities or certificates/keys you are
entitled to use:

- Local generation creates an independent P-256 attestation key and self-signed
  X.509v3 leaf certificate. Configure country, organization, Common Name and
  1–3650 days of validity. OU is fixed to `Authenticator Attestation`, CA=false,
  key usage is digital signature, and the certificate binds the model AAGUID.
  Validity starts five minutes early to tolerate clock skew.
- Import accepts 1–5 PEM `CERTIFICATE` blocks, leaf first, followed by supplied
  intermediates/root. Each DER certificate is at most 16 KiB; total certificate
  PEM input is at most 120 KiB.
- The key must be one unencrypted PEM `PRIVATE KEY` containing P-256 PKCS#8,
  at most 8 KiB. Encrypted keys, SEC1 `EC PRIVATE KEY`, RSA/Ed25519 attestation
  keys and PKCS#12 are unsupported.
- The leaf must match the key and packed subject/CA=false requirements, include
  digital-signature usage and exclude certificate/CRL signing. An AAGUID
  extension, if present, must be noncritical and match the model. Duplicate or
  unsupported critical extensions are rejected.
- Supplied certificates are checked for issuer, signature, CA and path constraints.
  The final root may be omitted. This validates structure and key consistency,
  not public PKI/FIDO trust; it performs no online revocation lookup.

Certificate and attestation key remain fixed with the software authenticator.
Restart and ordinary configuration saves do not regenerate them. There is no
automatic renewal or in-place replacement. New imports and new basic registrations
require a currently valid chain. Certificate expiry does not expire existing
website credential keys or prevent their assertions; websites still apply their
own revocation, validity and trust rules.

### Older noncanonical DER certificates

An earlier generator explicitly encoded the default `BasicConstraints.cA=false`
as BOOLEAN FALSE. This matches the reported Yubico-demo error
`ParseError { kind: EncodedDefault, location: ["BasicConstraints::ca"] }`, also
reproduced with an independent strict local parser. Newly generated non-CA
extensions use an empty SEQUENCE (`30 00`), omitting the default; country uses
PrintableString. New imports and basic registrations check canonical DER.

Existing noncanonical certificates can still load from storage and full backups.
Their DER, attestation key, website keys and registration snapshots are preserved,
without silent re-signing, repair or replacement. Settings warns that the identity
cannot perform new certificate-attestation registrations. Create a new certificate
identity and re-register where needed, retaining the old authenticator for existing
credentials. Assertions do not depend on the attestation certificate. Requests
for none, omitted attestation or downgraded enterprise can still register with
the configured AAGUID without sending a certificate.

Settings exposes certificate summaries such as subject, validity, SHA-256
fingerprint and chain length, never the private key. Backups do include that key.
Import sends it from your browser to your deployed WebAuthn Browser service for
storage. Use only a trusted service and protected connection; do not import
production vendor private keys.

## Requested, configured and returned identity

A site's `attestation` is a conveyance preference, the local mode describes
available attestation, and a credential's registration snapshot records what was
actually returned. Configuration edits cannot rewrite an existing registration.
Omitted attestation is equivalent to `none`; unknown preferences are rejected.

| Website request | Local mode | Actual attestation | AAGUID |
| --- | --- | --- | --- |
| none or omitted | none / self / basic | `fmt=none`, empty `attStmt`, no signature/certificate | Configured UUID |
| direct / indirect | none | `fmt=none`, empty `attStmt`, no signature/certificate | Configured UUID |
| direct / indirect | self | packed, credential-key signature, no `x5c` | Configured UUID |
| direct / indirect | basic | packed, independent attestation-key signature and `x5c` | Configured UUID |
| enterprise | none / self / basic | Unsupported enterprise attestation falls back to none | Configured UUID |

Both device and USB software types use these rules. WebAuthn Level 3 distinguishes
no attestation from no model identifier: the none branch strips attestation rather
than automatically zeroing AAGUID. The previous implementation coupled those
choices; the correction affects new registrations only. Direct/Indirect or a
certificate is not needed just to return AAGUID. All-zero remains the default and
explicit no-model choice. A unique custom UUID can correlate registrations across
sites. All-zero does not hide a basic certificate sent for direct/indirect, so it
does not make that mode completely anonymous.

A read-only review of official webauthn.io source on 2026-10-11 found that Provider
Name comes from the site's own AAGUID-to-name mapping, without requiring Direct or
a certificate. None registrations can therefore display an AAGUID/name. An unknown
custom UUID may still have no displayed name, and the local Provider label cannot
modify that mapping. The reviewed defaults were Attestation None, Discoverable
Credential Preferred and User Verification Preferred; defaults do not establish
what a historical request actually contained. Choose Direct/Indirect for a future
self/basic test. No third-party registration was performed as part of that review.
This project's registration counter starts at zero and increments on successful
assertion signing independently of attestation mode.

Persisted/exported/site-stored `registrationAaguid`, attestation mode and identity
snapshots remain unchanged. A credential originally registered with all-zero keeps
its key and can sign in; storing a different AAGUID at the site requires a new
registration. If its authenticator was created with all-zero, a new authenticator
is needed for another fixed model UUID.

Provider is a local label, not a website protocol field or certificate vendor
identity. AAGUID is a model identifier, not a serial number, credential ID or trusted
vendor assertion. Supplying a vendor name/UUID does not obtain that vendor's trust.

## Separate approval steps

1. Select the key and account for this request. Selection does not sign.
2. If UV is required/preferred and the key has no password, set a local password.
3. For required/preferred UV, actually verify that password. Initial setup does
   not replace this independent verification step.
4. Separately allow or reject the touch/presence confirmation. Password submission
   is not presence confirmation.
5. Sign, persist and answer only while every step, authorization and deadline
   remains valid.

With UV discouraged, selection goes directly to presence confirmation without
password setup/verification. All supported requests require UP. Password approval
authorizes one exact request/key/account/configuration operation, not a reusable
verified session. Cancel, timeout, deletion, configuration change, disconnect or
session revocation invalidates old approval. Neither a prior touch nor an old
submission can be replayed. SSE carries current steps/candidates, never passwords,
hashes, challenges, private keys or signatures.

## References

- [RFC 5280 Appendix B: omit DER defaults](https://www.rfc-editor.org/rfc/rfc5280#appendix-B)
- [rcgen 0.13.2 certificate encoding](https://github.com/rustls/rcgen/blob/v0.13.2/rcgen/src/certificate.rs)
- [W3C credential creation and conveyance preference](https://www.w3.org/TR/webauthn-3/#sctn-createCredential)
- [W3C Level 3 and section 18.1.1 change history](https://www.w3.org/TR/webauthn-3/)
- [W3C attestation types](https://www.w3.org/TR/webauthn-3/#sctn-attestation-types)
- [webauthn.io default settings](https://github.com/duo-labs/webauthn.io/blob/master/_app/homepage/templates/homepage/sections/webauthn_form.html#L425-L435)
- [webauthn.io Provider mapping](https://github.com/duo-labs/webauthn.io/blob/master/_app/homepage/services/metadata.py)
- [webauthn.io AAGUID storage](https://github.com/duo-labs/webauthn.io/blob/master/_app/homepage/services/credential.py)
- [webauthn.io Provider/AAGUID display](https://github.com/duo-labs/webauthn.io/blob/master/_app/homepage/templates/homepage/profile.html)
- [W3C packed attestation](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
- [W3C authenticator data](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
- [Chromium WebAuthenticationProxy](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy)

These references explain protocol boundaries. Project policies above describe
this code; they do not require all authenticators or browsers to use identical
privacy, timeout or interaction policies.
