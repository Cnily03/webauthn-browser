# Legacy credential fixture

This fixture contains a disposable, public test key generated with OpenSSL
`genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` and exported as unencrypted
PKCS8 DER. It is not an actual user's credential and must never secure an account.
The JSON uses the original project's CDP `WebAuthn.Credential` shape, standard
base64 fields, existing counter 41, legacy policy flags, and no new PIN field.
`legacy-public-key.der` is the matching DER SPKI public key for independent
signature verification. The store test reopens without resetting either access
hash, verifies ID/key/counter preservation, signs, increments to 42, saves, and
reopens again. This verifies format compatibility, not a live Chromium export.
