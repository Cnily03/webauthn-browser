# Key backup and restore

Settings → Virtual Keys provides export and restore. Version 1 JSON backups
contain software-key configuration, Argon2 hashes of each key's local verification
password, website credentials and **unencrypted private keys**. Basic attestation
also exports its independent attestation private key and complete certificate
chain. Keep backups on trusted devices; do not share them or upload them to
untrusted services. They exclude the Settings password, VNC password and browser
profile, and do not replace a full offline backup of `./.data`.

## Restore procedure

1. Select an unencrypted JSON file exported by this project, at most 2 MiB.
2. Validate it, then review the incoming/current key and credential counts and
   warnings. No data has been replaced yet.
3. Download and safely retain the pre-restore backup ("恢复前备份"). Starting a
   download does not prove it reached disk; confirm that it was actually saved.
4. Separately confirm replacement. Restore replaces **all** software keys and
   their credentials; current keys absent from the backup are removed rather
   than implicitly merged. A key's local verification password follows that key.
   The two access passwords and browser website data remain unchanged.

A preview lasts ten minutes and is bound to the current session, file contents
and current storage. Registration, signature-counter advances or configuration
changes invalidate it; preview again and download a new pre-restore backup.
Submission revalidates the complete file, with no partial imports. Canceling,
closing the preview or choosing another file does not restore any keys.

## Counters, compatibility and failures

If an imported credential matches a local credential ID, private key, RP, user
identity and discoverability, restore retains the higher signature counter. A
same-ID credential with different identity/key material rejects the entire backup.
A new machine cannot know a higher counter already seen by a website, so restoring
an old backup may still cause rejection or a risk warning. Use the site's other
recovery method and re-register a passkey when needed.

Missing older model fields receive compatibility defaults. Legacy automatic-UP or
simulated-UV flags do not grant approval. Encrypted archives, directory archives,
non-ES256 credentials and custom fields are unsupported. Invalid versions,
duplicate IDs, malformed keys, invalid RP/user/counter values, oversized files and
unsupported password hashes are rejected.

Version 1 uses optional fields for certificate identities and requested/actual
registration results. Older none/self backups remain compatible; do not assume
new basic backups work in old releases. Identity and certificate chains are
revalidated. Matching local credentials retain their original registration
metadata, so restore cannot rewrite historical attestation.

Restore can retain expired certificate identities whose structure and key match
remain valid. Expiry must not prevent recovering or using existing website
credentials. Expired certificates cannot be used for new basic registrations;
restoring them does not extend their validity. Importing a certificate creates
neither vendor trust nor hardware protection.

Persistence uses a single atomic file replacement after full validation, and
in-flight authentication requests are revoked during restore. Ordinary pre-write
failures preserve the old data. If storage synchronization fails after replacement,
power-loss durability is uncertain; keep the pre-restore backup and investigate
storage before retrying. If the persisted file cannot be reread after a failure,
the service blocks further writes and authentication completion. Repair storage
and restart successfully; refreshing the page cannot bypass this protection.
Never run two containers against the same data directory.

## Displayed passkey metadata

The backup format remains version 1. Optional `userName` and `userDisplayName`
preserve names supplied by the website at registration. `registeredAt` is the
service's credential-creation timestamp in nonnegative Unix milliseconds, bounded
by year 9999; it is not a website-signed time. Missing older values remain unknown
rather than being replaced with restore/upgrade time.

Matching credentials retain locally recorded names, registration time and identity
snapshots, together with the higher-counter rule. Ordinary Settings APIs expose
only type-checked public summaries, never private keys.
