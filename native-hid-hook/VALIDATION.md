# Native hook validation and archived checkpoints

## Current contract and evidence limits

Ordinary packaged startup prepares the normal Linux x86_64 hook/control channel.
Only an authenticated, approved Native session may activate an opaque FIDO report
endpoint. Genuine monitor prerequisites, generation ownership, lease deadlines,
revocation and standard-fork cleanup remain required; simulated readiness is never
accepted in production. No kernel device, generic USB forwarding or security-policy
bypass is provided.

See the repository's [current test manifest](../TESTING.md), [hook README](README.md)
and [launcher contract](../docs/fido-launcher-design.md) for current commands and
limits. Real Chromium discovery/session restoration, physical USB interoperability,
and raw-fork descendant sanitation are not established by the fixtures below.

All hashes and counts below belong to their stated **archived build checkpoints**,
not necessarily the current source or rebuilt artifact. Build paths, toolchains
and even source-line changes can change native debug hashes. Use a fresh hash of
the actual tested library when reporting a new build.

## Archived libudev PLT correction (2026-10-12, after v31)

- Baseline normal debug `47e14f1b0332a17b276c9d18c703176bd978e7f1011865219ab26c89f2751871`
  was tested with a mock genuine `enable_receiving` that calls `filter_update`
  through a verified PLT relocation, matching installed libudev 1.7.10. It hung
  for the bounded 2.00-second observation: initial UNAVAILABLE, no completed
  enable and no READY. The test child was terminated/reaped.
- Fixed normal debug: `2e672116ebe0682d34469bc99a6e19a11656794517918a460be4ae4149a894eb`.
  Fixed normal release: `8a7e289c0d66d775e602846af86cfe16f2b107a44078629cf74910c389ffd2fe`.
  The identical nested mock now completes enable/READY. Only state-neutral
  filter_update passthrough locks were removed; outer enable ownership locks,
  reference pins, child rejection, errno and genuine readiness checks remain.
- 11 normal monitor mock groups pass on both artifacts, including nested EIO with
  no false READY, recovery, direct-update errno, concurrent ref/unref and fork.
  Production prerequisite tests pass on both; 17 simulation groups, 6 codec tests
  and strict Clippy in both modes, 11 fork/owner and 2 legacy-generation tests pass.
  Signed CTAP/OpenSSL and supplied-endpoint HTTP/helper-WebSocket relay round trips
  pass on debug and release. These are synthetic fixtures, not real hardware.
- Independent source review found no remaining blocker in the changed locking
  path. Attribution is version-specific: upstream
  [systemd v252](https://raw.githubusercontent.com/systemd/systemd/v252/src/libudev/libudev-monitor.c)
  uses an internal enable path. This proves a compatibility defect, not the cause
  of the user's Debian Bookworm USB wait without its runtime/library evidence.
  No genuine netlink, actual Chromium or physical-device probe was performed.


## Archived restored-tree audit (2026-10-12, after v30)

- Normal debug library SHA-256: `47e14f1b0332a17b276c9d18c703176bd978e7f1011865219ab26c89f2751871`.
- 10 normal monitor-adapter mock result groups passed, now including unfiltered
  enumeration and exact sealed descriptor/ioctl/revoke checks. Native Rust code
  is unchanged; build-path differences change artifact hashes.
- Packaged startup now prepares the controller by default; only an approved
  Native session can activate a report endpoint. Explicit `0` remains an opt-out.
- Waiting helper offers renew without report I/O, while genuine browser monitor
  readiness is still required before opening. Static/simulation checks do not
  prove actual Chromium or physical USB operation.

### Pinned Chromium linkage audit

At Chromium commit `73c14f6228d7cd537c855007e8f88678969cc0eb`,
[udev_loader.cc](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/device/udev_linux/udev_loader.cc)
constructs Udev1Loader, whose
[implementation](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/device/udev_linux/udev1_loader.cc)
calls `::udev_*` directly. Its
[BUILD.gn](https://raw.githubusercontent.com/chromium/chromium/73c14f6228d7cd537c855007e8f88678969cc0eb/device/udev_linux/BUILD.gn)
links libudev; there is no private `dlsym(handle, ...)` bypass in this path.
The inspected Chromium ELF embeds version `154.0.8037.57` and that exact commit;
SHA-256 `4dc9f9f9b20e9bd95bf201f43d2d643f48938f36a70ddcb6fce3dd611a178180`.
`readelf -d` shows `DT_NEEDED libudev.so.1`; `readelf -rW` shows 31
`R_X86_64_JUMP_SLOT` udev imports at `LIBUDEV_183`. This verifies the intended
static interposition route, not actual loader execution or device discovery.
No browser or genuine monitor was launched for this audit.

## Earlier v30 checkpoint

Validated from this self-contained repository tree, 2026-10-12. These are static,
mock/native ABI and anonymous IPC tests. No Chromium launch, genuine netlink retry,
physical USB access, sudo, security-policy change or Docker run occurred.

### Archived v30 artifacts

- Normal debug library SHA-256:
  `fc7159fd573d4bd73f3494f81c001fe968845b3a0da6018ab82b299b59a210e6`
- Normal optimized release library SHA-256:
  `f5520482411c3e8e0b51330320dd26082885c3bf4d939a25f51cfc32a1e6ab79`
- Both are ignored build outputs, not committed artifacts. Different absolute
  build paths/toolchains can change hashes. The earlier separate experiment's
  normal debug hash `2ea6cd925bf0ff1c132e78e9e641ddbea60820034ab7a8c434d1047d16a66d69`
  was built before source relocation; it is not the packaged-tree binary.

### Archived v30 checks

- 17 compile-only simulation lifecycle result groups, covering native control
  scenarios, bounded event overflow and 128 forks racing 64 SCM_RIGHTS deliveries.
- 9 normal-build monitor-adapter mock result groups: authoritative original API
  success/errors, genuine-event forwarding/rearm, initial unavailable/later ready,
  add/remove/report I/O, last-monitor revoke/recovery, filters, cookie-pinned raw
  FD reuse/replacement cleanup, bounded failure draining and continued unrelated
  event forwarding. Repeated against the optimized release library.
- 6 shared wire tests in each build mode; strict Clippy for normal and simulation.
- 11 existing fork/owner isolation cases and 2 legacy endpoint-reuse cases. Legacy
  mode intentionally does not retract already queued packets; control generations
  separately test terminal queued-packet denial.
- Production startup test: no compiled simulation constructor, environment cannot
  enable it, no READY before genuine monitor prerequisites; repeated for release.
- 4 source/Docker/Compose layout tests: relative codec source, required source/licenses,
  default simulation disabled, then-current Compose with environment opt-in defaulting off
  (superseded by the default-ready controller contract above),
  x86_64-only normal build, read-only runtime library
  path and ignored native build outputs. This is not a Docker build/run claim.
- Explicit preload → backend HTTP → paired helper WebSocket → supplied opaque
  endpoint round-trip, against both debug and release libraries. Rust models the
  outer-page forwarding; real TypeScript adapter tests are a separate layer.
- `tests/ctap2_fixture/tests/hook_roundtrip.py` against debug and release libraries:
  CTAPHID INIT/getInfo/makeCredential/getAssertion, independent OpenSSL validation
  of self-attestation and two bound monotonic assertions, fragmented CANCEL.
  This uses ephemeral test keys and is not browser discovery or hardware evidence.

Reproduce with `tests/test_control_hotplug.sh`, `tests/run_fork_isolation.py`,
`tests/run_generation_reset.py` and the documented root integration commands.
To select the optimized normal library for monitor/control tests, set
`AUTH_BROWSER_TEST_HID_PRELOAD` on that explicit Python command. Production
launcher/gateway reject the simulation bit; the mock libudev library is built only
by tests and is never copied into the runtime image.

Real Chromium descriptor parsing/discovery, the complete real outer-page WebAuthn
flow, physical authenticator interoperability and descendant raw-fork sanitization
remain unverified. See the parent launcher design for the remaining acceptance
checks and unsupported ABI/process cases.
