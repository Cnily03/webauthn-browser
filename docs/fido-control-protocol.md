# Private FIDO generation control

This is a session-gated Linux x86_64 userspace adapter with experimental validation. The control plane manages
opaque report capabilities; it does not parse CTAP, relying parties, credentials,
or signatures. Deterministic tests are not evidence that Chromium discovered a
device or completed WebAuthn.

## Authority and ownership

`runtime/fido_control.py` owns one anonymous `SOCK_SEQPACKET` control endpoint
per exact gateway/browser child epoch. Only the initial verified Chromium ELF
receives the preload and browser control endpoint. The gateway receives its own
control endpoint and no preload. Secondary singleton launchers receive neither.
The packaged supervisor prepares metadata/control automatically without a USB flag;
no endpoint or virtual device exists before an authorized Native Prepare/Activate.
An explicit `AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY=0` deployment override disables preparation; untrusted/missing packages
remain unavailable.

`src/relay/fido_launcher.rs` is a bounded, single-attachment actor. The authenticated
HTTP handler remains the authority: existing cookie/CSRF owner, helper session,
pairing token, native-mode generation and deadline are checked before Prepare,
before Activate and after its exact acknowledgement. A reservation can be
canceled before the endpoint becomes visible. Logout, token refresh, mode exit,
endpoint failure and disconnected controls terminate the matching attachment.
A late acknowledgement cannot attach to a replacement session.

Prepare passes one fresh report FD. Transient copies are closed after transfer.
The supervisor intentionally retains one **tracked revocation duplicate** while
an attachment is pending or active; it never reads or writes reports. Every
terminal path calls `shutdown(SHUT_RDWR)` and closes that duplicate. This is
necessary because dropping a transient SCM_RIGHTS sender copy alone cannot revoke
an already-delivered receiver copy. Independent browser/backend deadlines remain
mandatory even if a process or control channel stalls.

## Canonical wire format

Every message is exactly 96 bytes, big-endian, with no trailing bytes:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | `UFHC` |
| 4 | 1 | version 1 |
| 5 | 1 | opcode |
| 6 | 1 | flags |
| 7 | 1 | zero |
| 8 | 16 | nonzero gateway epoch |
| 24 | 16 | nonzero browser epoch |
| 40 | 16 | attachment identity |
| 56 | 8 | device generation |
| 64 | 8 | existing native mode generation |
| 72 | 8 | absolute `CLOCK_MONOTONIC` deadline in nanoseconds |
| 80 | 8 | renewal sequence |
| 88 | 8 | zero |

Opcodes: Hello 1, Ready 2, Prepare 3, Prepared 4, Activate 5, Active 6,
Revoke 7, Revoked 8, Unavailable 9, Renew 10, Renewed 11.

Hello/Ready/Unavailable have zero attachment/counter/deadline fields. Other
messages require nonzero identity, generation, mode and deadline. Initial
Prepare/Prepared/Activate/Active use renewal sequence zero. Renew/Renewed use the
next positive sequence. Revoke is terminal by full attachment identity, even if
its last confirmed lease differs from a concurrently acknowledged renewal.

Ready/Prepared/Active/Renewed require flag 1 (genuine monitor prerequisite).
Compile/test-only adapters additionally set bit 128, making 129. Production
supervisor and gateway reject bit 128; no environment variable enables their
simulation mode. Unavailable uses 0, or 128 for a test-only peer. Other opcodes
use zero flags. Every unknown opcode, noncanonical flag, reserved byte or
structural field combination is rejected.

Exactly one connected Unix packet socket is carried by SCM_RIGHTS on Prepare;
all other frames carry none. Unknown ancillary messages, extra/truncated rights,
wrong socket types, wrong packet size and malformed frames close **all received
FDs**. Socket operations are nonblocking, received descriptors are CLOEXEC, sends
suppress SIGPIPE, and queue saturation fails closed. Rust and Python implementations
are tested against the same layout.

## Repeated sessions and renewable grants

Each attachment gets a new socket pair, device generation and unique device path.
Revocation is terminal for old aliases, including queued old reports. A new helper
advertisement is required for another attachment; no failed transaction is retried
or moved across generations. Gateway/browser restarts get independent epochs.
Bounded generation/epoch tombstones reject stale resurrection.

Each lease grant is at most 30 seconds, using an absolute monotonic deadline.
Transit and acknowledgement time consume that grant. The outer page renews only
while the original paired connection and native-mode authorization remain live:

1. Send `fido_renew` with the next lease sequence to the exact helper relay.
2. Await its exact `fido_renewed`, capped at existing pairing authorization.
3. Subtract observed round-trip time, then POST authenticated `/api/helper/fido/renew`.
4. The backend revalidates ownership, requests native Renew, and publishes the
   new deadline only after exact Renewed and another authorization check.

An advertised but unopened helper offer may renew while Native/pair authorization
is live and genuine browser-monitor readiness is pending. This sends no report and
does not activate a browser device. Helper lease sequences remain monotonic across
open; native lease sequences independently start at 1 for each fresh native generation.
The page validates each leg against its own expected counter.

Report/exchange sequences are independent and never reset by renewal. The old
confirmed deadline remains in force while an ACK is pending. Expiry, ambiguity,
invalid/replayed renewal or disconnect closes the generation, with no automatic
reattachment. A healthy authorized session can renew beyond 30 seconds without
replacing its endpoint or replaying a report.

## Status and tests

`experimental_fido_launcher_ready` means only the private control prerequisite is
ready. `experimental_fido_available` means an actual endpoint is attached. The page
also requires a real helper `fido_available` advertisement and confirmed native
mode before opening. Neither flag is rendered as USB-connected or WebAuthn success.

Tests cover actual anonymous sockets and SCM_RIGHTS between simulated subprocesses,
native C ABI generation lifecycle, helper fake physical I/O, authenticated HTTP,
and the real TypeScript adapter in jsdom. These are separate test layers. No test
claim substitutes for an actual normal-sandbox Chromium/outer-page/CTAP acceptance
run; the earlier singleton and genuine-monitor EPERM observations remain intact.
