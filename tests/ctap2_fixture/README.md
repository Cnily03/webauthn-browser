# Disposable CTAPHID / CTAP2 fixture

Status: **signed harness-level acceptance passed; real browser acceptance NOT RUN and remains blocked.**

This disposable test fixture is included under `tests/ctap2_fixture`. It creates genuine, disposable P-256 credential keys and CTAP2 signatures in memory. It is **not** a real USB device, production authenticator, user-presence mechanism, upstream-device relay, or packaged feature. No real account or credential may be used.

## Explicit fixture boundaries

- Only `localhost` and `ctap.fixture.test` RP IDs are accepted. The authenticator receives the CTAP `clientDataHash`, not browser origin or client JSON; origin/type/challenge verification belongs to the independent acceptance verifier.
- Presence is **simulated**, explicitly enabled by the test launcher. Default construction denies presence-requiring operations. UV and PIN are never claimed. An assertion requested with `up:false` correctly has no UP flag.
- The only cryptographic algorithm is ES256/P-256. Registration uses genuine packed self-attestation. Assertions bind `authenticatorData || clientDataHash`, with increasing counters and overflow rejection.
- At most 16 non-discoverable credentials and 8 CTAPHID channels exist. No credential, private key, user account, or approval is persisted. Python cleanup is best effort and does not promise memory zeroization. OpenSSL cross-check files contain only synthetic messages, public keys, and signatures.
- No resident keys, PIN/UV protocols, U2F, extensions, certificate attestation, getNextAssertion, credential management, hardware access, or remote RP traffic is implemented. Unsupported options/commands fail explicitly.

## Modules and transport

- `cborcodec.py`: strict canonical definite-length CBOR subset with 4096-byte, 512-item, and depth-8 bounds; rejects nonminimal, duplicate/unordered maps, invalid UTF-8, floats, tags, indefinite values and trailing data.
- `authenticator.py`: getInfo, makeCredential, getAssertion, in-memory keys and bounds.
- `hid.py`: real CTAPHID INIT, PING, CBOR, CANCEL, channel allocation, fragmentation, sequence/busy errors and partial-transaction timeout. INIT resynchronizes its channel. CANCEL clears a same-channel partial CBOR and responds to that canceled CBOR with KEEPALIVE_CANCEL, never acknowledges CANCEL itself. Cryptographic commands execute synchronously, so cancellation cannot interrupt a signature already executing.
- `transport.py`: accepts only a supplied anonymous connected `AF_UNIX/SOCK_SEQPACKET` endpoint. Every packet is exactly 64 bytes. No listener, network service, device node or host USB access is created.
- `preflight.py`: fails closed before any listener/socketpair/browser allocation on unsupported Linux/architecture, missing/nonregular/symlink/unreadable/nonexecutable files, incompatible ELF types, static/privileged/file-capability browser images that may ignore preloading, missing dynamic ABI exports, unavailable real libudev monitoring, or failed immediate dependency/symbol resolution. The isolated trusted-hook load probe has no opt-in/relay and is never Chromium. Inherited loader/hook configuration is rejected.
- `runner_resources.py`: bounded resource cleanup, including errors before browser process creation and before worker threads start.
- `acceptance.py`: independently validates WebAuthn browser-output shapes, one-use challenge, origin, RP hash, flags, fixture identity, public key, self-attestation signature, assertion signature and counter.

The repository’s `native-hid-hook` owns the client end of the anonymous socketpair. Its explicit child-process-only preload strips report ID zero from a 65-byte hidraw write and transfers exactly 64 bytes to this fixture. Incoming fixture packets are exactly 64 bytes; the unchanged browser would supply its own report-ID representation. The original inherited relay FD remains dedicated to this protocol and is retained until child shutdown. No automatic reconnect or replay occurs.

## Reproduce the completed checks

Requires Python `cryptography` 50.0.0, OpenSSL, and a C compiler. These were already installed during verification; a fresh environment can use the pinned requirements.txt through its normal approved dependency workflow.

```sh
cd tests/ctap2_fixture
python3 -m unittest discover -s tests -v
python3 tests/hook_roundtrip.py
python3 -m py_compile *.py tests/*.py
```

The hook must already be built through its own authorized workflow; this fixture does not modify/build it. The C client is compiled only into this fixture's `evidence/` directory.

Reproducible checks (generated evidence is deliberately excluded from source):

- `evidence/unit-tests.log`: **28 passing tests**, including canonical encodings, bad inputs/bounds, unsupported options, allow-list/RP/exclusion checks, default-denied presence, overflow, counters, cancellation/resync/timeout, actual packet socket and EOF, browser-result verification and no-launch default. Twelve added preflight/cleanup tests mock missing loader dependencies and denied libudev operations; no real denied monitor call is retried. Real read-only ELF/export checks are in `evidence/preflight-static.log`.
- Both registration self-attestation and assertions are independently verified using the public key reconstructed from returned COSE data, including **separate OpenSSL CLI verification**. Tampered client hashes/signatures/origins/challenges/RP hashes/IDs are rejected.
- `evidence/hook-roundtrip.log`: real preloaded **C ABI harness** opened the FIDO-only virtual hidraw boundary and exchanged INIT/getInfo/makeCredential/getAssertion. OpenSSL verified registration and two monotonic assertions. Partial CANCEL passed. This is not Chromium acceptance.

## Prepared future browser acceptance, never executed here

```sh
python3 future_browser_acceptance.py
```

The default prints a plan and creates **no** browser, listener, profile, or credential. In a separately authorized environment where ordinary Chromium and real libudev monitoring work, supplying only a trusted, authorized hook build, the explicit `--run-in-authorized-environment` flag prepares an anonymous relay, a temporary profile, and a localhost-only page. Use both page buttons through Chromium's native external security-key UI. No CDP virtual-authenticator command, patched browser parser, sandbox relaxation, external test site, or fabricated WebAuthn response is used. Packed self-attestation must actually be returned and verified; browser attestation stripping is a failure of this stricter acceptance criterion, not a fabricated pass.

The prepared runtime branch is **unexecuted**. Tests invoke only its mocked prerequisite-rejection path and verify no server/socketpair/browser is allocated. Real libudev and hook-load probes in the future runner were not executed here; the existing separate C ABI fixture roundtrip remains the actual hook-loading evidence. It requires testing process/FD inheritance, real enumeration, Chromium's descriptor/parser/FIDO path, native UI and both verified browser results. It does not establish any of them merely by existing.

This environment's previously confirmed Chromium singleton socket EPERM and libudev monitor EPERM are unchanged. No Chromium launch was attempted for this fixture. Do not retry through a workaround, preload a denied system call, edit host policy, install a global preload, or relax browser security.

## Primary protocol reference

The fixture intentionally implements a bounded subset of [FIDO CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html), especially authenticatorMakeCredential/getAssertion/getInfo, canonical CBOR and CTAPHID transport. Passing these tests is neither FIDO certification nor proof of complete conformance.
