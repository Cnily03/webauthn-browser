# Endpoint lifetime and attempted rebind regression

Run from the prototype root:

```sh
python3 tests/run_generation_reset.py
```

The runner uses the **existing** `target/debug/libuserland_hid_hook.so`, prints its
SHA-256, and verifies that the binary is unchanged afterward. It never runs Cargo.
It compiles only `tests/generation_reset.c` into a temporary directory inside
`tests`, removes that directory, and runs two fresh preloaded subprocesses. The
recorded successful output is `tests/generation_reset.log`.

Each subprocess opens the virtual node and creates `dup` and `F_DUPFD_CLOEXEC`
aliases. An explicit pipe handshake ensures that all old aliases exist before
the Python fixture closes the backend peer. A second handshake ensures the peer
is closed before the child checks results. There are no sleeps or timing-based
packet-delivery assumptions. The compiler, parent coordination, subprocess, and
fixture send operations are bounded by timeouts; the C child also has an alarm.

The two cases cover an empty old receive queue and three synthetic queued
64-byte reports. They establish these specific behaviors:

1. Old aliases cannot send after peer close (`EPIPE`). Reads return `ENODEV` when
   the old queue is empty. Already-queued reports remain readable.
2. Closing all virtual aliases and reopening while the original relay still
   denotes the old endpoint succeeds, retaining that identity and any queued old
   reports. **That reopen is not a session reset.**
3. The child deliberately raw-closes the original relay descriptor and uses raw
   `dup2` to install a fresh connected socket at exactly that descriptor number.
   Distinct `SO_COOKIE` values verify that the endpoint changed, while existing
   virtual aliases still refer to the old endpoint. This intentionally violates
   the documented dedicated-relay-FD contract to exercise fail-closed behavior;
   it is not a supported reconnection recipe.
4. A report queued by the fresh peer remains untouched by old-alias reads. Old
   aliases can still consume the final old queued report, then return `ENODEV`.
   Their writes return `EPIPE`, and the fresh peer receives nothing from them.
5. New virtual opens are `EBUSY` while old aliases remain. After the last alias
   closes, all 16 attempts across `open`, `open64`, `openat`, and `openat64` fail
   with `ENODEV`, rather than rebinding to the replacement endpoint. The fresh
   endpoint's queued report and nonblocking flag remain intact. A direct socket
   exchange confirms the fresh connection itself works in both directions.

These are deterministic sequential regressions, not proof of every concurrent
raw-syscall race. Peer close does **not** retract queued packets, and this test
does not add queue flushing, generation/session reset, reconnect, hotplug, or
cross-process coordination. It uses anonymous sockets and synthetic opaque
bytes only. It launches no browser, changes no host settings, logs no payloads,
and makes no authenticator or WebAuthn acceptance claim.
