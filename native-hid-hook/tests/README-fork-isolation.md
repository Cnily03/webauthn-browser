# Standard-fork endpoint isolation regression

Run after building the hardened hook:

```sh
python3 tests/run_fork_isolation.py
```

This runner compiles only `tests/fork_isolation.c` into a temporary directory
under `tests`, then exercises the existing hook library in six independent
preloaded processes, plus five constructor-owner rejection processes. It prints
and verifies the library SHA-256, never runs
Cargo, and uses only anonymous sockets and synthetic opaque reports. Compilation,
subprocess execution, fixture operations, pin observation, and child completion
are bounded. The C process also has an alarm. No payloads are printed.
Successful output is recorded in `tests/fork_isolation.log`. The unchanged
endpoint-reset cases were also rerun against the hardened library, with their
output in `tests/generation_reset_hardened.log`; the earlier log is preserved.

Cases:

- `basic`: the validated original relay is `FD_CLOEXEC`, and the initial owner
  marker matches the process. Standard `fork` closes the original relay and two
  virtual aliases in the child. Raw `fcntl`, `read`, and `write` return `EBADF`,
  and a `/proc/self/fd` scan finds no socket with the owned endpoint's
  `SO_COOKIE`. An ordinary inherited pipe and unrelated socket still work.
- `relay-reuse`: a raw close and raw `dup2` put an unrelated socket at the
  original relay FD number. The fork child preserves this unrelated socket
  while closing remaining owned virtual aliases.
- `alias-reuse`: an unrelated socket replaces a tracked alias using raw
  syscalls. The child preserves that socket while closing the original relay
  and a still-owned alias.
- `blocked-pin`: another thread blocks in a virtual read. A cookie scan first
  proves that a third FD exists beyond the original relay and known alias,
  identifying the internal pinned duplicate. Standard fork must leave zero
  matching endpoint cookies in the child. The parent then writes a report;
  its blocked reader resumes with the fixture's echo and the internal pin
  disappears. The test does not assume that a delay proves a read is pinned.
- `fork-exec`: a child verifies old owned FDs were physically closed, explicitly
  points `UHF_RELAY_FD` at a fresh unrelated connected socket, and execs the C
  harness with the inherited `UHF_OWNER_PID`. Both synthetic device and
  descriptor opens remain absent. The unrelated socket keeps ordinary raw
  read/write functionality in both directions and does not acquire CLOEXEC
  merely because the owner marker mismatched.
- `capability-aliases`: duplicates of the original relay through `dup`, `dup2`,
  `dup3`, `F_DUPFD`, and `F_DUPFD_CLOEXEC` (both `fcntl` and `fcntl64`) retain
  ordinary 64-byte socket semantics and standard descriptor flags. The same
  variants duplicate those aliases again. All still-owned aliases close in the
  fork child, and parent I/O continues. An unrelated descriptor overwriting a
  capability alias through interposed `dup2`, and another replacing a
  raw-closed alias, remain usable in the child. This does not claim tracking of
  newly created raw-syscall aliases.
- `inactive-owner`: five fresh subprocesses supply malformed, zero, negative,
  overflowing, and known-mismatched positive owner markers. Each marker remains
  unchanged, synthetic device and descriptor opens are absent, and the supplied
  socket still exchanges raw reports without any descriptor-flag mutation.
  No libudev or browser calls are made by this dedicated runner.

All cases verify parent report I/O after fork. Existing `tests/harness.c` also
retains its 30-child sustained concurrent-dup/fork test; it now expects physical
child FD closure and explicitly checks ordinary inherited pipe/socket access.

This validates standard libc-fork lifecycle hygiene for supported original,
alias, and internal pinned descriptors. It does not establish a hostile-process
security boundary, cover deliberate marker removal, or certify arbitrary
raw-fork/clone, raw duplicated FDs, manipulation of shim-private pinned FDs, or
all races/third-party atfork orderings. In particular, raw-replacing a private
pin during a blocked read can redirect a later syscall within that read and is
not supported; the live-pin case proves child closure without such tampering.
It makes no browser, authenticator, or WebAuthn acceptance claim.
