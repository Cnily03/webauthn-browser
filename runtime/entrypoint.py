#!/usr/bin/env python3
"""Prepare only the dedicated data directory, then permanently drop privileges."""
import os
from pathlib import Path
import stat
import sys

UID = 10001
GID = 10001
DATA = Path("/data")


def only_empty_runtime_mount(fd, entries, parent, uid):
    # Docker creates the nested tmpfs mount before this process runs. A fresh
    # bind source therefore already contains "run"; recognize only that empty,
    # private, separately mounted directory, never an arbitrary existing child.
    if entries != ["run"]:
        return False
    try:
        run = os.open("run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    except OSError:
        return False
    try:
        info = os.fstat(run)
        return (info.st_dev != parent.st_dev and info.st_uid == uid
                and stat.S_IMODE(info.st_mode) == 0o700 and not os.listdir(run))
    finally:
        os.close(run)


def prepare_data(path=DATA, uid=UID, gid=GID):
    # Open the mount point itself without following a symlink. Never recurse:
    # existing browser profiles may legitimately contain Chromium lock symlinks.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        entries = os.listdir(fd)
        initialize = not entries or only_empty_runtime_mount(fd, entries, info, uid)
        if not initialize and info.st_uid != uid:
            raise RuntimeError(
                "Existing /data must already belong to UID 10001. Refusing to "
                "recursively change host file ownership. Preserve your old "
                "container and see docs/data-migration.md."
            )
        for name in ("run", "chromium", "config", "cache", "auth-browser.json"):
            try:
                child = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(child.st_mode):
                raise RuntimeError(f"Refusing symbolic link at /data/{name}")
        if initialize:
            # Docker can create an empty root-owned ./.data bind source. Change
            # only this directory inode; no host content is traversed or chowned.
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o700)
        elif info.st_mode & 0o777 != 0o700:
            raise RuntimeError("Existing /data must have private mode 0700; no permissions were changed.")
    finally:
        os.close(fd)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if os.getuid() == 0:
        prepare_data()
        os.setgroups([])
        os.setgid(GID)
        os.setuid(UID)
    # With --user override, preparation is intentionally skipped; non-root
    # supervisor checks report incompatible ownership without escalating.
    os.umask(0o077)
    os.execv(sys.executable, [sys.executable, "/opt/webauthn-browser/runtime/supervisor.py", *args])


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"[entrypoint] {error}", file=sys.stderr, flush=True)
        sys.exit(1)
