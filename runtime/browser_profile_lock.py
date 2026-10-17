"""Explicit, narrowly scoped recovery of a stopped Chromium profile's symlinks.

A foreign hostname or a socket missing in this container cannot establish that
another container sharing the profile is stopped. Recovery therefore requires
an explicit exclusive-profile deployment assertion (or maintenance approval).
"""
import argparse
import fcntl
import os
from pathlib import Path
import socket
import stat


NAMES = ('SingletonSocket', 'SingletonCookie', 'SingletonLock')
GUARD = '.webauthn-browser-profile.lock'


class ProfileLockError(RuntimeError):
    pass


def acquire(profile):
    """Serialize cooperating owners without replacing the persistent lock inode."""
    directory = os.open(profile, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ProfileLockError('Profile directory must be owned by this user with mode 0700.')
        descriptor = os.open(GUARD, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ProfileLockError('Unsafe persistent profile guard.')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProfileLockError('Profile is already owned by another running service.') from None
            return directory, descriptor
        except BaseException:
            os.close(descriptor)
            raise
    except BaseException:
        os.close(directory)
        raise


def snapshot(directory):
    result = {}
    for name in NAMES:
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            raise ProfileLockError('Singleton artifacts must be owned symbolic links; nothing was removed.')
        target = os.readlink(name, dir_fd=directory)
        if not target or len(target) > 4096:
            raise ProfileLockError('Invalid singleton link; nothing was removed.')
        result[name] = (info.st_dev, info.st_ino, info.st_ctime_ns, target)
    return result


def recover(profile, *, confirmed_exclusive=False):
    if not confirmed_exclusive:
        raise ProfileLockError('Confirm that every container or browser using this profile is stopped and the profile is not shared before recovery.')
    directory, descriptor = acquire(profile)
    try:
        return recover_locked(profile, directory, confirmed_exclusive=confirmed_exclusive)
    finally:
        os.close(descriptor)
        os.close(directory)


def recover_locked(profile, directory, *, confirmed_exclusive=False):
    if not confirmed_exclusive:
        return 0
    argument = '--user-data-dir=' + str(Path(profile).resolve())
    # The persistent guard serializes cooperating services. Independently
    # refuse a visible process using this profile before applying the explicit
    # deployment assertion about other containers/namespaces.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            arguments = (entry / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise ProfileLockError('Local process ownership cannot be inspected.') from None
        if argument.encode() in arguments:
            raise ProfileLockError('A local process is still using this browser profile.')
    before = snapshot(directory)
    lock = before.get('SingletonLock')
    if lock is None:
        if before:
            raise ProfileLockError('Missing SingletonLock ownership evidence; nothing was removed.')
        return 0
    host, separator, pid = lock[3].rpartition('-')
    if not separator or not host or not pid.isdecimal() or int(pid) <= 1:
        raise ProfileLockError('Malformed SingletonLock; nothing was removed.')
    if host == socket.gethostname():
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            pass
        except PermissionError:
            raise ProfileLockError('Singleton owner cannot be inspected; nothing was removed.') from None
        else:
            raise ProfileLockError('Singleton owner PID is still present; nothing was removed.')
    endpoint = before.get('SingletonSocket')
    if endpoint:
        if not os.path.isabs(endpoint[3]):
            raise ProfileLockError('Singleton socket target must be absolute; nothing was removed.')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(.2)
            try:
                probe.connect(endpoint[3])
            except (FileNotFoundError, ConnectionRefusedError):
                pass
            except OSError:
                raise ProfileLockError('Singleton socket state is uncertain; nothing was removed.') from None
            else:
                raise ProfileLockError('Singleton socket is active; nothing was removed.')
    if snapshot(directory) != before:
        raise ProfileLockError('Singleton artifacts changed during inspection; nothing was removed.')
    # Remove directory entries only. Never follow the socket/cookie links,
    # remove their targets, or touch browser data, extensions or credentials.
    for name in NAMES:
        if name in before:
            if snapshot(directory).get(name) != before[name]:
                raise ProfileLockError('Singleton artifact changed during recovery; stopped.')
            os.unlink(name, dir_fd=directory)
    os.fsync(directory)
    return len(before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--confirm-exclusive-profile', action='store_true',
                        help='Assert every old browser/container using this profile is stopped and the profile is not shared.')
    args = parser.parse_args()
    try:
        count = recover(args.profile, confirmed_exclusive=args.confirm_exclusive_profile)
    except (OSError, ProfileLockError) as error:
        parser.exit(1, f'Profile recovery refused: {error}\n')
    print(f'Removed {count} verified Chromium singleton symlink(s); browser data was preserved.')


if __name__ == '__main__':
    main()
