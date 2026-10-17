"""Reconcile only process generations created by the private profile manager.

The manifest exists before exec, so a worker crash cannot lose process ownership.
Every owned exec inherits an unpredictable generation marker. Signals use pidfds,
never process names, unverified PIDs, old process groups or persistent user files.
"""
import errno
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import time

MANIFEST = 'resources.json'
DISPLAY_ROOT = Path('/tmp/webauthn-browser-resources')
X_ROOT = Path('/tmp')
GENERATION_KEY = 'AUTH_BROWSER_RESOURCE_GENERATION'
EPOCH_KEY = 'AUTH_BROWSER_PROFILE_EPOCH'
ROLE_KEY = 'AUTH_BROWSER_RESOURCE_ROLE'
MAX_PROCESSES = 8192
MAX_ENVIRONMENT = 1024 * 1024
ROLES = frozenset(('browser', 'desktop'))
FORCE_ROLES = ROLES | {'worker'}
SOCKETS = frozenset(('reconnect.sock', 'webauthn.sock', 'clipboard.sock', 'ble.sock',
                    'dbus-system.sock', 'dbus-session.sock'))
FILES = frozenset(('runtime.json', 'runtime.tmp', 'dbus-system.conf'))


class ResourceError(RuntimeError):
    pass


def namespace():
    return dict(boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                pid_namespace=os.readlink('/proc/self/ns/pid'), uid=os.getuid())


def create(paths, epoch, generation):
    value = dict(version=1, profile_id=paths.profile_id, slot=paths.slot,
                 runtime_epoch=epoch, generation=generation, **namespace())
    fd = os.open(paths.runtime / MANIFEST,
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    return value


def read(paths):
    fd = os.open(paths.runtime / MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 2048):
            raise ResourceError('unsafe_resource_manifest')
        raw = source.read(2049)
        if len(raw) > 2048:
            raise ResourceError('resource_manifest_limit')
        value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'version', 'profile_id', 'slot',
            'runtime_epoch', 'generation', 'boot', 'pid_namespace', 'uid'}
            or type(value['version']) is not int or value['version'] != 1 or value['profile_id'] != paths.profile_id
            or type(value['slot']) is not int or value['slot'] != paths.slot
            or not isinstance(value['runtime_epoch'], str)
            or re.fullmatch('[0-9a-f]{32}', value['runtime_epoch']) is None
            or not isinstance(value['generation'], str)
            or re.fullmatch('[0-9a-f]{64}', value['generation']) is None):
        raise ResourceError('invalid_resource_manifest')
    return value


def identity(pid):
    root = Path('/proc') / str(pid)
    info = root.stat()
    raw = (root / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    return info.st_uid, fields[0], int(fields[19]), int(fields[2])


def manager_ancestors():
    ancestors = set()
    pid = os.getpid()
    for _ in range(64):
        if pid <= 0 or pid in ancestors:
            break
        ancestors.add(pid)
        try:
            raw = (Path('/proc') / str(pid) / 'stat').read_text()
            pid = int(raw[raw.rfind(')') + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return ancestors


def process(pid, manifest, *, any_generation=False):
    before = identity(pid)
    if before[0] != manifest['uid'] or before[1] == 'Z':
        return None
    with (Path('/proc') / str(pid) / 'environ').open('rb') as source:
        raw = source.read(MAX_ENVIRONMENT + 1)
    if len(raw) > MAX_ENVIRONMENT:
        raise ResourceError('process_environment_limit')
    fields = raw.split(b'\0')
    prefix = (GENERATION_KEY + '=').encode()
    generations = [item[len(prefix):].decode('ascii', errors='replace')
                   for item in fields if item.startswith(prefix)]
    if (len(generations) != 1 or re.fullmatch('[0-9a-f]{64}', generations[0]) is None
            or (not any_generation and generations[0] != manifest['generation'])):
        return None
    role_prefix = (ROLE_KEY + '=').encode()
    roles = [item[len(role_prefix):].decode('ascii', errors='replace')
             for item in fields if item.startswith(role_prefix)]
    after = identity(pid)
    if (after[0], after[2], after[3]) != (before[0], before[2], before[3]):
        raise ResourceError('process_identity_changed')
    result = dict(pid=pid, start=before[2], group=before[3],
                  role=roles[0] if len(roles) == 1 else 'unknown')
    if any_generation:
        result['generation'] = generations[0]
    return result


def scan(manifest, *, deadline=None):
    if any(manifest[key] != value for key, value in namespace().items()):
        raise ResourceError('foreign_resource_namespace')
    names = os.listdir('/proc')
    if len(names) > MAX_PROCESSES:
        raise ResourceError('process_inventory_limit')
    groups = {}
    ancestors = manager_ancestors()
    found, unreadable, foreign_users = [], [], []
    for name in names:
        if deadline is not None and time.monotonic() >= deadline:
            raise ResourceError('resource_cleanup_timeout')
        if not name.isdecimal():
            continue
        try:
            info = identity(int(name))
            if info[0] != manifest['uid'] and info[1] != 'Z':
                foreign_users.append((int(name), info))
                continue
            owned = process(int(name), manifest, any_generation=True)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            try:
                info = identity(int(name))
                if info[0] == manifest['uid'] and info[1] != 'Z':
                    unreadable.append((int(name), info))
            except (FileNotFoundError, ProcessLookupError):
                pass
            continue
        if owned is None:
            continue
        if owned['pid'] == owned['group']:
            # Supervisor execs create fresh groups. A positively identified
            # leader also proves the origin of non-dumpable sandbox children.
            groups[owned['group']] = dict(owned)
        if owned['generation'] == manifest['generation']:
            owned.pop('generation')
            found.append(owned)
    for pid, info in foreign_users:
        owner = groups.get(info[3])
        if pid in ancestors:
            continue
        if owner is None:
            # An unclassified different-UID orphan can still retain the display
            # or profile. Lack of permission to read it is not absence proof.
            raise ResourceError('foreign_process_inventory_unavailable')
        if owner['generation'] == manifest['generation']:
            found.append(dict(pid=pid, start=info[2], group=info[3], role='unknown'))
    for pid, info in unreadable:
        owner = groups.get(info[3])
        if owner is None or owner['start'] > info[2]:
            raise ResourceError('process_inventory_unavailable')
        try:
            current_owner = process(owner['pid'], manifest, any_generation=True)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            raise ResourceError('process_group_owner_changed') from None
        if current_owner != owner:
            raise ResourceError('process_group_owner_changed')
        if owner['generation'] == manifest['generation']:
            found.append(dict(pid=pid, start=info[2], group=info[3],
                              role=owner['role'], owner=dict(owner)))
        # An unreadable child in a separately verified healthy generation is
        # excluded, rather than blocking every unrelated profile's cleanup.
    return found


def terminate(owned, manifest, *, force=False, kill=None):
    """Pin identity before rechecking it; PID reuse can never redirect a signal."""
    if any(manifest.get(key) != value for key, value in namespace().items()):
        raise ResourceError('foreign_resource_namespace')
    if kill is None:
        kill = force
    if kill and not force:
        raise ResourceError('force_cleanup_required')
    roles = FORCE_ROLES if force else ROLES
    if owned['role'] not in roles or not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ResourceError('owned_process_signal_unavailable')
    try:
        fd = os.pidfd_open(owned['pid'], 0)
    except ProcessLookupError:
        return
    try:
        if 'owner' in owned:
            info = identity(owned['pid'])
            owner = owned['owner']
            if (info[0] != manifest['uid'] or info[2] != owned['start']
                    or info[3] != owned['group'] or owner['generation'] != manifest['generation']):
                raise ResourceError('process_identity_changed')
            # Never keep numeric group authority after its verified leader
            # exits. A reused PGID alone cannot authorize any new process.
            try:
                current_owner = process(owner['pid'], manifest, any_generation=True)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                raise ResourceError('process_group_owner_changed') from None
            if current_owner != owner:
                raise ResourceError('process_group_owner_changed')
        else:
            current = process(owned['pid'], manifest)
            if current is None:
                return
            if current != owned:
                raise ResourceError('process_identity_changed')
        signal.pidfd_send_signal(fd, signal.SIGKILL if kill else signal.SIGTERM)
    except (FileNotFoundError, ProcessLookupError):
        pass
    finally:
        os.close(fd)


def reconcile(manifest, deadline, *, force=False):
    """Reconcile a generation; force is reserved for explicit teardown/recovery.

    Graceful callers retain browser-first TERM-only semantics. Forced teardown
    gives every verified process TERM first, then reopens a pidfd and rechecks
    ownership before KILL. Neither mode signals an unclassified process.
    """
    signaled, killed = set(), set()
    now = time.monotonic()
    # Reserve time for escalation and proving absence within the caller's bound.
    grace_deadline = now + min(1.0, max(0, deadline - now) / 2)
    while True:
        if time.monotonic() >= deadline:
            if force:
                raise ResourceError('resource_cleanup_timeout: process_exit_unconfirmed')
            return False
        try:
            owned = scan(manifest, deadline=deadline)
        except ResourceError as error:
            if str(error) == 'resource_cleanup_timeout' and not force:
                return False
            raise
        if not owned:
            return True
        roles = FORCE_ROLES if force else ROLES
        unknown = [item for item in owned if item['role'] not in roles]
        if unknown:
            if force:
                raise ResourceError('owned_process_role_unconfirmed: pid=' + str(unknown[0]['pid']))
            return False
        if time.monotonic() >= deadline:
            if force:
                raise ResourceError('resource_cleanup_timeout: process_inventory_unconfirmed')
            return False
        browsers = [item for item in owned if item['role'] == 'browser']
        targets = owned if force else (browsers or owned)
        # Non-dumpable children must be signaled while their leader can still
        # prove their ownership. Never retain numeric group authority afterward.
        for item in sorted(targets, key=lambda item: ('owner' not in item, item['role'] != 'browser')):
            if time.monotonic() >= deadline:
                break
            key = (item['pid'], item['start'])
            if key not in signaled:
                if force:
                    terminate(item, manifest, force=True, kill=False)
                else:
                    terminate(item, manifest)
                signaled.add(key)
            elif force and time.monotonic() >= grace_deadline and key not in killed:
                terminate(item, manifest, force=True)
                killed.add(key)
        time.sleep(min(.05, max(0, deadline - time.monotonic())))


def display_directory(*, create=False):
    if create:
        DISPLAY_ROOT.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(DISPLAY_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ResourceError('unsafe_display_lease_directory')
    finally:
        os.close(fd)


def read_display(profile):
    display_directory()
    fd = os.open(DISPLAY_ROOT / f'{profile}.json',
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'r') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 2048):
            raise ResourceError('unsafe_display_lease')
        raw = source.read(2049)
        if len(raw) > 2048:
            raise ResourceError('display_lease_limit')
        lease = json.loads(raw)
    if (not isinstance(lease, dict) or set(lease) != {'profile_id', 'slot', 'runtime_epoch',
            'generation', 'pid', 'start', 'artifacts', 'boot', 'pid_namespace', 'uid'}
            or lease['profile_id'] != profile or type(lease['slot']) is not int or not 0 <= lease['slot'] < 16
            or not isinstance(lease['runtime_epoch'], str) or re.fullmatch('[0-9a-f]{32}', lease['runtime_epoch']) is None
            or not isinstance(lease['generation'], str) or re.fullmatch('[0-9a-f]{64}', lease['generation']) is None
            or type(lease['pid']) is not int or lease['pid'] <= 1
            or type(lease['start']) is not int or lease['start'] <= 0
            or type(lease['uid']) is not int or lease['uid'] != os.getuid()
            or not isinstance(lease['boot'], str) or not isinstance(lease['pid_namespace'], str)
            or not isinstance(lease['artifacts'], dict) or set(lease['artifacts']) - {'socket', 'lock'}
            or any(not isinstance(value, list) or len(value) != 3
                   or any(type(part) is not int or part < 0 for part in value)
                   for value in lease['artifacts'].values())):
        raise ResourceError('invalid_display_lease')
    return lease


def record_display(runtime, epoch, generation, pid, slot):
    owner = process(pid, dict(uid=os.getuid(), generation=generation))
    if owner is None or owner['role'] != 'desktop':
        raise ResourceError('display_owner_unconfirmed')
    artifacts = {}
    for name, path in (('lock', X_ROOT / f'.X{99+slot}-lock'),
                       ('socket', X_ROOT / '.X11-unix' / f'X{99+slot}')):
        try:
            item = path.lstat()
        except FileNotFoundError:
            continue
        expected = stat.S_ISREG if name == 'lock' else stat.S_ISSOCK
        if item.st_uid != os.getuid() or not expected(item.st_mode):
            raise ResourceError('unsafe_display_artifact')
        artifacts[name] = [item.st_dev, item.st_ino, item.st_ctime_ns]
    profile = Path(runtime).name
    value = dict(profile_id=profile, slot=slot, runtime_epoch=epoch, generation=generation,
                 pid=pid, start=owner['start'], artifacts=artifacts, **namespace())
    if process(pid, dict(uid=os.getuid(), generation=generation)) != owner:
        raise ResourceError('display_owner_unconfirmed')
    display_directory(create=True)
    fd = os.open(DISPLAY_ROOT / f'{profile}.json',
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())


def remove_display_lease(paths, manifest):
    try:
        lease = read_display(paths.profile_id)
    except FileNotFoundError:
        return
    if (lease['runtime_epoch'] != manifest['runtime_epoch']
            or lease['generation'] != manifest['generation'] or lease['slot'] != paths.slot):
        raise ResourceError('display_generation_changed')
    (DISPLAY_ROOT / f'{paths.profile_id}.json').unlink()


def remove_display(paths, manifest):
    number = 99 + paths.slot
    socket_dir = X_ROOT / '.X11-unix'
    socket_path = socket_dir / f'X{number}'
    lock_path = X_ROOT / f'.X{number}-lock'
    if socket_dir.is_symlink():
        raise ResourceError('unsafe_display_directory')
    if not any(path.exists() or path.is_symlink() for path in (socket_path, lock_path)):
        return
    # Display artifacts outside the private runtime require an additional lease
    # proving which exact Xvfb created them. Never infer ownership from a slot.
    lease = read_display(paths.profile_id)
    if (lease['runtime_epoch'] != manifest['runtime_epoch']
            or lease['generation'] != manifest['generation'] or lease['slot'] != paths.slot):
        raise ResourceError('invalid_display_lease')
    if all(lease[key] == value for key, value in namespace().items()):
        try:
            live = identity(lease['pid'])
            if live[1] != 'Z':
                raise ResourceError('display_owner_unconfirmed')
        except (FileNotFoundError, ProcessLookupError):
            pass
    # Across a container namespace restart, no old PID is inspected or signaled.
    # Exact inode/ctime evidence and an inactive socket are still required.
    expected = {}
    for path, check in ((lock_path, stat.S_ISREG), (socket_path, stat.S_ISSOCK)):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if info.st_uid != os.getuid() or not check(info.st_mode):
            raise ResourceError('unsafe_display_artifact')
        evidence = [info.st_dev, info.st_ino, info.st_ctime_ns]
        name = 'lock' if path == lock_path else 'socket'
        if lease['artifacts'].get(name) != evidence:
            raise ResourceError('display_artifact_changed')
        expected[path] = evidence
    if lock_path in expected:
        fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'r') as source:
            raw = source.read(64).strip()
        if not raw.isdecimal() or int(raw) != lease['pid']:
            raise ResourceError('display_lock_changed')
    if socket_path in expected:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as probe:
            probe.settimeout(.1)
            try:
                probe.connect(str(socket_path))
            except OSError as error:
                if error.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                    raise ResourceError('display_socket_unconfirmed') from None
            else:
                raise ResourceError('display_socket_active')
    for path, identity_value in expected.items():
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if [info.st_dev, info.st_ino, info.st_ctime_ns] != identity_value:
            raise ResourceError('display_artifact_changed')
        path.unlink()


def remove_transient(paths, manifest):
    """Only known runtime files, through a pinned directory and exact manifest."""
    try:
        fd = os.open(paths.runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        remove_display(paths, manifest)
        remove_display_lease(paths, manifest)
        return
    try:
        try:
            current = read(paths)
        except FileNotFoundError:
            # A completed cleanup may be retried, but a missing ownership file
            # cannot authorize deleting leftover runtime resources.
            for name in SOCKETS | FILES:
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ResourceError('resource_manifest_missing_with_resources')
            remove_display(paths, manifest)
            remove_display_lease(paths, manifest)
            return
        if current != manifest:
            raise ResourceError('resource_generation_changed')
        remove_display(paths, manifest)
        for name in sorted(SOCKETS | FILES):
            try:
                before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            expected = stat.S_ISSOCK if name in SOCKETS else stat.S_ISREG
            if before.st_uid != os.getuid() or not expected(before.st_mode):
                raise ResourceError('unsafe_transient_resource')
            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ResourceError('transient_resource_changed')
            os.unlink(name, dir_fd=fd)
        # Completion removes the ownership record last. Unknown files, caches,
        # Chromium data, saved sessions and user configuration are untouched.
        if read(paths) != manifest:
            raise ResourceError('resource_generation_changed')
        remove_display_lease(paths, manifest)
        os.unlink(MANIFEST, dir_fd=fd)
    finally:
        os.close(fd)


def pristine_start(run_root, max_profiles, *, deadline=None, allowed_generations=(), allowed_slots=(), allowed_processes=None):
    """Prove an empty container namespace before issuing null-epoch receipts.

    Empty in-memory records are insufficient after a manager restart. Check
    process provenance and the fixed display/transport namespace as well.
    """
    ancestors = manager_ancestors()
    names = os.listdir('/proc')
    if len(names) > MAX_PROCESSES:
        return False
    displays = {f'DISPLAY=:{99+slot}'.encode() for slot in range(max_profiles)}
    runtime_prefix = str(Path(run_root).parent).encode()
    groups, unreadable = {}, []
    for name in names:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        if not name.isdecimal() or int(name) in ancestors:
            continue
        try:
            info = identity(int(name))
            if allowed_processes and allowed_processes.get(int(name)) == (info[0], info[2]):
                continue
            if info[1] == 'Z':
                continue
            if info[0] != os.getuid():
                unreadable.append((int(name), info))
                continue
            with (Path('/proc') / name / 'environ').open('rb') as source:
                raw = source.read(MAX_ENVIRONMENT + 1)
            if len(raw) > MAX_ENVIRONMENT:
                return False
            fields = raw.split(b'\0')
            prefix = (GENERATION_KEY+'=').encode()
            generations = [item[len(prefix):].decode('ascii', errors='replace')
                           for item in fields if item.startswith(prefix)]
            if generations:
                if len(generations) == 1 and generations[0] in allowed_generations:
                    if int(name) == info[3]:
                        owner = process(int(name), dict(uid=os.getuid(), generation=generations[0]),
                                        any_generation=True)
                        if owner is None or owner['start'] != info[2] or owner['generation'] != generations[0]:
                            return False
                        groups[info[3]] = owner
                    continue
                return False
            if any(item.startswith(b'AUTH_BROWSER_PROFILE_ID=') for item in fields):
                return False
            if displays.intersection(fields) and any(
                    item.startswith(b'XDG_RUNTIME_DIR='+runtime_prefix) for item in fields):
                return False
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            try:
                info = identity(int(name))
                if info[1] != 'Z':
                    unreadable.append((int(name), info))
            except (FileNotFoundError, ProcessLookupError):
                pass
            except (OSError, ValueError):
                return False
        except (OSError, ValueError, ResourceError):
            return False
    # Non-dumpable sandbox children cannot expose their environment. Only a
    # still-live, generation-verified group leader can account for them; an
    # unknown or reused group must continue blocking admission globally.
    for pid, info in unreadable:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        owner = groups.get(info[3])
        if owner is None or owner['start'] > info[2]:
            return False
        try:
            current = process(owner['pid'], dict(uid=os.getuid(), generation=owner['generation']),
                              any_generation=True)
            if current != owner:
                return False
        except (OSError, ValueError, ResourceError):
            return False
        try:
            child = identity(pid)
            if (child[0], child[2], child[3]) != (info[0], info[2], info[3]):
                return False
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError):
            return False
    for slot in range(max_profiles):
        if slot in allowed_slots:
            continue
        for path in (X_ROOT / f'.X{99+slot}-lock', X_ROOT / '.X11-unix' / f'X{99+slot}'):
            if path.exists() or path.is_symlink():
                return False
    for source in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')):
        try:
            with source.open() as stream:
                raw = stream.read(MAX_ENVIRONMENT + 1)
            if len(raw) > MAX_ENVIRONMENT:
                return False
            for row in raw.splitlines()[1:]:
                fields = row.split()
                port = int(fields[1].rsplit(':', 1)[1], 16)
                if fields[3] == '0A' and 5900 <= port < 5900 + max_profiles and port-5900 not in allowed_slots:
                    return False
        except (OSError, ValueError, IndexError):
            return False
    return True
