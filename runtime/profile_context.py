"""Immutable, server-derived paths for isolated desktop profiles.

Display slots are transient runtime resources. Persistent paths use only immutable
profile IDs, never editable names or a caller-supplied filesystem path.
"""
import os
from pathlib import Path
import stat
import uuid

MAX_PROFILES = 16
# A worker failure may still have completed its owned-service cleanup. Other
# nonzero exits (especially signals) never prove that its display slot is free.
CLEAN_FAILURE_EXIT = 70
DATA_ROOT = Path('/data')
RUN_ROOT = Path('/data/run/profiles')
CACHE_ROOT = Path('/tmp/webauthn-browser-cache')


def prepare_x_socket_dir(path=Path('/tmp/.X11-unix')):
    """Prepare the shared X socket directory before concurrent workers start."""
    if path.is_symlink():
        raise RuntimeError('X socket directory must not be a symbolic link')
    if not path.exists():
        path.mkdir(mode=0o1777)
        path.chmod(0o1777)  # The private manager umask must not strip access.
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o1777:
        raise RuntimeError('X socket directory must be a directory with mode 1777')


def valid_profile_id(value):
    if value == 'default':
        return True
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, AttributeError):
        return False


def private_directory(path):
    """Create missing private components; never repair existing user ownership."""
    path = Path(path)
    missing = []
    current = path
    while not current.exists() and not current.is_symlink():
        missing.append(current)
        current = current.parent
    for ancestor in (current, *current.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('Unsafe profile directory')
    for directory in reversed(missing):
        # Different profiles can create their shared private ancestor at once.
        # Revalidate the winner; never repair permissions or follow a symlink.
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Unsafe newly created profile directory')
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('Profile directory must be private and owned by the runtime user')
    return path


class ProfilePaths:
    def __init__(self, profile_id, slot, *, data=DATA_ROOT, run=RUN_ROOT, cache=CACHE_ROOT):
        if not valid_profile_id(profile_id) or type(slot) is not int or not 0 <= slot < MAX_PROFILES:
            raise ValueError('Invalid profile identity or display slot')
        self.profile_id = profile_id
        self.slot = slot
        self.home = Path(data) if profile_id == 'default' else Path(data) / 'profiles' / profile_id
        self.profile = self.home / 'chromium'
        self.config = self.home / 'config'
        self.runtime = Path(run) / profile_id
        self.cache = Path(cache) / profile_id
        self.display = f':{99 + slot}'
        self.vnc_port = 5900 + slot

    def prepare(self):
        # Check intermediate roots as well as final leaves; a preexisting profile
        # must never redirect another profile's sockets or persistent storage.
        for path in (self.home.parent, self.home, self.profile, self.config,
                     self.runtime.parent, self.runtime, self.cache.parent, self.cache):
            if path in (Path('/'), Path('/tmp')):
                continue
            private_directory(path)

    def metadata(self):
        root = self.runtime
        return dict(display=self.display, vnc_port=self.vnc_port,
                    runtime_dir=str(root), control_path=str(root / 'reconnect.sock'),
                    proxy_path=str(root / 'webauthn.sock'), clipboard_path=str(root / 'clipboard.sock'),
                    ble_path=str(root / 'ble.sock'), status_path=str(root / 'runtime.json'))

    def environment(self, inherited):
        result = dict(inherited)
        # No gateway capability or old preload/descriptor marker may propagate
        # into a newly selected profile. Worker management is added separately.
        for key in tuple(result):
            if key.startswith('UHF_') or key.startswith('AUTH_BROWSER_FIDO_') or key.startswith('AUTH_BROWSER_RESOURCE_') or key in (
                    'AUTH_BROWSER_PROFILE_EPOCH',
                    'LD_PRELOAD', 'AUTH_BROWSER_PROFILE_WORKER_FD',
                    'AUTH_BROWSER_PROFILE_CONTROL_TOKEN', 'AUTH_BROWSER_PROFILE_CONTROL_PATH'):
                result.pop(key)
        result.update(HOME=str(self.home), DISPLAY=self.display,
                      XDG_RUNTIME_DIR=str(self.runtime), XDG_CONFIG_HOME=str(self.config),
                      XDG_CACHE_HOME=str(self.cache), AUTH_BROWSER_PROFILE_ID=self.profile_id,
                      AUTH_BROWSER_PROFILE_SLOT=str(self.slot),
                      AUTH_BROWSER_PROFILE_RUNTIME_DIR=str(self.runtime),
                      AUTH_BROWSER_PROFILE_DATA_DIR=str(self.profile),
                      AUTH_BROWSER_PROFILE_VNC_PORT=str(self.vnc_port),
                      AUTH_BROWSER_PROXY_SOCKET=str(self.runtime / 'webauthn.sock'),
                      DBUS_SYSTEM_BUS_ADDRESS=f'unix:path={self.runtime}/dbus-system.sock',
                      DBUS_SESSION_BUS_ADDRESS=f'unix:path={self.runtime}/dbus-session.sock')
        # The hook path is trusted package configuration, not a received FD.
        if 'AUTH_BROWSER_FIDO_HOOK_PATH' in inherited:
            result['AUTH_BROWSER_FIDO_HOOK_PATH'] = inherited['AUTH_BROWSER_FIDO_HOOK_PATH']
        return result
