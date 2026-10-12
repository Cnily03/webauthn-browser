"""Fail-closed checks before the prepared browser runner allocates any service.

No browser is executed. The hook load probe is a separate, opt-out process;
only explicitly authorized, trusted fixture build artifacts may be supplied.
"""
import ctypes
import errno
import os
import pathlib
import platform
import shutil
import stat
import struct
import subprocess
import sys

REQUIRED_EXPORTS = frozenset({
    "open", "open64", "openat", "openat64", "read", "write", "close", "ioctl", "fcntl",
    "udev_enumerate_new", "udev_enumerate_scan_devices", "udev_enumerate_get_list_entry",
    "udev_device_new_from_syspath", "udev_device_get_devnode", "udev_device_get_parent",
})

class PreflightError(RuntimeError):
    pass

def clean_environment():
    # Do not let an inherited preload, audit library, or hook opt-in affect the
    # probe/runner. Isolated Python also ignores PYTHONPATH and startup hooks.
    return {key:value for key,value in os.environ.items()
            if not key.startswith("LD_") and key not in {"UHF_ENABLE", "UHF_RELAY_FD"}}

def elf_file(path, *, executable=False, shared=False):
    path = pathlib.Path(path).absolute()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise PreflightError(f"Cannot open required regular file: {path.name}: {error.strerror}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PreflightError(f"Not a regular file: {path.name}")
        if info.st_size > (64 * 1024 * 1024 if shared else 1024 * 1024 * 1024):
            raise PreflightError(f"ELF image exceeds fixture inspection bound: {path.name}")
        if executable and (not info.st_mode & 0o111 or not os.access(path, os.X_OK)):
            raise PreflightError(f"Browser is not executable: {path.name}")
        header = os.read(descriptor, 64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise PreflightError(f"Expected native ELF64 little-endian image: {path.name}")
        kind, machine, version = struct.unpack_from("<HHI", header, 16)
        if machine != 62 or version != 1 or kind not in ({3} if shared else {2,3}):
            raise PreflightError(f"Wrong ELF type or x86-64 target: {path.name}")
        if executable:
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise PreflightError("Privileged browser executable may ignore the explicit preload")
            try:
                capabilities = os.getxattr(path,"security.capability",follow_symlinks=False)
            except OSError as error:
                if error.errno not in (errno.ENODATA,errno.EOPNOTSUPP):
                    raise PreflightError("Cannot verify browser file-capability state") from error
            else:
                if capabilities:
                    raise PreflightError("Browser file capabilities may suppress the explicit preload")
            # A static executable silently ignores LD_PRELOAD. Require the real
            # ELF interpreter rather than treating an executable bit as enough.
            offset = struct.unpack_from("<Q",header,32)[0]
            width,count = struct.unpack_from("<HH",header,54)
            if width != 56 or not 0 < count <= 128 or offset + width*count > info.st_size:
                raise PreflightError("Browser has no bounded dynamic program-header table")
            interpreter = None
            for index in range(count):
                program = os.pread(descriptor,width,offset+width*index)
                if len(program) != width:
                    raise PreflightError("Truncated browser program headers")
                if struct.unpack_from("<I",program)[0] != 3:
                    continue
                start = struct.unpack_from("<Q",program,8)[0]
                size = struct.unpack_from("<Q",program,32)[0]
                if interpreter is not None or not 1 < size <= 4096 or start+size > info.st_size:
                    raise PreflightError("Invalid browser ELF interpreter")
                interpreter = os.pread(descriptor,size,start)
            if interpreter is None or not interpreter.startswith(b"/") or not interpreter.endswith(b"\0") or b"\0" in interpreter[:-1]:
                raise PreflightError("Browser must use a dynamic ELF interpreter for LD_PRELOAD")
        return path
    finally:
        os.close(descriptor)

def dynamic_exports(path):
    readelf = shutil.which("readelf")
    if not readelf:
        raise PreflightError("readelf is required to inspect the hook's dynamic ABI")
    try:
        result = subprocess.run([readelf, "--dyn-syms", "--wide", str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
            env=clean_environment(), check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("Cannot inspect hook dynamic symbols") from error
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise PreflightError("Hook has no readable bounded dynamic symbol table")
    exports = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[3] == "FUNC" and fields[4] in ("GLOBAL", "WEAK") and fields[5] == "DEFAULT" and fields[6] != "UND":
            exports.add(fields[7].split("@")[0])
    return exports

def probe_hook_load(path):
    """RTLD_NOW resolves dependencies/symbols; missing LD_PRELOAD cannot be ignored.

    This executes only a trusted hook constructor in a short isolated opt-out
    Python process, never Chromium or a synthetic HID session.
    """
    source = "import ctypes,os,sys; ctypes.CDLL(sys.argv[1],mode=os.RTLD_NOW|os.RTLD_LOCAL); print('hook-load-ok')"
    try:
        result = subprocess.run([sys.executable, "-I", "-c", source, str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
            env=clean_environment(), cwd="/", check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError("Hook loader prerequisite failed") from error
    if result.returncode or result.stdout.strip() != "hook-load-ok":
        raise PreflightError("Hook could not load with immediate symbol/dependency resolution")

def probe_udev_monitor():
    """Real libudev monitor prerequisite, with no preload or security changes."""
    try:
        library = ctypes.CDLL("libudev.so.1", use_errno=True)
        for name, arguments, result in [
            ("udev_new", [], ctypes.c_void_p),
            ("udev_unref", [ctypes.c_void_p], ctypes.c_void_p),
            ("udev_monitor_new_from_netlink", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_void_p),
            ("udev_monitor_enable_receiving", [ctypes.c_void_p], ctypes.c_int),
            ("udev_monitor_get_fd", [ctypes.c_void_p], ctypes.c_int),
            ("udev_monitor_unref", [ctypes.c_void_p], ctypes.c_void_p),
        ]:
            function = getattr(library,name)
            function.argtypes, function.restype = arguments,result
    except (OSError, AttributeError) as error:
        raise PreflightError("Required system libudev ABI is unavailable") from error
    context = library.udev_new()
    if not context:
        raise PreflightError("System libudev context creation failed")
    monitor = None
    try:
        ctypes.set_errno(0)
        monitor = library.udev_monitor_new_from_netlink(context,b"udev")
        if not monitor:
            code = ctypes.get_errno()
            raise PreflightError(f"Real libudev monitor unavailable: errno={code}; do not bypass this prerequisite")
        if library.udev_monitor_enable_receiving(monitor) != 0 or library.udev_monitor_get_fd(monitor) < 0:
            raise PreflightError("Real libudev monitor could not enable receiving or expose its FD")
    finally:
        if monitor:
            library.udev_monitor_unref(monitor)
        library.udev_unref(context)

def preflight(browser, hook, *, exports_check=dynamic_exports, monitor_check=probe_udev_monitor, load_check=probe_hook_load):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise PreflightError("Only the reviewed Linux x86-64 ABI is supported")
    if any(key.startswith("LD_") for key in os.environ) or os.environ.get("UHF_ENABLE") or os.environ.get("UHF_RELAY_FD"):
        raise PreflightError("Start the runner without inherited loader/preload/hook configuration")
    browser = elf_file(browser,executable=True)
    hook = elf_file(hook,shared=True)
    missing = REQUIRED_EXPORTS - exports_check(hook)
    if missing:
        raise PreflightError("Hook lacks required exported ABI: " + ", ".join(sorted(missing)))
    # Check the previously blocked prerequisite BEFORE executing even the hook
    # loader probe; no listener, socketpair or browser exists at this point.
    monitor_check()
    load_check(hook)
    return browser,hook
