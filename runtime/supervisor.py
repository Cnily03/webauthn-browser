#!/usr/bin/env python3
"""Keep management available when the desktop cannot start.

Tini is PID 1 and reaps orphaned grandchildren. Each managed process gets its
own process group so termination reaches its descendants, not just its launcher.
Sandbox disabling requires the explicit --no-sandbox runtime option.
"""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request

# Resolve beside this file for both the image entrypoint and importlib-based
# lifecycle tests; do not depend on or modify the caller's module search path.
_fido_spec = importlib.util.spec_from_file_location("auth_browser_fido_control", Path(__file__).with_name("fido_control.py"))
_fido_control = sys.modules.get(_fido_spec.name)
if _fido_control is None:
    _fido_control = importlib.util.module_from_spec(_fido_spec)
    sys.modules[_fido_spec.name] = _fido_control
    _fido_spec.loader.exec_module(_fido_control)

_cdp_spec = importlib.util.spec_from_file_location("auth_browser_cdp", Path(__file__).with_name("browser_cdp.py"))
_browser_cdp = sys.modules.get(_cdp_spec.name)
if _browser_cdp is None:
    _browser_cdp = importlib.util.module_from_spec(_cdp_spec)
    sys.modules[_cdp_spec.name] = _browser_cdp
    _cdp_spec.loader.exec_module(_browser_cdp)


_profile_modules = {}
for _name in ("profile_context", "profile_wire", "profile_resources", "display_size"):
    _spec = importlib.util.spec_from_file_location(f"auth_browser_{_name}", Path(__file__).with_name(f"{_name}.py"))
    if not _spec.origin or not Path(_spec.origin).exists():
        continue
    _module = sys.modules.get(_spec.name)
    if _module is None:
        _module = importlib.util.module_from_spec(_spec)
        sys.modules[_spec.name] = _module
        _spec.loader.exec_module(_module)
    _profile_modules[_name] = _module


SANDBOX_FAILURE = (
    "Chromium could not start with its sandbox intact. Inspect its preceding log. "
    "Namespace creation may be denied by container seccomp, AppArmor, or host "
    "user-namespace policy; this error alone does not identify which. "
    "Chromium sandbox layers remain enabled. Settings and "
    "backup export remain available; the desktop is unavailable. "
    "See docs/startup-troubleshooting.md."
)
RUN_PATH = Path(os.environ.get("AUTH_BROWSER_PROFILE_RUNTIME_DIR", "/data/run"))
STATUS_PATH = RUN_PATH / "runtime.json"
RECONNECT_PATH = RUN_PATH / "reconnect.sock"
PROFILE_PATH = Path(os.environ.get("AUTH_BROWSER_PROFILE_DATA_DIR", "/data/chromium"))
PROFILE_ID = os.environ.get("AUTH_BROWSER_PROFILE_ID")
DISPLAY = os.environ.get("DISPLAY", ":99") if PROFILE_ID is not None else ":99"
VNC_PORT = int(os.environ.get("AUTH_BROWSER_PROFILE_VNC_PORT", "5900"))
EXTENSION_UPGRADE_URL = "chrome-extension://hjfbndgjlhfjaplmakeicgoibanbncaf/upgrade.html"
CACHE_PATH = Path(os.environ["XDG_CACHE_HOME"]) if PROFILE_ID is not None else Path("/tmp/webauthn-browser-cache")
EXTENSION_UPGRADE_ATTEMPTS = 2
EXTENSION_UPGRADE_TIMEOUT = 15


class BrowserUnavailable(RuntimeError):
    """The browser can recover without terminating the X/VNC desktop."""


# Only fixed codes and fixed text cross the public diagnostic boundary.
CONTROL_MESSAGES = {
    "invalid_request": "Invalid browser control request; check gateway/runtime versions.",
    "invalid_viewport": "Optional viewport ignored; continuing without resizing.",
    "inspect_failed": "Window inspection failed; check the profile display and window manager.",
    "desktop_unavailable": "Desktop services are unavailable; check the profile runtime log.",
    "maximize_failed": "Window maximization could not be confirmed; check the window manager.",
    "resize_failed": "Optional resizing failed; continuing at the current display size.",
    "resize_query_failed": "Optional resizing could not read the display; continuing without confirmed dimensions.",
    "resize_mode_failed": "Optional resizing could not create a mode; continuing without confirmed dimensions.",
    "resize_attach_failed": "Optional resizing could not attach a mode; continuing without confirmed dimensions.",
    "resize_apply_failed": "Optional resizing could not apply a mode; continuing without confirmed dimensions.",
    "resize_unconfirmed": "Optional resizing was not confirmed; continuing without reporting resized dimensions.",
    "canceled": "Browser request canceled; no automatic retry was made.",
    "timed_out": "Browser request timed out; check current state before retrying.",
    "stale_epoch": "Browser generation changed; refresh ownership before retrying.",
    "restart_unavailable": "Owned browser restart is unavailable; check the profile runtime log.",
    "close_unconfirmed": "Browser close was not confirmed; check current state before retrying.",
    "operation_failed": "Browser lifecycle operation failed; check the profile runtime log.",
}
CONTROL_STAGES = frozenset(("validation", "inspect", "desktop", "resize", "ensure", "restart", "maximize", "reconnect", "transport"))


def control_diagnostic(stage, reason, *, warning=False):
    stage = stage if stage in CONTROL_STAGES else "transport"
    reason = reason if reason in CONTROL_MESSAGES else "operation_failed"
    text = f"Browser control [{stage}/{reason}]: {CONTROL_MESSAGES[reason]}"
    print(f"[supervisor] {'warning' if warning else 'failed'} {text}", file=sys.stderr, flush=True)
    return stage, reason, text


def control_phase(stage, operation):
    try:
        return operation()
    except Exception as error:
        # Preserve the original exception class for cancellation and lifecycle
        # handling; only this fixed phase label is used by the response mapper.
        error.browser_control_stage = stage
        raise


def control_failure(message, error):
    command = message.get("command") if isinstance(message, dict) else None
    command = command if command in ("inspect", "ensure", "restart", "maximize", "reconnect") else None
    stage = getattr(error, "browser_control_stage", command or "validation")
    known = {
        "Unsupported browser command": "invalid_request",
        "Unsupported runtime command": "invalid_request",
        "Invalid browser command lifetime": "invalid_request",
        "Browser request canceled.": "canceled",
        "Browser operation timed out.": "timed_out",
        "Browser generation changed.": "stale_epoch",
        "Desktop is unavailable.": "desktop_unavailable",
        "Owned browser restart is unavailable.": "restart_unavailable",
        "Browser did not finish closing.": "close_unconfirmed",
    }
    # Exact known strings select codes, never become response/log content.
    reason = known.get(str(error), {"inspect": "inspect_failed", "maximize": "maximize_failed"}.get(stage, "operation_failed"))
    stage, reason, text = control_diagnostic(stage, reason)
    response = {"ok": False, "stage": stage, "reason": reason, "error": text}
    request_id = message.get("request_id") if isinstance(message, dict) else None
    if command is not None and isinstance(request_id, str) and re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", request_id):
        response.update(command=command, request_id=request_id)
    return response


def control_request_live(connection):
    # The one request line has already been fully read. Any pending data, EOF,
    # HUP or error now invalidates this operation. poll(0) avoids the socket's
    # one-second read timeout delaying every liveness checkpoint.
    try:
        poller = select.poll()
        poller.register(connection.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
        return not poller.poll(0)
    except (OSError, ValueError, TypeError):
        return False


def verify_browser_executable():
    """Verify the fixed packaged native ELF without FIDO's x86_64 restriction."""
    path = Path(_fido_control.NATIVE_CHROMIUM)
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError("Packaged browser ownership is unsafe.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111
                or info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            raise ValueError("Packaged browser executable is unsafe.")
        # The native OS validates machine compatibility during exec. ARM and
        # other supported Debian architectures remain usable without the hook.
        header = os.read(fd, 6)
        if len(header) != 6 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
            raise ValueError("Packaged browser is not a native ELF.")
    finally:
        os.close(fd)


def prepare_cache_dir(path=CACHE_PATH):
    """Use a private transient cache, without touching any existing user data."""
    path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("Transient cache must belong to the browser user with mode 0700; no existing permissions were changed.")
    finally:
        os.close(fd)



def prepare_x_socket_dir(path=Path("/tmp/.X11-unix")):
    # The manager prepares this once before it accepts concurrent profile starts.
    # Workers still validate it before attaching their separate display socket.
    return _profile_modules["profile_context"].prepare_x_socket_dir(path)


class Supervisor:
    def __init__(self, no_sandbox=False):
        self.no_sandbox = no_sandbox
        self.children = []
        self.stopping = False
        self.control = None
        self.profile_control = None
        self.profile_epoch = os.environ.get("AUTH_BROWSER_PROFILE_EPOCH", secrets.token_hex(16))
        self.profile_gateway_token = None
        self.profile_deadline = None
        self.profile_engine_pending = False
        self.fido_control = _fido_control.FidoController.from_environment()
        self.browser_closed_reported = False
        self.browser_epoch = secrets.token_hex(16)
        self.browser_pipe = None
        self.browser_pipe_process = None
        self.browser_operations = {}
        self.viewport_failures = {}
        self.gateway_started = False
        self.gateway_retry_at = None
        self.gateway_backoff = 1.0
        self.gateway_healthy_since = None
        self.gateway_recovering = False
        self.gateway_probe_at = 0.0
        self.browser_retry_at = None
        self.browser_backoff = 1.0
        self.browser_healthy_since = None
        self.browser_probe_at = 0.0
        self.browser_crash_recovery = False
        self.reset_extension_upgrade()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def browser_failure(self):
        if self.no_sandbox:
            return "Chromium failed in explicitly enabled no-sandbox mode; inspect its preceding log. Settings remain available."
        return SANDBOX_FAILURE

    def request_stop(self, _signum, _frame):
        self.stopping = True

    def spawn(self, name, command):
        if name == "Chromium" and command[0] == "/usr/bin/chromium":
            subprocess.run([sys.executable, "/opt/webauthn-browser/runtime/verify_extension.py"],
                           check=True, timeout=5)
        print(f"[supervisor] Starting {name}", flush=True)
        role = "gateway" if name == "gateway" else "browser" if name == "Chromium" else None
        child_control = None
        options = {"start_new_session": True}
        if self.fido_control is not None or role == "browser" or PROFILE_ID is not None:
            environment = os.environ.copy()
            # Control descriptors and hook ownership belong only to their
            # explicit child. Even secondary launchers get a clean copy.
            for key in tuple(environment):
                if key.startswith("UHF_") or key in (
                        "LD_PRELOAD", "AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY",
                        "AUTH_BROWSER_FIDO_CONTROL_FD", "AUTH_BROWSER_FIDO_GATEWAY_EPOCH",
                        "AUTH_BROWSER_PROFILE_CONTROL_TOKEN", "AUTH_BROWSER_PROFILE_CONTROL_PATH",
                        "AUTH_BROWSER_PROFILE_WORKER_FD"):
                    environment.pop(key)
            if PROFILE_ID is not None:
                environment["AUTH_BROWSER_RESOURCE_ROLE"] = ("browser" if name.startswith("Chromium") else "desktop")
            options["env"] = environment
        if self.fido_control is not None and role is not None:
            try:
                if role == "browser":
                    # Only the initial owned native ELF gets preload/control.
                    # Window and extension-reload launchers keep the wrapper.
                    _fido_control.verify_elf(_fido_control.NATIVE_CHROMIUM)
                    _fido_control.verify_elf(self.fido_control.hook_path, library=True)
                    if command[0] not in ("/usr/bin/chromium", _fido_control.NATIVE_CHROMIUM):
                        raise ValueError("unexpected initial browser executable")
                additions, child_control = self.fido_control.prepare_child(role)
                environment.update(additions)
                options.update(env=environment, pass_fds=(child_control.fileno(),))
                if role == "browser":
                    command = [_fido_control.NATIVE_CHROMIUM, *command[1:]]
            except (OSError, ValueError):
                if child_control is not None:
                    child_control.close()
                    child_control = None
                self.fido_control.retire(role)
                print("[supervisor] Experimental FIDO control unavailable; continuing without it.", file=sys.stderr, flush=True)
        try:
            if role == "browser":
                # The debugging pipe is private to this owned native process.
                # Debian's shell wrapper cannot safely preserve its fd3/fd4.
                verify_browser_executable()
                command = [_fido_control.NATIVE_CHROMIUM, *command[1:]]
                if "--remote-debugging-pipe" not in command:
                    command.insert(1, "--remote-debugging-pipe")
                process, self.browser_pipe = _browser_cdp.spawn(
                    command, options.get("env", os.environ.copy()),
                    inherited_fds={"UHF_CONTROL_FD": child_control.fileno()} if child_control is not None else {})
                self.browser_pipe_process = process
            else:
                process = subprocess.Popen(command, **options)
        except BaseException:
            if self.fido_control is not None and role is not None:
                self.fido_control.child_failed(role)
            raise
        finally:
            if child_control is not None:
                child_control.close()
        self.children.append((name, process))
        if child_control is not None:
            self.fido_control.child_started(role, process)
        return process

    def maintain_gateway(self):
        """Restart only our failed engine process; never replay a ceremony.

        A native-helper failure is recovered by the extension, not by replacing
        a live gateway or Chromium. Logs are never used as crash evidence.
        """
        if self.stopping or not self.gateway_started:
            return
        now = time.monotonic()
        child = next((p for name, p in self.children if name == "gateway"), None)
        if child is not None and child.poll() is not None:
            if self.fido_control is not None:
                self.fido_control.retire("gateway")
            # Retire the entire owned session before opening the same sockets.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            self.children = [(name, p) for name, p in self.children if p is not child]
            self.gateway_retry_at = now + self.gateway_backoff
            self.gateway_backoff = min(30.0, self.gateway_backoff * 2)
            self.gateway_healthy_since = None
            self.gateway_recovering = True
            self.write_status("recovering", "Authentication engine exited; restarting automatically. Active authentication requests were canceled.")
        if self.gateway_retry_at is not None and now >= self.gateway_retry_at:
            try:
                self.spawn("gateway", ["/usr/local/bin/webauthn-browser"])
            except OSError as error:
                self.gateway_retry_at = now + self.gateway_backoff
                self.gateway_backoff = min(30.0, self.gateway_backoff * 2)
                self.write_status("recovering", f"Authentication engine restart failed; retrying automatically: {error}")
                return
            self.gateway_retry_at = None
            self.gateway_probe_at = now
        child = next((p for name, p in self.children if name == "gateway"), None)
        if child is None or child.poll() is not None or now < self.gateway_probe_at:
            return
        self.gateway_probe_at = now + 2
        try:
            ready = self.proxy_ready()
        except (OSError, ValueError):
            ready = False
        if not ready:
            self.gateway_healthy_since = None
            return
        if self.gateway_healthy_since is None:
            self.gateway_healthy_since = now
        if now - self.gateway_healthy_since >= 60:
            self.gateway_backoff = 1.0
        if self.gateway_recovering:
            self.gateway_recovering = False
            if any(name == "Xvfb" and p.poll() is None for name, p in self.children):
                self.write_status("ready", "Authentication engine reconnected. Retry any canceled sign-in.")

    def maintain_browser(self):
        """Recover abnormal browser exits, but respect intentional window close."""
        if self.stopping:
            return
        child = next((p for name, p in self.children if name == "Chromium"), None)
        if child is None and not self.browser_crash_recovery:
            return
        result = child.poll() if child is not None else 1
        now = time.monotonic()
        if result is None:
            self.browser_retry_at = None
            if now >= self.browser_probe_at:
                self.browser_probe_at = now + 2
                try:
                    ready = self.proxy_ready()
                except (OSError, ValueError):
                    ready = False
                if ready and (self.browser_crash_recovery or self.profile_engine_pending):
                    self.browser_crash_recovery = False
                    self.profile_engine_pending = False
                    self.browser_closed_reported = False
                    self.write_status("ready", "Chromium and authentication engine reconnected. Retry any canceled sign-in.")
                if not ready:
                    self.browser_healthy_since = None
                elif self.browser_healthy_since is None:
                    self.browser_healthy_since = now
                elif now - self.browser_healthy_since >= 60:
                    self.browser_backoff = 1.0
            return
        self.browser_healthy_since = None
        self.release_browser_pipe()
        # A launcher can exit while its window-owning descendant survives. X
        # evidence is conservative: a failed query is not proof of browser death.
        try:
            surviving_windows = self.browser_windows()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.browser_retry_at = None
            self.browser_crash_recovery = True
            self.browser_unavailable(BrowserUnavailable(f"Window inspection failed; browser unchanged: {error}"))
            return
        if surviving_windows:
            self.browser_retry_at = None
            if self.browser_crash_recovery and now >= self.browser_probe_at:
                self.browser_probe_at = now + 2
                try:
                    engine_ready = self.proxy_ready()
                except (OSError, ValueError, subprocess.SubprocessError):
                    engine_ready = False
                if engine_ready:
                    self.browser_crash_recovery = False
                    self.browser_closed_reported = False
                    self.write_status("ready", "Browser and engine ready.")
            return
        if result == 0:
            # Closing the final window is a user action, not a crash signal.
            self.browser_crash_recovery = False
            self.browser_retry_at = None
            if not self.browser_closed_reported:
                self.browser_unavailable(BrowserUnavailable("Browser closed. Reconnect to reopen."))
            return
        self.browser_crash_recovery = True
        if self.browser_retry_at is None:
            self.browser_retry_at = now + self.browser_backoff
            self.browser_backoff = min(30.0, self.browser_backoff * 2)
            self.browser_closed_reported = True
            self.write_status("recovering", "Chromium exited unexpectedly; restarting automatically. Retry any canceled sign-in after recovery.")
        if now < self.browser_retry_at:
            return
        self.browser_retry_at = None
        try:
            self.reconnect()
        except InterruptedError:
            raise
        except Exception as error:
            # A living browser with a disconnected helper is not killed here.
            self.browser_unavailable(error)

    def check_children(self, require_browser=True):
        if self.profile_control is not None:
            self.serve_profile_control()
        if self.profile_deadline is not None and time.monotonic() >= self.profile_deadline:
            raise BrowserUnavailable("Profile startup timed out.")
        if self.stopping:
            raise InterruptedError("shutdown requested")
        if self.fido_control is not None:
            self.fido_control.tick()
        self.maintain_gateway()
        self.reap_window_launcher()
        for name, child in self.children:
            result = child.poll()
            if result is not None:
                if name == "gateway" and self.gateway_started:
                    continue
                if name == "Chromium":
                    if require_browser:
                        raise BrowserUnavailable(f"Chromium exited with status {result}. {self.browser_failure()}")
                    continue
                raise RuntimeError(f"{name} exited with status {result}.")
        if self.stopping:
            raise InterruptedError("shutdown requested")

    def wait_ready(self, name, check, timeout=30, require_browser=True):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.check_children(require_browser=require_browser)
            try:
                if check():
                    return
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.2)
        extra = " " + self.browser_failure() if name == "Chromium" else ""
        if name == "Chromium" and self.extension_upgrade_attempted:
            extra = (" The authentication extension did not confirm the current image after bounded reload attempts. "
                     "Reconnect to retry, or rebuild and recreate the container with the current source, preserving /data. "
                     "Do not delete the Chromium profile; inspect extension and native-host versions in the logs.")
        error_type = BrowserUnavailable if name == "Chromium" else RuntimeError
        raise error_type(f"Timed out waiting for {name}.{extra}")

    def display_ready(self):
        result = subprocess.run(
            ["xdpyinfo", "-display", DISPLAY],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        )
        return result.returncode == 0

    def proxy_ready(self):
        # Public status confirms the extension attached, without depending on
        # /readyz (which itself waits for this supervisor's ready state).
        request = urllib.request.Request(
            f"http://127.0.0.1:8080/api/runtime/profiles/{PROFILE_ID}/engine"
            if PROFILE_ID is not None else "http://127.0.0.1:8080/api/status")
        if PROFILE_ID is not None:
            if self.profile_gateway_token is None:
                return False
            request.add_header("X-Profile-Control-Token", self.profile_gateway_token)
        with self.opener.open(request, timeout=2) as response:
            status = json.load(response)
        if status.get("mode_error") == "extension_upgrade_required":
            self.request_extension_upgrade()
            return self.extension_upgrade_readiness(False)
        if status.get("native_qr_mode") is True:
            live = {name for name, child in self.children if child.poll() is None}
            return self.extension_upgrade_readiness(
                status.get("control_connected") is True
                and {"private D-Bus", "BlueZ bridge"}.issubset(live)
                and (RUN_PATH / "ble.sock").is_socket())
        return self.extension_upgrade_readiness(status.get("engine_connected") is True)

    def extension_upgrade_readiness(self, ready):
        if self.extension_upgrade_recovering:
            if ready:
                self.extension_upgrade_recovering = False
                self.extension_upgrade_failed = False
                self.write_status("ready", "Authentication extension updated and connected. Retry any canceled sign-in.")
            elif self.extension_upgrade_expired() and not self.extension_upgrade_failed:
                if self.extension_upgrade_attempts < EXTENSION_UPGRADE_ATTEMPTS:
                    self.request_extension_upgrade()
                else:
                    self.extension_upgrade_failed = True
                    self.write_status("failed", "Authentication extension did not confirm the current image after two reload attempts. Reconnect to retry. If it still fails, rebuild and recreate the container while preserving the data volume and Chromium profile.")
        return ready

    def reset_extension_upgrade(self):
        # Only a new owned Chromium process or an explicit, already authorized
        # Reconnect after exhaustion starts another bounded recovery episode.
        self.extension_upgrade_episode = secrets.token_hex(16)
        self.extension_upgrade_attempts = 0
        self.extension_upgrade_attempted = False
        self.extension_upgrade_recovering = False
        self.extension_upgrade_failed = False
        self.extension_upgrade_deadline = 0.0
        self.extension_upgrade_expires_ms = 0

    def extension_upgrade_expired(self):
        # Both clocks must expire before another page is issued. The page uses
        # the wall-clock bound, so a clock adjustment must not authorize two
        # overlapping reload attempts from this supervisor.
        return (time.monotonic() >= self.extension_upgrade_deadline
                and int(time.time() * 1000) >= self.extension_upgrade_expires_ms)

    def request_extension_upgrade(self):
        # A stale worker cannot understand a new native control frame. Open a
        # packaged extension page: runtime.reload() can reload only that same
        # extension, without management/debugging permissions or profile edits.
        # Readiness remains false until the broker accepts the fresh handshake.
        if self.stopping or self.extension_upgrade_failed or self.extension_upgrade_attempts >= EXTENSION_UPGRADE_ATTEMPTS:
            return
        if self.extension_upgrade_attempts and (
                not self.extension_upgrade_recovering or not self.extension_upgrade_expired()):
            return
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        if browser is None:
            return
        # A live process alone does not prove a browser window exists. Never
        # create an upgrade window as a side effect of uncertain restoration.
        # This also preserves a window whose tracked launcher already exited.
        try:
            if not self.browser_windows():
                return
        except (OSError, ValueError, subprocess.SubprocessError):
            return
        if any(name == "Chromium window launcher" for name, _ in self.children):
            return
        self.extension_upgrade_attempts += 1
        self.extension_upgrade_attempted = True
        self.extension_upgrade_recovering = True
        self.extension_upgrade_failed = False
        self.extension_upgrade_deadline = time.monotonic() + EXTENSION_UPGRADE_TIMEOUT
        self.extension_upgrade_expires_ms = int(time.time() * 1000) + EXTENSION_UPGRADE_TIMEOUT * 1000
        command = self.browser_command()
        attempt = f"{self.extension_upgrade_episode}-{self.extension_upgrade_attempts}"
        command[-1] = f"{EXTENSION_UPGRADE_URL}?attempt={attempt}&expires={self.extension_upgrade_expires_ms}"
        self.write_status("recovering", f"Reloading the browser authentication extension (attempt {self.extension_upgrade_attempts} of {EXTENSION_UPGRADE_ATTEMPTS}). Existing sign-ins are canceled; browser data is preserved.")
        print(f"[supervisor] incompatible extension handshake; requesting extension-only reload {self.extension_upgrade_attempts}/{EXTENSION_UPGRADE_ATTEMPTS}", flush=True)
        self.spawn("Chromium window launcher", command)

    @staticmethod
    def vnc_ready():
        with socket.create_connection(("127.0.0.1", VNC_PORT), timeout=2) as connection:
            return connection.recv(12).startswith(b"RFB ")

    def shutdown(self, desktop_only=False):
        if self.fido_control is not None:
            if desktop_only:
                self.fido_control.retire("browser")
            else:
                self.fido_control.close()
        if not desktop_only:
            self.stopping = True
        if not desktop_only and self.control is not None:
            self.control.close()
            RECONNECT_PATH.unlink(missing_ok=True)
            self.control = None
        children = [(name, child) for name, child in self.children
                    if not desktop_only or name != "gateway"]
        for _, child in reversed(children):
            # Always address the group; children may outlive a failed launcher.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if all(child.poll() is not None for _, child in children):
                break
            time.sleep(0.1)
        for _, child in reversed(children):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        self.release_browser_pipe()
        if desktop_only:
            self.children = [(name, child) for name, child in self.children if name == "gateway"]

    def write_status(self, state, message):
        temporary = STATUS_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps({"state": state, "message": message, "sandbox_enabled": not self.no_sandbox, "updated_at_unix_ms": time.time_ns() // 1_000_000}))
        os.replace(temporary, STATUS_PATH)

    def start_desktop(self, *, wait_engine=True):
        # Do not inherit a host/launcher session address (including disabled:).
        # Both buses belong to this container and are supervised independently.
        self.spawn("private session D-Bus", ["dbus-daemon", "--session", "--nofork", "--nopidfile",
                   f"--address=unix:path={RUN_PATH}/dbus-session.sock"])
        self.wait_ready("private session D-Bus", self.session_dbus_ready)
        self.spawn("private D-Bus", ["dbus-daemon", "--nofork", "--nopidfile",
                   f"--config-file={RUN_PATH / 'dbus-system.conf'}" if PROFILE_ID is not None else "--config-file=/opt/webauthn-browser/runtime/dbus-system.conf"])
        self.wait_ready("private D-Bus", self.dbus_ready)
        self.spawn("BlueZ bridge", [sys.executable, "/opt/webauthn-browser/runtime/bluez_bridge.py"])
        self.wait_ready("BlueZ bridge", self.bluez_ready)
        prepare_x_socket_dir()
        self.spawn("Xvfb", ["Xvfb", DISPLAY, "-screen", "0",
                              "3840x2160x24" if PROFILE_ID is not None else "1440x900x24", "-noreset", "-nolisten", "tcp"])
        self.wait_ready("Xvfb", self.display_ready)
        xvfb = next((child for name, child in self.children if name == "Xvfb"), None)
        if PROFILE_ID is not None and xvfb is not None:
            _profile_modules["profile_resources"].record_display(
                RUN_PATH, self.profile_epoch, os.environ["AUTH_BROWSER_RESOURCE_GENERATION"],
                xvfb.pid, int(os.environ["AUTH_BROWSER_PROFILE_SLOT"]))
        if PROFILE_ID is not None:
            try:
                _profile_modules["display_size"].initialize(DISPLAY, env=os.environ)
            except _profile_modules["display_size"].DisplaySizeError as error:
                # Xvfb readiness is already confirmed; optional initial sizing
                # must not prevent the remaining desktop services from starting.
                control_diagnostic("resize", error.code, warning=True)
        self.spawn("Openbox", ["openbox", "--sm-disable"])
        self.spawn("clipboard bridge", [sys.executable, "/opt/webauthn-browser/runtime/clipboard_bridge.py"])
        self.wait_ready("clipboard bridge", lambda: (RUN_PATH / "clipboard.sock").is_socket())
        self.spawn("x11vnc", [
            "x11vnc", "-display", DISPLAY, "-listen", "127.0.0.1", "-localhost",
            "-rfbport", str(VNC_PORT), "-forever", "-shared", "-nopw", "-noxdamage", "-nosel", "-xrandr",
        ])
        self.wait_ready("x11vnc", self.vnc_ready)
        self.start_browser()
        self.wait_ready("Chromium", self.proxy_ready if wait_engine else self.browser_ready,
                        timeout=45 if wait_engine else 15)

    @staticmethod
    def session_dbus_ready():
        result = subprocess.run(["dbus-send", "--session", "--print-reply", "--reply-timeout=1000",
                                 "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
                                 "org.freedesktop.DBus.GetId"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0

    @staticmethod
    def dbus_ready():
        result = subprocess.run(["dbus-send", "--system", "--print-reply", "--reply-timeout=1000",
                                 "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
                                 "org.freedesktop.DBus.GetId"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0

    @staticmethod
    def bluez_ready():
        if not (RUN_PATH / "ble.sock").is_socket():
            return False
        result = subprocess.run(["dbus-send", "--system", "--print-reply", "--reply-timeout=1000",
                                 "--dest=org.bluez", "/", "org.freedesktop.DBus.ObjectManager.GetManagedObjects"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0

    def browser_command(self, new_window=False, restore_session=False):
        chrome_command = [
            "/usr/bin/chromium", f"--user-data-dir={PROFILE_PATH}",
            f"--disk-cache-dir={CACHE_PATH / 'chromium'}",
            "--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage",
            "--disable-background-mode",
            "--load-extension=/opt/webauthn-browser/extension,/opt/webauthn-browser/extensions/zeroomega,/opt/webauthn-browser/extensions/webrtc-control",
            "--disable-gpu", "--window-size=1440,900", "--start-maximized", "about:blank",
        ]
        if self.no_sandbox:
            chrome_command.insert(1, "--no-sandbox")
            print("[supervisor] WARNING: Chromium sandbox is explicitly disabled; untrusted pages may access container keys and browser data after a browser exploit.", file=sys.stderr, flush=True)
        if new_window:
            chrome_command.insert(-1, "--new-window")
        if restore_session:
            # Recovery alone asks Chromium to restore its own saved session.
            # No profile files are edited and no extra blank page is requested.
            chrome_command[-1] = "--restore-last-session"
        return chrome_command

    def release_browser_pipe(self):
        # Pipe EOF asks Chromium to exit. Never dispose a live owner's pipe as
        # routine timeout/retry cleanup; release only after observed process exit.
        if self.browser_pipe is not None and self.browser_pipe_process.poll() is not None:
            self.browser_pipe.dispose_after_exit()
            self.browser_pipe = self.browser_pipe_process = None

    def start_browser(self, restore_session=False):
        self.release_browser_pipe()
        if self.browser_pipe is not None:
            raise BrowserUnavailable("Browser is still running.")
        self.browser_epoch = secrets.token_hex(16)
        self.browser_operations.clear()
        self.reset_extension_upgrade()
        self.spawn("Chromium", self.browser_command(restore_session=restore_session))

    def reap_window_launcher(self):
        launcher = next((child for name, child in self.children if name == "Chromium window launcher"), None)
        if launcher is None:
            return
        result = launcher.poll()
        if result is not None:
            launcher.wait()
            self.children = [(name, child) for name, child in self.children if child is not launcher]
            if result != 0:
                raise BrowserUnavailable("Chromium could not reopen its window.")
            return
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        if browser is None or browser.poll() is not None:
            if self.fido_control is not None:
                # A singleton launcher was deliberately not preloaded. Promotion
                # must never adopt the old browser's control capability.
                self.fido_control.retire("browser")
            # The original browser can quit between inspection and singleton
            # forwarding. In that race the launcher becomes the one primary.
            if browser is not None:
                browser.wait()
            self.children = [(name, child) for name, child in self.children
                             if name not in ("Chromium", "Chromium window launcher")]
            self.children.append(("Chromium", launcher))
            self.release_browser_pipe()
            self.browser_epoch = secrets.token_hex(16)
            self.browser_operations.clear()

    def browser_windows(self):
        result = subprocess.run(["wmctrl", "-lx"], capture_output=True, text=True, timeout=2, check=True)
        windows = []
        rows = [line for line in result.stdout.splitlines() if line.strip()]
        for line in rows:
            # -lx includes every managed window, including iconified windows
            # and desktop -1 (all desktops): ID, desktop, instance.class, host,
            # optional title. Never use a title to identify a browser.
            fields = line.split(None, 4)
            if (len(fields) < 4 or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", fields[0])
                    or int(fields[0], 16) == 0
                    or not re.fullmatch(r"-?\d+", fields[1]) or int(fields[1]) < -1):
                raise ValueError("Cannot identify existing browser window.")
            if {"chromium", "chromium-browser"}.intersection(fields[2].lower().split(".")):
                windows.append(fields[0])
        if windows:
            return windows
        if rows:
            # Unknown WM_CLASS (including N/A) may be our surviving browser.
            # Preserve it rather than treating unrecognized as genuinely closed.
            raise ValueError("Cannot identify existing browser window.")
        # Cross-check an apparently empty inventory before recovery. Openbox
        # publishes both arrays even when explicitly empty.
        # Require independent, present, empty EWMH properties before recovery.
        clients = subprocess.run(["xprop", "-root", "_NET_CLIENT_LIST", "_NET_CLIENT_LIST_STACKING"],
                                 capture_output=True, text=True, timeout=2, check=True).stdout
        properties = [line.strip() for line in clients.splitlines() if line.strip()]
        expected = ("_NET_CLIENT_LIST", "_NET_CLIENT_LIST_STACKING")
        if len(properties) != 2 or any(
                re.fullmatch(re.escape(name) + r"\(WINDOW\):\s*window id #\s*", line) is None
                for name, line in zip(expected, properties)):
            raise ValueError("Cannot confirm browser windows are closed.")
        return []

    def browser_ready(self):
        # Desktop restoration must not depend on the separate authentication
        # engine handshake, which may be unavailable while live tabs are usable.
        return bool(self.browser_windows())

    def restore_browser(self, budget=lambda seconds: seconds):
        budget(2)
        windows = self.browser_windows()
        if not windows:
            raise BrowserUnavailable("Chromium has no visible browser window yet.")
        window = windows[0]
        # Activation maps an iconified window and brings its desktop forward.
        # Remove fullscreen first so maximizing a formerly fullscreen window
        # still leaves a normal, usable browser toolbar. Existing tabs survive.
        for arguments in (["-ir", window, "-b", "remove,fullscreen"],
                          ["-ir", window, "-b", "add,maximized_vert,maximized_horz"],
                          ["-ia", window]):
            subprocess.run(["wmctrl", *arguments], timeout=budget(1), check=True)
        self.wait_ready("browser window", lambda: self.window_restored(window, budget), timeout=budget(3), require_browser=False)

    def window_restored(self, window, budget=lambda seconds: seconds):
        state = subprocess.run(["xprop", "-id", window, "_NET_WM_STATE"],
                               capture_output=True, text=True, timeout=budget(1), check=True).stdout
        active = subprocess.run(["xprop", "-root", "_NET_ACTIVE_WINDOW"],
                                capture_output=True, text=True, timeout=budget(1), check=True).stdout
        state_property = re.fullmatch(r"_NET_WM_STATE\(ATOM\)\s*=\s*([^\n]*)\s*", state.strip())
        focused = re.fullmatch(r"_NET_ACTIVE_WINDOW\(WINDOW\):\s*window id #\s*(0x[0-9a-fA-F]{1,8})", active.strip())
        if state_property is None or focused is None:
            return False
        atoms = {atom.strip() for atom in state_property.group(1).split(",")}
        return ({"_NET_WM_STATE_MAXIMIZED_VERT", "_NET_WM_STATE_MAXIMIZED_HORZ"}.issubset(atoms)
                and not {"_NET_WM_STATE_HIDDEN", "_NET_WM_STATE_FULLSCREEN"}.intersection(atoms)
                and int(focused.group(1), 16) == int(window, 16))

    def reconnect(self, allow_extension_retry=False):
        # Called exclusively by the supervisor loop: even simultaneous HTTP
        # requests cannot race to create duplicate Chromium processes.
        self.check_children(require_browser=False)
        if not any(name == "Xvfb" for name, _ in self.children) or not self.display_ready() or not self.vnc_ready():
            raise RuntimeError("Desktop infrastructure is unavailable; inspect container startup logs.")
        if allow_extension_retry and self.extension_upgrade_failed:
            self.reset_extension_upgrade()
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        # Inspect before deciding to launch anything. In particular, never kill
        # the process group of an exited launcher: a descendant can still own
        # live tabs. An unavailable X query is an error, never an empty result.
        windows = self.browser_windows()
        restarted = False
        self.write_status("starting", "Restoring browser window.")
        if not windows:
            if browser is None or browser.poll() is not None:
                if browser is not None:
                    browser.wait()  # poll proved this owned launcher exited.
                self.children = [(name, child) for name, child in self.children if name != "Chromium"]
                self.start_browser(restore_session=True)
                restarted = True
            else:
                # Reconnect restores existing windows; a live process with no
                # identified window is uncertainty, not permission to open one.
                raise BrowserUnavailable("Browser is running; window not identified.")
        self.wait_ready("Chromium", self.browser_ready, timeout=25, require_browser=False)
        self.restore_browser()
        self.check_children(require_browser=False)
        # One bounded engine check informs status; it cannot block restoration
        # on an indefinite handshake or authorize restarting a living browser.
        try:
            engine_ready = self.proxy_ready()
        except (OSError, ValueError, subprocess.SubprocessError):
            engine_ready = False
        restarted = restarted or next((child for name, child in self.children if name == "Chromium"), None) is not browser
        self.browser_closed_reported = False
        if engine_ready:
            self.browser_crash_recovery = False
            self.write_status("ready", "Desktop is ready.")
        else:
            self.browser_crash_recovery = True
            self.write_status("recovering", "Browser restored; engine reconnecting.")
        return {"ok": True, "restarted": restarted, "engine_ready": bool(engine_ready)}

    def browser_control(self, message, request_live=lambda: True):
        command = message.get("command")
        request_id = message.get("request_id")
        if (command not in ("inspect", "ensure", "restart", "maximize")
                or not isinstance(request_id, str)
                or re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", request_id) is None
                or set(message) - {"command", "request_id", "expected_epoch", "remaining_ms", "viewport"}):
            raise ValueError("Unsupported browser command")
        viewport = message.get("viewport")
        if viewport is not None and (not isinstance(viewport, dict)
                or set(viewport) != {"width", "height"}
                or any(type(viewport[key]) is not int or not 1 <= viewport[key] <= 16384
                       for key in ("width", "height"))):
            control_diagnostic("validation", "invalid_viewport", warning=True)
            viewport = None
        # Older gateways attached valid geometry to every phase. Observation
        # accepts that envelope but must never resize or apply the dimensions.
        if command == "inspect":
            viewport = None
        remaining_ms = message.get("remaining_ms", 25000)
        if type(remaining_ms) is not int or not 1 <= remaining_ms <= 25000:
            raise ValueError("Invalid browser command lifetime")
        deadline = time.monotonic() + remaining_ms / 1000

        def remaining(cap):
            if not request_live():
                raise BrowserUnavailable("Browser request canceled.")
            value = min(cap, deadline - time.monotonic())
            if value <= 0:
                raise BrowserUnavailable("Browser operation timed out.")
            return value

        if command != "inspect" and message.get("expected_epoch") != self.browser_epoch:
            raise BrowserUnavailable("Browser generation changed.")
        if self.stopping:
            raise InterruptedError("shutdown requested")
        control_phase("desktop", lambda: self.check_children(require_browser=False))
        # Child maintenance can replace the owned process. Recheck the epoch
        # after it runs so an earlier inspect cannot authorize the replacement.
        if command != "inspect" and message.get("expected_epoch") != self.browser_epoch:
            raise BrowserUnavailable("Browser generation changed.")
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        windows = control_phase("inspect", self.browser_windows)
        remaining(25)
        running = browser is not None and browser.poll() is None
        restarted = False
        engine_ready = False
        if command != "inspect":
            if not self.display_ready() or not self.vnc_ready():
                raise BrowserUnavailable("Desktop is unavailable.")
        geometry = None

        def resize_viewport():
            # Revalidate owner-request liveness between individual RandR calls;
            # an observer cannot invoke this through ordinary VNC resizing.
            # Match this admitted request's viewport, including shrinking.
            if viewport is None:
                return None
            now = time.monotonic()
            self.viewport_failures = {key: until for key, until in self.viewport_failures.items() if until > now}
            if request_id in self.viewport_failures or len(self.viewport_failures) >= 128:
                return None
            try:
                return _profile_modules["display_size"].resize(
                    DISPLAY, viewport["width"], viewport["height"], env=os.environ,
                    check=lambda: remaining(25))
            except _profile_modules["display_size"].DisplaySizeError as error:
                # A failed apply may already have changed the screen. Do not
                # retry, claim rollback, or report unconfirmed dimensions.
                self.viewport_failures[request_id] = now + 60
                control_diagnostic("resize", error.code, warning=True)
                return None

        if command != "restart":
            geometry = resize_viewport()
            remaining(25)
        if command == "restart":
            # An auxiliary singleton handoff may still target this profile; do
            # not close its owner while that handoff can race the fresh launch.
            if any(name == "Chromium window launcher" and child.poll() is None
                   for name, child in self.children):
                raise BrowserUnavailable("Browser launcher is still active.")
            key = (request_id, message["expected_epoch"])
            if key in self.browser_operations:
                raise BrowserUnavailable("Restart was already attempted.")
            if len(self.browser_operations) >= 64:
                raise BrowserUnavailable("Restart retry limit reached.")
            # Reserve before writing: an ambiguous pipe response must never
            # replay this explicit request against the same owned generation.
            self.browser_operations[key] = True
            if not running or browser is not self.browser_pipe_process or self.browser_pipe is None:
                raise BrowserUnavailable("Owned browser restart is unavailable.")
            if len(windows) != 1:
                raise BrowserUnavailable("One browser window is required.")
            geometry = resize_viewport()
            remaining(25)
            self.write_status("recovering", "Restarting browser; restoring saved tabs.")
            close_error = None
            try:
                self.browser_pipe.close_browser(timeout=remaining(2))
            except (OSError, ValueError, TimeoutError, _browser_cdp.BrowserPipeError) as error:
                close_error = error
            # Response/EOF alone is not proof of completed session persistence.
            close_deadline = time.monotonic() + remaining(8)
            while browser.poll() is None and time.monotonic() < close_deadline:
                remaining(25)
                if self.stopping:
                    raise InterruptedError("shutdown requested")
                if self.fido_control is not None:
                    self.fido_control.tick()
                time.sleep(0.05)
            if browser.poll() is None:
                raise BrowserUnavailable("Browser did not finish closing.") from close_error
            exit_code = browser.wait()
            self.release_browser_pipe()
            if exit_code != 0:
                raise BrowserUnavailable("Browser exit was not clean.")
            if self.browser_windows():
                raise BrowserUnavailable("Browser windows are still open.")
            # Retire the previous report/control capabilities before a fresh
            # process is launched. No old endpoint or authorization is adopted.
            if self.fido_control is not None:
                self.fido_control.retire("browser")
            self.children = [(name, child) for name, child in self.children if name != "Chromium"]
            remaining(25)
            self.start_browser(restore_session=True)
            restarted = True
            self.wait_ready("Chromium", self.browser_ready, timeout=remaining(10), require_browser=False)
            windows = control_phase("inspect", self.browser_windows)
        elif command == "ensure" and not windows:
            if not running:
                if browser is not None:
                    browser.wait()
                self.children = [(name, child) for name, child in self.children if name != "Chromium"]
                remaining(25)
                self.start_browser(restore_session=True)
                restarted = True
                self.wait_ready("Chromium", self.browser_ready, timeout=remaining(10), require_browser=False)
                windows = control_phase("inspect", self.browser_windows)
            # A live background browser with zero confirmed windows is handled
            # by the authenticated extension's fixed windows.create operation.
        elif command == "maximize":
            remaining(25)
            if len(windows) != 1:
                raise BrowserUnavailable("One browser window is required.")
            control_phase("maximize", lambda: self.restore_browser(budget=remaining))
            windows = control_phase("inspect", self.browser_windows)
            if len(windows) != 1:
                raise BrowserUnavailable("Browser windows changed.")
            remaining(25)
            try:
                engine_ready = self.proxy_ready()
            except (OSError, ValueError, subprocess.SubprocessError):
                engine_ready = False
            self.browser_crash_recovery = not engine_ready
            self.browser_closed_reported = False
            self.write_status("ready" if engine_ready else "recovering",
                              "Desktop is ready." if engine_ready else "Browser restored; engine reconnecting.")
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        response = {"ok": True, "command": command, "request_id": request_id,
                    "browser_epoch": self.browser_epoch, "process_running": browser is not None and browser.poll() is None,
                    "window_count": len(windows), "engine_ready": bool(engine_ready), "restarted": restarted}
        if geometry is not None:
            response.update(display_width=geometry["width"], display_height=geometry["height"])
        return response

    def open_control(self):
        if RECONNECT_PATH.is_symlink():
            raise RuntimeError("Refusing symbolic link at reconnect socket")
        RECONNECT_PATH.unlink(missing_ok=True)
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(str(RECONNECT_PATH))
        RECONNECT_PATH.chmod(0o600)
        self.control.listen(8)
        self.control.settimeout(0.5)

    def serve_control(self):
        try:
            connection, _ = self.control.accept()
        except socket.timeout:
            return
        with connection:
            connection.settimeout(1)
            message = None
            try:
                payload = b""
                while b"\n" not in payload and len(payload) <= 512:
                    part = connection.recv(513 - len(payload))
                    if not part:
                        break
                    payload += part
                if len(payload) > 512 or not payload.endswith(b"\n"):
                    raise ValueError("Unsupported runtime command")
                message = json.loads(payload)
                if not isinstance(message, dict):
                    raise ValueError("Unsupported runtime command")
                try:
                    # Legacy internal reconnect remains non-destructive; the
                    # public API now sends explicit ensure/restart commands.
                    response = (self.reconnect(allow_extension_retry=True)
                                if message == {"command": "reconnect"} else self.browser_control(message, lambda: control_request_live(connection)))
                except InterruptedError:
                    raise
                except Exception as error:
                    response = control_failure(message, error)
                    self.write_status("failed", response["error"])
                connection.sendall(json.dumps(response).encode() + b"\n")
            except (ValueError, OSError) as error:
                try:
                    connection.sendall(json.dumps(control_failure(message, error)).encode() + b"\n")
                except OSError:
                    pass

    def prepare_profile_gateway(self):
        if self.fido_control is None:
            return {}, None
        additions, endpoint = self.fido_control.prepare_child("gateway")
        self.fido_control.channel_started("gateway")
        return {"fido_gateway_epoch": additions["AUTH_BROWSER_FIDO_GATEWAY_EPOCH"]}, endpoint

    def stop_profile(self):
        """Disable a desktop without deleting data or hard-killing a live browser."""
        if self.fido_control is not None:
            self.fido_control.retire("gateway")
        # A singleton launcher can become the primary after the prior process
        # exits. Do not let generic desktop teardown signal that live browser
        # before its ownership and private close can be confirmed.
        if any(name == "Chromium window launcher" and child.poll() is None
               for name, child in self.children):
            raise BrowserUnavailable("Browser launcher is still active.")
        browser = next((child for name, child in self.children if name == "Chromium"), None)
        if browser is not None and browser.poll() is None:
            if self.browser_pipe is None or browser is not self.browser_pipe_process:
                raise BrowserUnavailable("Owned browser close is unavailable.")
            try:
                self.browser_pipe.close_browser(timeout=2)
            except (OSError, ValueError, _browser_cdp.BrowserPipeError):
                pass
            deadline = time.monotonic() + 8
            while browser.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if browser.poll() is None:
                raise BrowserUnavailable("Browser did not finish closing.")
        self.release_browser_pipe()
        self.shutdown(desktop_only=True)
        self.stopping = True

    def serve_profile_control(self):
        wire = _profile_modules["profile_wire"]
        try:
            message, rights = wire.receive(self.profile_control)
        except BlockingIOError:
            return
        except (OSError, ValueError):
            self.stopping = True
            return
        wire.close_rights(rights)
        endpoint = None
        response = {"ok": False, "error": "profile_command_failed"}
        try:
            if message.get("action") == "gateway_lost" and set(message) == {"action"}:
                if self.fido_control is not None:
                    self.fido_control.retire("gateway")
                self.profile_gateway_token = None
                self.profile_engine_pending = True
                self.write_status("recovering", "Profile engine reconnecting.")
                response = {"ok": True}
            elif message.get("action") == "gateway" and set(message) == {"action", "token"}:
                if not re.fullmatch(r"[0-9a-f]{64}", message.get("token", "")):
                    raise ValueError("Invalid gateway capability")
                self.profile_gateway_token = message["token"]
                self.profile_engine_pending = True
                response, endpoint = self.prepare_profile_gateway()
                response.update(ok=True, runtime_epoch=self.profile_epoch)
            elif message == {"action": "stop"}:
                self.stop_profile()
                response = {"ok": True, "stopped": True}
            else:
                raise ValueError("Unsupported profile command")
        except (OSError, ValueError, BrowserUnavailable):
            pass
        try:
            wire.send(self.profile_control, response, endpoint.fileno() if endpoint else None)
        finally:
            if endpoint is not None:
                endpoint.close()

    def run_profile(self, fd):
        if os.getuid() == 0:
            raise RuntimeError("Profile workers must be non-root")
        context = _profile_modules["profile_context"]
        paths = context.ProfilePaths(PROFILE_ID, int(os.environ["AUTH_BROWSER_PROFILE_SLOT"]))
        expected = paths.environment({})
        for key in ("DISPLAY", "AUTH_BROWSER_PROFILE_RUNTIME_DIR", "AUTH_BROWSER_PROFILE_DATA_DIR",
                    "AUTH_BROWSER_PROFILE_VNC_PORT", "AUTH_BROWSER_PROXY_SOCKET", "HOME",
                    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                    "DBUS_SYSTEM_BUS_ADDRESS", "DBUS_SESSION_BUS_ADDRESS"):
            if os.environ.get(key) != expected[key]:
                raise ValueError("Profile environment does not match its immutable identity")
        paths.prepare()
        wire = _profile_modules["profile_wire"]
        channel = socket.socket(fileno=fd)
        if channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            channel.close()
            raise ValueError("Invalid profile management channel")
        channel.set_inheritable(False)
        channel.settimeout(5)
        initial, rights = wire.receive(channel)
        wire.close_rights(rights)
        if set(initial) != {"action", "token"} or initial.get("action") != "start" or not re.fullmatch(r"[0-9a-f]{64}", initial.get("token", "")):
            raise ValueError("Invalid profile startup")
        self.profile_gateway_token = initial["token"]
        # Copy the fixed packaged policy, replacing its one listen endpoint only.
        # Canonical profile IDs cannot inject XML or D-Bus address syntax.
        policy = Path(__file__).with_name("dbus-system.conf").read_text()
        policy = policy.replace("unix:path=/data/run/dbus-system.sock", f"unix:path={RUN_PATH}/dbus-system.sock")
        policy_path = RUN_PATH / "dbus-system.conf"
        if policy_path.is_symlink():
            raise ValueError("Unsafe profile D-Bus policy")
        policy_path.write_text(policy)
        policy_path.chmod(0o600)
        self.open_control()
        self.write_status("starting", "Profile desktop is starting.")
        reply, endpoint = self.prepare_profile_gateway()
        self.profile_deadline = time.monotonic() + 40
        try:
            # The gateway binds the proxy listener after receiving this reply.
            # Window existence is a startup fact, never an engine-ready claim.
            self.start_desktop(wait_engine=False)
            self.profile_deadline = None
            reply.update(ok=True, runtime_epoch=self.profile_epoch, engine_ready=False)
            wire.send(channel, reply, endpoint.fileno() if endpoint else None)
        except Exception:
            wire.send(channel, {"ok": False, "error": "profile_start_failed"})
            raise
        finally:
            if endpoint is not None:
                endpoint.close()
        channel.setblocking(False)
        self.profile_control = channel
        self.profile_engine_pending = True
        self.write_status("recovering", "Profile started; engine connecting.")
        try:
            while not self.stopping:
                self.check_children(require_browser=False)
                self.maintain_browser()
                self.serve_control()
        finally:
            channel.close()
            self.profile_control = None

    def browser_unavailable(self, error):
        self.write_status("failed", str(error))
        self.browser_closed_reported = True
        print(f"[supervisor] Browser unavailable; reconnect can retry: {error}", file=sys.stderr, flush=True)

    def run(self):
        if os.getuid() == 0:
            raise RuntimeError("Run this image as its built-in non-root user.")
        os.umask(0o077)
        for path in ("/data/run", "/data/chromium", "/data/config"):
            Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)
        prepare_cache_dir()
        os.environ.update({
            "HOME": "/data", "DISPLAY": ":99", "XDG_RUNTIME_DIR": "/data/run",
            "XDG_CONFIG_HOME": "/data/config", "XDG_CACHE_HOME": str(CACHE_PATH),
            "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/data/run/dbus-system.sock",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/data/run/dbus-session.sock",
        })
        self.write_status("starting", "Desktop is starting; settings are available.")
        self.open_control()
        self.spawn("gateway", ["/usr/local/bin/webauthn-browser"])
        self.gateway_started = True
        try:
            self.start_desktop()
            self.write_status("ready", "Desktop is ready.")
            print("[supervisor] Desktop ready; gateway on port 8080", flush=True)
        except InterruptedError:
            raise
        except BrowserUnavailable as error:
            self.browser_unavailable(error)
        except Exception as error:
            self.desktop_failed(error)
        while True:
            try:
                self.check_children(require_browser=False)
            except BrowserUnavailable as error:
                self.browser_unavailable(error)
            except RuntimeError as error:
                if any(name == "gateway" and child.poll() is not None for name, child in self.children):
                    raise
                self.desktop_failed(error)
            self.maintain_browser()
            self.serve_control()

    def desktop_failed(self, error):
        # Never turn a crashed desktop into a healthy container or restart loop.
        # Preserve the gateway's normal authentication and export protections.
        print(f"[supervisor] Desktop unavailable: {error}", file=sys.stderr, flush=True)
        self.write_status("failed", str(error))
        self.shutdown(desktop_only=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run the WebAuthn Browser desktop and management gateway")
    parser.add_argument("--no-sandbox", action="store_true", help="Explicitly disable Chromium sandbox (unsafe for untrusted content)")
    parser.add_argument("--profile-worker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main():
    args = parse_args()
    if not args.profile_worker:
        spec = importlib.util.spec_from_file_location("auth_browser_profile_manager", Path(__file__).with_name("profile_manager.py"))
        manager = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = manager
        spec.loader.exec_module(manager)
        return manager.main(no_sandbox=args.no_sandbox)
    descriptor = os.environ.pop("AUTH_BROWSER_PROFILE_WORKER_FD", "")
    if not descriptor.isdecimal() or int(descriptor) < 3:
        raise ValueError("Profile worker requires its inherited management channel")
    supervisor = Supervisor(no_sandbox=args.no_sandbox)
    signal.signal(signal.SIGTERM, supervisor.request_stop)
    signal.signal(signal.SIGINT, supervisor.request_stop)
    result = 0
    try:
        supervisor.run_profile(int(descriptor))
    except InterruptedError:
        print("[supervisor] Shutting down", flush=True)
    except Exception as error:
        print(f"[supervisor] FATAL: {error}", file=sys.stderr, flush=True)
        result = 1
    finally:
        supervisor.shutdown()
        if result:
            # Emit this reserved code only after all owned-service cleanup has
            # returned. A killed worker cannot accidentally free its old slot.
            result = _profile_modules["profile_context"].CLEAN_FAILURE_EXIT
    return result


if __name__ == "__main__":
    sys.exit(main())
