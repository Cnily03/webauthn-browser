"""Owned Chromium shutdown over private inherited pipes, never a TCP debugger.

Only version readiness and graceful whole-browser close are exposed. Pipe EOF
can itself terminate Chromium: timeouts must retain the controller until the
owned process has exited, rather than accidentally turning a probe into a close.
"""
import fcntl
import json
import math
import os
import select
import signal
import subprocess
import threading
import time

MAX_MESSAGE = 64 * 1024
MAX_EXCHANGE_BYTES = 256 * 1024
MAX_IGNORED_MESSAGES = 64


class BrowserPipeError(RuntimeError):
    pass


class OwnedProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        if self.returncode is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned Chromium", timeout)
            time.sleep(0.01)
        return self.returncode

    def send_signal(self, sig):
        if self.poll() is None:
            os.kill(self.pid, sig)

    def terminate(self):
        self.send_signal(signal.SIGTERM)


class BrowserPipe:
    def __init__(self, process, request, response):
        self._process = process
        self._request = request
        self._response = response
        self._buffer = bytearray()
        self._next_id = 0
        self._lock = threading.Lock()
        self._disposed = False
        self._close_sent = False
        os.set_blocking(request, False)
        os.set_blocking(response, False)

    def get_version(self, timeout=2):
        result = self._exchange("Browser.getVersion", timeout)
        if not isinstance(result, dict) or not isinstance(result.get("product"), str):
            raise BrowserPipeError("Browser readiness response was invalid")
        return result

    def close_browser(self, timeout=2):
        # A timed-out request must not be retransmitted: it may already be
        # closing the browser. The supervisor decides success from process exit.
        with self._lock:
            if self._close_sent:
                raise BrowserPipeError("Browser close was already requested")
            self._close_sent = True
            return self._exchange_locked("Browser.close", timeout)

    def _exchange(self, method, timeout):
        with self._lock:
            if self._close_sent:
                raise BrowserPipeError("Browser close is already in progress")
            return self._exchange_locked(method, timeout)

    def _exchange_locked(self, method, timeout):
        if self._disposed or self._process.poll() is not None:
            raise BrowserPipeError("Browser control is unavailable")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 10:
            raise ValueError("Invalid browser control timeout")
        self._next_id += 1
        request_id = self._next_id
        encoded = json.dumps({"id": request_id, "method": method}, separators=(",", ":")).encode() + b"\0"
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(encoded):
            self._ready(deadline, writing=True)
            try:
                offset += os.write(self._request, encoded[offset:])
            except BlockingIOError:
                continue
            except OSError:
                raise BrowserPipeError("Browser control write failed") from None
        total = len(self._buffer)
        ignored = 0
        while True:
            delimiter = self._buffer.find(0)
            if delimiter >= 0:
                raw = bytes(self._buffer[:delimiter])
                del self._buffer[:delimiter + 1]
                if len(raw) > MAX_MESSAGE:
                    raise BrowserPipeError("Browser control response exceeded its limit")
                try:
                    message = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise BrowserPipeError("Browser control response was invalid") from None
                if not isinstance(message, dict):
                    raise BrowserPipeError("Browser control response was invalid")
                if type(message.get("id")) is int and message["id"] == request_id:
                    if "error" in message or not isinstance(message.get("result"), dict):
                        raise BrowserPipeError("Browser control command failed")
                    return message["result"]
                ignored += 1
                if ignored > MAX_IGNORED_MESSAGES:
                    raise BrowserPipeError("Browser control response exceeded its limit")
                continue
            if len(self._buffer) > MAX_MESSAGE:
                raise BrowserPipeError("Browser control response exceeded its limit")
            self._ready(deadline, writing=False)
            try:
                chunk = os.read(self._response, 8192)
            except BlockingIOError:
                continue
            except OSError:
                raise BrowserPipeError("Browser control read failed") from None
            if not chunk:
                raise BrowserPipeError("Browser control closed")
            total += len(chunk)
            if total > MAX_EXCHANGE_BYTES:
                raise BrowserPipeError("Browser control response exceeded its limit")
            self._buffer.extend(chunk)

    def _ready(self, deadline, *, writing):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserPipeError("Browser control timed out")
        try:
            poller = select.poll()
            poller.register(self._request if writing else self._response,
                            select.POLLOUT if writing else select.POLLIN)
            events = poller.poll(math.ceil(remaining * 1000))
        except OSError:
            raise BrowserPipeError("Browser control pipe failed") from None
        if not events:
            raise BrowserPipeError("Browser control timed out")
        if any(flags & select.POLLNVAL for _, flags in events):
            raise BrowserPipeError("Browser control pipe failed")

    def dispose_after_exit(self):
        with self._lock:
            if self._disposed:
                return
            if self._process.poll() is None:
                raise BrowserPipeError("Cannot dispose live browser control")
            self._disposed = True
            os.close(self._request)
            os.close(self._response)
            self._buffer.clear()


def spawn(command, environment, inherited_fds=None):
    """Map fd3/fd4 and explicit capabilities only in the new child.

    posix_spawn file actions avoid parent fd mutation and Python preexec code.
    Native Chromium must be passed by the caller; shell wrappers are not used.
    Returned process ownership is retained by the supervisor, not this module.
    """
    inherited_fds = {} if inherited_fds is None else dict(inherited_fds)
    if not command or not os.path.isabs(command[0]):
        raise ValueError("Browser executable must be absolute")
    if set(inherited_fds) - {"UHF_CONTROL_FD"}:
        raise ValueError("Unsupported browser capability")
    if any(type(fd) is not int or fd < 0 for fd in inherited_fds.values()):
        raise ValueError("Invalid browser capability descriptor")
    allocated = []
    process = None
    try:
        request_read, request_write = os.pipe2(os.O_CLOEXEC)
        allocated.extend((request_read, request_write))
        response_read, response_write = os.pipe2(os.O_CLOEXEC)
        allocated.extend((response_read, response_write))

        def duplicate(fd):
            copy = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64)
            allocated.append(copy)
            return copy

        # All sources are distinct and above fixed Chromium fd3/fd4, even
        # when the inherited capability or original pipe end occupied them.
        actions = [(os.POSIX_SPAWN_DUP2, duplicate(request_read), 3),
                   (os.POSIX_SPAWN_DUP2, duplicate(response_write), 4)]
        keep = {0, 1, 2, 3, 4}
        child_env = dict(environment)
        child_env.pop("UHF_CONTROL_FD", None)
        for key, fd in inherited_fds.items():
            source = duplicate(fd)
            target = duplicate(fd)
            actions.append((os.POSIX_SPAWN_DUP2, source, target))
            keep.add(target)
            child_env[key] = str(target)
        # Explicit close actions also remove unrelated inheritable descriptors;
        # CLOEXEC alone is not sufficient to assert least-capability inheritance.
        for fd in sorted(int(name) for name in os.listdir("/proc/self/fd") if name.isdigit()):
            if fd not in keep:
                try:
                    fcntl.fcntl(fd, fcntl.F_GETFD)
                except OSError:
                    continue
                actions.append((os.POSIX_SPAWN_CLOSE, fd))
        # A dedicated process group preserves supervisor group ownership without
        # requiring a setsid extension unavailable in some Python builds.
        pid = os.posix_spawn(command[0], command, child_env, file_actions=actions,
                             setpgroup=0, setsigdef=(signal.SIGPIPE,))
        process = OwnedProcess(pid)
        controller = BrowserPipe(process, request_write, response_read)
        allocated.remove(request_write)
        allocated.remove(response_read)
        return process, controller
    finally:
        for fd in allocated:
            os.close(fd)
