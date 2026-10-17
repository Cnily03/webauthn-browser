#!/usr/bin/env python3
"""Demand-driven text clipboard. Never stores a last clipboard value.

The X CLIPBOARD owner answers each data conversion with a new outer-browser
read. Only request-scoped wire/INCR buffers exist, and are dropped on completion,
revocation, timeout, or disconnect. PRIMARY is intentionally not mirrored.
"""
import json
import os
from pathlib import Path
import select
import signal
import socket
import time
import uuid

MAX_TEXT = 1024 * 1024
MAX_WIRE = 6 * MAX_TEXT + 1024
TIMEOUT = 30
MAX_PENDING = 16
CHUNK = 64 * 1024
SOCKET_PATH = Path(os.environ.get('AUTH_BROWSER_PROFILE_RUNTIME_DIR', '/data/run')) / 'clipboard.sock'


def text_bytes(value):
    if not isinstance(value, str):
        raise ValueError('text required')
    data = value.encode('utf-8', errors='strict')
    if len(data) > MAX_TEXT:
        raise ValueError('text too large')
    return data


class Requests:
    """Metadata-only pending reads; never retains successful result payloads."""
    def __init__(self, send, answer, clock=time.monotonic):
        self.pending = {}
        self.send = send
        self.answer = answer
        self.clock = clock

    def request(self, event):
        # The active outer page processes one permission/read operation at a time.
        # A newer paste invalidates the previous request rather than replaying it.
        self.expire(all_requests=True)
        if len(self.pending) >= MAX_PENDING:
            self.answer(event, None)
            return
        key = str(uuid.uuid4())
        self.pending[key] = (event, self.clock() + TIMEOUT)
        if not self.send({'type': 'read', 'id': key}):
            item = self.pending.pop(key, None)
            if item:
                self.answer(item[0], None)

    def result(self, message):
        key = message.get('id')
        if not isinstance(key, str) or len(key) > 128:
            return
        item = self.pending.pop(key, None)
        if item is None:
            return
        event, deadline = item
        data = None
        if self.clock() < deadline and 'error' not in message:
            try:
                data = text_bytes(message.get('text'))
            except (ValueError, UnicodeError):
                pass
        self.answer(event, data)

    def expire(self, all_requests=False):
        for key, (event, deadline) in list(self.pending.items()):
            if all_requests or self.clock() >= deadline:
                self.pending.pop(key, None)
                self.answer(event, None)
                self.send({'type': 'cancel', 'id': key})


class Bridge:
    def __init__(self):
        # Imported only in the runtime, allowing dependency-free state tests.
        from Xlib import X, Xatom, display, protocol, error
        from Xlib.ext import xfixes
        self.X, self.Xatom, self.protocol, self.xfixes = X, Xatom, protocol, xfixes
        self.display = display.Display()
        self.XError = error.XError
        # Requestor windows may disappear between selection events. These
        # asynchronous protocol errors must not kill the desktop supervisor.
        self.display.set_error_handler(lambda _error, _request: None)
        if not self.display.has_extension('XFIXES'):
            raise RuntimeError('XFIXES is required for clipboard synchronization')
        self.display.xfixes_query_version()
        self.root = self.display.screen().root
        self.window = self.new_window()
        self.atoms = {name: self.display.intern_atom(name) for name in (
            'CLIPBOARD', 'TARGETS', 'UTF8_STRING', 'text/plain;charset=utf-8',
            'text/plain', 'STRING', 'INCR', '_AUTH_BROWSER_COPY')}
        self.clipboard = self.atoms['CLIPBOARD']
        self.display.xfixes_select_selection_input(self.window, self.clipboard, 7)
        self.client = None
        self.input = bytearray()
        self.output = bytearray()
        self.output_deadline = None
        self.input_deadline = None
        self.capture = None
        self.transfers = {}
        self.requests = Requests(self.send, self.answer)
        self.stopping = False
        self.own()
        self.display.sync()

    def new_window(self):
        return self.root.create_window(0, 0, 1, 1, 0, self.X.CopyFromParent,
                                       event_mask=self.X.PropertyChangeMask)

    def own(self):
        self.window.set_selection_owner(self.clipboard, self.X.CurrentTime)
        self.display.flush()

    def send(self, message):
        if self.client is None:
            return False
        encoded = json.dumps(message, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
        if len(self.output) + len(encoded) > MAX_WIRE:
            self.disconnect()
            return False
        if not self.output:
            self.output_deadline = time.monotonic() + TIMEOUT
        self.output.extend(encoded)
        return True

    def disconnect(self):
        client, self.client = self.client, None
        if client:
            client.close()
        self.input.clear()
        self.output.clear()
        self.output_deadline = None
        self.input_deadline = None
        self.requests.expire(all_requests=True)
        # Delete request-scoped INCR data, terminating any active transfer empty.
        for key, transfer in list(self.transfers.items()):
            self.finish_transfer(key, transfer)
        self.drop_capture()
        self.own()

    def notify(self, event, property_atom):
        event.requestor.send_event(self.protocol.event.SelectionNotify(
            time=event.time, requestor=event.requestor, selection=event.selection,
            target=event.target, property=property_atom), propagate=False)
        self.display.flush()

    def answer(self, event, data):
        prop = event.property or event.target
        if data is None:
            self.notify(event, self.X.NONE)
            return
        if event.target == self.atoms['STRING']:
            # STRING is ISO-8859-1, not UTF-8. Never silently corrupt Unicode.
            try:
                data = data.decode('utf-8').encode('latin-1')
            except UnicodeError:
                self.notify(event, self.X.NONE)
                return
        if len(data) <= CHUNK:
            event.requestor.change_property(prop, event.target, 8, data)
            self.notify(event, prop)
        else:
            key = (event.requestor.id, prop)
            if len(self.transfers) >= MAX_PENDING or key in self.transfers:
                self.notify(event, self.X.NONE)
                return
            event.requestor.change_attributes(event_mask=self.X.PropertyChangeMask)
            self.transfers[key] = (event.requestor, prop, event.target, data, time.monotonic() + TIMEOUT)
            event.requestor.change_property(prop, self.atoms['INCR'], 32, [len(data)])
            self.notify(event, prop)

    def finish_transfer(self, key, transfer):
        self.transfers.pop(key, None)
        window, prop, target, _, _ = transfer
        window.change_property(prop, target, 8, b'')
        self.display.flush()

    def selection_request(self, event):
        if event.selection != self.clipboard:
            self.notify(event, self.X.NONE)
        elif event.target == self.atoms['TARGETS']:
            # Chromium queries available types when opening its native menu.
            # Metadata never triggers clipboard reads or permission prompts.
            prop = event.property or event.target
            names = ('TARGETS', 'UTF8_STRING', 'text/plain;charset=utf-8', 'text/plain', 'STRING')
            event.requestor.change_property(prop, self.Xatom.ATOM, 32,
                                             [self.atoms[name] for name in names])
            self.notify(event, prop)
        elif event.target in [self.atoms[name] for name in ('UTF8_STRING', 'text/plain;charset=utf-8', 'text/plain', 'STRING')]:
            # A newer paste supersedes an unfinished remote copy capture.
            # Do not deliver late source text over the user's newly read value.
            self.drop_capture()
            self.requests.request(event)
        else:
            self.notify(event, self.X.NONE)

    def drop_capture(self):
        if self.capture:
            self.capture['window'].destroy()
            self.capture = None

    def fail_capture(self, error='unavailable'):
        if self.capture:
            self.send({'type': 'copy_failed', 'id': str(uuid.uuid4()), 'error': error})
            self.drop_capture()

    def remote_copy(self, event):
        owner_id = getattr(event.owner, 'id', event.owner)
        if owner_id == self.window.id:
            return
        # Queued ownership notifications can be superseded by another copy or
        # our own reclaim. Never convert our own selection back into a copy.
        current = self.display.get_selection_owner(self.clipboard)
        current_id = getattr(current, 'id', current)
        if current_id != owner_id:
            return
        self.requests.expire(all_requests=True)
        for key, transfer in list(self.transfers.items()):
            self.finish_transfer(key, transfer)
        self.drop_capture()
        if owner_id and self.client:
            window = self.new_window()
            self.capture = {'window': window, 'data': bytearray(), 'incr': False,
                            'deadline': time.monotonic() + TIMEOUT}
            window.convert_selection(self.clipboard, self.atoms['UTF8_STRING'],
                                     self.atoms['_AUTH_BROWSER_COPY'], self.X.CurrentTime)
        # ConvertSelection precedes SelectionClear on the source's event queue.
        # Reclaim immediately so Chromium cannot bypass us using its local data.
        self.own()

    def capture_property(self, incremental=False):
        capture = self.capture
        if not capture:
            return
        prop = self.atoms['_AUTH_BROWSER_COPY']
        value = capture['window'].get_property(prop, self.X.AnyPropertyType, 0,
                                               MAX_TEXT // 4 + 1, delete=True)
        if value is None:
            return
        if value.property_type == self.atoms['INCR'] and not incremental:
            capture['incr'] = True
            capture['window'].delete_property(prop)
            self.display.flush()
            return
        if value.bytes_after:
            self.fail_capture('too_large')
            return
        if value.format != 8 or value.property_type not in (
                self.atoms['UTF8_STRING'], self.atoms['text/plain;charset=utf-8'], self.atoms['text/plain']):
            self.fail_capture()
            return
        chunk = bytes(value.value)
        if len(capture['data']) + len(chunk) > MAX_TEXT:
            self.fail_capture('too_large')
            return
        capture['data'].extend(chunk)
        if not incremental or not chunk:
            try:
                text = capture['data'].decode('utf-8', errors='strict')
                self.send({'type': 'copy', 'id': str(uuid.uuid4()), 'text': text})
            except UnicodeError:
                self.fail_capture()
            self.drop_capture()
        self.display.flush()

    def event(self, event):
        X = self.X
        if isinstance(event, self.xfixes.SelectionNotify):
            if event.selection == self.clipboard:
                self.remote_copy(event)
        elif event.type == X.SelectionRequest:
            self.selection_request(event)
        elif event.type == X.SelectionNotify:
            if self.capture and event.requestor.id == self.capture['window'].id:
                if event.property:
                    self.capture_property()
                else:
                    self.fail_capture()
        elif event.type == X.PropertyNotify:
            if (self.capture and self.capture['incr'] and
                    event.window.id == self.capture['window'].id and
                    event.atom == self.atoms['_AUTH_BROWSER_COPY'] and event.state == X.PropertyNewValue):
                self.capture_property(incremental=True)
            key = (event.window.id, event.atom)
            transfer = self.transfers.get(key)
            if transfer and event.state == X.PropertyDelete:
                window, prop, target, data, deadline = transfer
                if not data or time.monotonic() >= deadline:
                    self.finish_transfer(key, transfer)
                else:
                    window.change_property(prop, target, 8, data[:CHUNK])
                    self.transfers[key] = (window, prop, target, data[CHUNK:], deadline)
                    self.display.flush()

    def receive(self):
        try:
            chunk = self.client.recv(65536)
            if not chunk:
                self.disconnect()
                return
            if not self.input:
                self.input_deadline = time.monotonic() + TIMEOUT
            self.input.extend(chunk)
            if len(self.input) > MAX_WIRE:
                self.disconnect()
                return
            while b'\n' in self.input:
                line, _, remaining = self.input.partition(b'\n')
                self.input = bytearray(remaining)
                self.input_deadline = time.monotonic() + TIMEOUT if remaining else None
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError('invalid message')
                if message.get('type') == 'read_result':
                    self.requests.result(message)
                elif message.get('type') != 'copy_result':
                    raise ValueError('unsupported message')
        except (OSError, ValueError, UnicodeError):
            self.disconnect()

    def run(self, path=SOCKET_PATH):
        if path.is_symlink():
            raise RuntimeError('Refusing symbolic link at clipboard socket')
        path.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        path.chmod(0o600)
        server.listen(4)
        server.setblocking(False)
        try:
            while not self.stopping:
                while self.display.pending_events():
                    try:
                        self.event(self.display.next_event())
                    except self.XError:
                        # A synchronous property read can race a destroyed window.
                        self.fail_capture()
                self.requests.expire()
                if any(deadline is not None and time.monotonic() >= deadline
                       for deadline in (self.input_deadline, self.output_deadline)):
                    self.disconnect()
                if self.capture and time.monotonic() >= self.capture['deadline']:
                    self.fail_capture()
                for key, transfer in list(self.transfers.items()):
                    if time.monotonic() >= transfer[4]:
                        self.finish_transfer(key, transfer)
                reads = [server, self.display]
                if self.client:
                    reads.append(self.client)
                ready, writable, _ = select.select(reads, [self.client] if self.client and self.output else [], [], .1)
                if server in ready:
                    client, _ = server.accept()
                    client.setblocking(False)
                    if self.client:
                        client.close()  # Single controller, never broadcast private text.
                    else:
                        self.client = client
                        self.own()
                if self.client in ready:
                    self.receive()
                if self.client in writable and self.output:
                    try:
                        count = self.client.send(self.output)
                        del self.output[:count]
                        if not self.output:
                            self.output_deadline = None
                    except BlockingIOError:
                        pass
                    except OSError:
                        self.disconnect()
        finally:
            self.disconnect()
            server.close()
            path.unlink(missing_ok=True)
            self.window.destroy()
            self.display.close()


def main():
    os.umask(0o077)
    bridge = Bridge()
    def stop(_signum, _frame):
        bridge.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    bridge.run()


if __name__ == '__main__':
    main()
