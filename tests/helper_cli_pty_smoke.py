"""Real POSIX PTY + WebSocket tests for the helper's inline consent panel.

Requires Python websockets; test D-Bus is absent and --disable-usb prevents HID discovery.
The timeout case intentionally waits for the real 60-second prompt deadline.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time
from websockets.sync.client import connect

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
ORIGIN = 'https://example.test:8443'

class Cli:
    def __init__(self, binary, no_color=False, columns=100, channel_flags=("--disable-usb",)):
        self.temp = tempfile.TemporaryDirectory(prefix='helper-pty-')
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, columns, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        env = dict(os.environ, TERM='xterm-256color', HOME=self.temp.name,
                   XDG_CONFIG_HOME=self.temp.name, APPDATA=self.temp.name,
                   DBUS_SYSTEM_BUS_ADDRESS='unix:path=/nonexistent-helper-pty-bus')
        if no_color:
            env['NO_COLOR'] = '1'
        else:
            env.pop('NO_COLOR', None)
        def child_terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            address = f'127.0.0.1:{port.getsockname()[1]}'
        self.process = subprocess.Popen([str(binary), *channel_flags, '--listen', address], stdin=self.slave,
            stdout=self.slave, stderr=self.slave, env=env, preexec_fn=child_terminal)
        self.output = b''
        self.counter = 0
        self.until(b'Listening: ')
        self.pump(.05)
        match = re.search(rb'Listening: (ws://127\.0\.0\.1:\d+)', self.plain())
        assert match, self.output
        self.url = match.group(1).decode()
        assert re.search(rb'\d{4}-\d{2}-\d{2}T\S+Z +INFO Listening:', self.plain())
    def plain(self):
        return ANSI.sub(b'', self.output)
    def pump(self, seconds=.1):
        end = time.monotonic()+seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], min(.03,max(0,end-time.monotonic())))
            if ready:
                try:
                    data = os.read(self.master, 65536)
                except OSError as e:
                    if e.errno == errno.EIO: break
                    raise
                if not data: break
                self.output += data
    def until(self, text, after=0, timeout=5):
        end = time.monotonic()+timeout
        while text not in self.plain()[after:]:
            self.pump(.03)
            assert self.process.poll() is None, self.output.decode(errors='replace')
            assert time.monotonic()<end, (text, self.output.decode(errors='replace'))
        return self.plain()[after:]
    def write(self, data):
        os.write(self.master, data)
    def pair(self, origin=ORIGIN, session=None):
        self.counter += 1
        ws = connect(self.url, origin=origin, proxy=None, open_timeout=3, close_timeout=2)
        payload = {'type':'pair','token':f'NeverLogPtyPairingToken{self.counter:020d}'}
        if session:
            payload['session_id'] = session
        ws.send(json.dumps(payload))
        return ws
    def panel(self, origin=ORIGIN, after=0):
        self.until(('Browser Origin: '+origin).encode(), after)
        self.until(b'Left/Right or Tab, then Enter', after)
        self.pump(.08)  # Publication and post-draw stale-input drain complete.
        attrs = termios.tcgetattr(self.slave)
        assert not attrs[3] & termios.ICANON
        assert not attrs[3] & termios.ECHO
    def restored(self):
        self.pump(.12)
        assert termios.tcgetattr(self.slave) == self.before
        assert b'\x1b[?25h' in self.output, 'cursor not restored'
    def close(self, keys=b'quit\n'):
        if self.process.poll() is None:
            self.write(keys)
            self.process.wait(timeout=8)
        self.pump(.05)
        assert self.process.returncode == 0, self.output
        assert termios.tcgetattr(self.slave) == self.before
        assert b'NeverLogPtyPairingToken' not in self.output
        assert not list(Path(self.temp.name).iterdir())
        # No alternate screen, full-screen erase, or scrollback erasure.
        for forbidden in [b'\x1b[?1049h', b'\x1b[2J', b'\x1b[3J']:
            assert forbidden not in self.output
        os.close(self.master)
        os.close(self.slave)
        self.temp.cleanup()
    def cleanup(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)
        self.temp.cleanup()

def outcome(ws, state, allow_ble=False):
    value=json.loads(ws.recv(timeout=4))
    while allow_ble and value.get('type') == 'status' and value.get('state') in ('error', 'scanning', 'stopped'):
        value=json.loads(ws.recv(timeout=4))
    assert value['type']=='status' and value['state']==state, value

def normal_and_keyboard(binary):
    cli=Cli(binary)
    try:
        first=cli.pair();cli.panel();assert b'Approve pairing and BLE for this origin?' in cli.plain();assert re.search(rb'\x1b\[(?:38;5;14|36)m> \[ Approve \]',cli.output), 'Selected Approve is not cyan';assert b'\x1b[38;5;13m' in cli.output or b'\x1b[35m' in cli.output
        cli.write(b'\r');outcome(first,'paired');cli.until(b'Connected: '+ORIGIN.encode());cli.restored()
        assert cli.plain().count(b'Approved: '+ORIGIN.encode()) == 1
        assert re.search(rb'\x1b\[[0-9;]+mApproved\x1b\[[0-9;]+m:',cli.output), 'Approved word is not library-colored'
        cli.until(b'BLE: starting')
        cli.until(b'BLE: unavailable')
        for state in [b'starting', b'unavailable']:
            assert cli.plain().count(b'BLE: '+state) == 1, cli.output
            assert re.search(rb'BLE: \x1b\[[0-9;]+m'+state+rb'\x1b\[[0-9;]+m', cli.output), 'BLE state is not library-colored'
        first.close();cli.until(b'Disconnected: '+ORIGIN.encode());cli.pump(.15)
        assert re.search(rb'\x1b\[[0-9;]+mDisconnected\x1b\[[0-9;]+m:',cli.output), 'Disconnected word is not library-colored'
        panels=cli.plain().count(b'Browser Origin:')
        second=cli.pair();outcome(second,'paired');cli.until(b'(remembered process Origin)');cli.pump(.1)
        assert cli.plain().count(b'Browser Origin:') == panels
        assert cli.plain().count(b'Connected: '+ORIGIN.encode()) == 2
        second.close();cli.pump(.2)
        for index,keys,allow in [(1,b'\x1b[C\r',False),(2,b'\x1b[C\x1b[D\r',True),(3,b'\t\r',False),(4,b'\t\t\r',True)]:
            origin=f'https://choice{index}.example.test';mark=len(cli.plain());ws=cli.pair(origin);cli.panel(origin,mark)
            cli.write(keys);outcome(ws,'paired' if allow else 'closed')
            cli.until(('Approved: ' if allow else 'Rejected: ').encode()+origin.encode(),mark);cli.restored()
            if not allow: assert re.search(rb'\x1b\[[0-9;]+mRejected\x1b\[[0-9;]+m:',cli.output), 'Rejected word is not library-colored'
            assert cli.plain()[mark:].count(('Approved: ' if allow else 'Rejected: ').encode()+origin.encode()) == 1
            ws.close();cli.pump(.25)
        cli.close()
    except BaseException:
        cli.cleanup();raise
    print('PASS: PTY default/Left/Right/Tab, magenta panel, exact Origin, log-once, process-memory reconnect, terminal restoration')

def withheld_retry_and_local_allow(binary):
    cli=Cli(binary)
    try:
        first=cli.pair(session='InitialBackendSession0123456789012345');cli.panel()
        cli.write(b'\t\r');outcome(first,'closed');cli.until(b'Pairing withheld for '+ORIGIN.encode());cli.restored();first.close()
        panels=cli.plain().count(b'Browser Origin:')
        for index in range(4):
            retry=cli.pair(session=f'RotatedBackendSession{index:020d}')
            outcome(retry,'closed');retry.close();cli.pump(.15)
        assert cli.plain().count(b'Browser Origin:') == panels
        assert cli.plain().count(b'Rejected: '+ORIGIN.encode()) == 1
        assert cli.plain().count(b'Pairing withheld for '+ORIGIN.encode()) == 1
        mark=len(cli.plain());cli.write(('allow '+ORIGIN+'\n').encode())
        cli.until(b'Local withholding cleared',mark)
        next=cli.pair(session='FreshAllowedBackendSession0123456789');cli.panel(after=mark)
        try: next.recv(timeout=.2);raise AssertionError('allow granted approval without confirmation')
        except TimeoutError:pass
        cli.write(b'\r');outcome(next,'paired');cli.until(b'Connected: '+ORIGIN.encode(),mark);cli.restored()
        # Revoke a previously approved Origin; fresh session/token must not bypass it.
        mark=len(cli.plain());cli.write(b'revoke\n');outcome(next,'closed',allow_ble=True);next.close();cli.until(b'Pairing withheld for '+ORIGIN.encode(),mark)
        panels=cli.plain().count(b'Browser Origin:')
        retry=cli.pair(session='RevokedNewBackendSession01234567890');outcome(retry,'closed');retry.close();cli.pump(.2)
        assert cli.plain().count(b'Browser Origin:') == panels
        mark=len(cli.plain());cli.write(('allow '+ORIGIN+'\n').encode());cli.until(b'Local withholding cleared',mark)
        next=cli.pair();cli.panel(after=mark)
        try: next.recv(timeout=.2);raise AssertionError('revoked approval was retained')
        except TimeoutError:pass
        cli.write(b'\t\r');outcome(next,'closed');next.close();cli.close()
    except BaseException:cli.cleanup();raise
    print('PASS: fresh-session/token retry cannot repeat rejected/revoked prompts; local allow clears withholding without approving')

def stale_and_cancel(binary):
    cli=Cli(binary)
    try:
        first=cli.pair();cli.panel();first.close();cli.until(b'Disconnected: '+ORIGIN.encode());cli.restored()
        cli.write(b'\r\r');cli.pump(.08)
        origin='https://replacement.example.test';mark=len(cli.plain());second=cli.pair(origin);cli.panel(origin,mark)
        try: second.recv(timeout=.2);raise AssertionError('stale Enter approved replacement')
        except TimeoutError:pass
        # Bracketed paste cannot activate Enter or a choice.
        cli.write(b'\x1b[200~\r\r\x1b[201~');cli.pump(.1)
        try: second.recv(timeout=.2);raise AssertionError('pasted Enter approved request')
        except TimeoutError:pass
        cli.write(b'\t\r\r');outcome(second,'closed');cli.restored();second.close();cli.pump(.2)
        origin='https://burst.example.test';mark=len(cli.plain());third=cli.pair(origin);cli.panel(origin,mark)
        try: third.recv(timeout=.2);raise AssertionError('extra Enter approved later request')
        except TimeoutError:pass
        cli.write(b'\t\r');outcome(third,'closed');cli.restored();third.close();cli.close()
    except BaseException:cli.cleanup();raise
    print('PASS: disconnected panel clears, stale/burst input and paste cannot approve later request')

def control_exit_and_no_color(binary):
    for key in [b'\x03',b'\x04']:
        cli=Cli(binary,no_color=True)
        try:
            ws=cli.pair();cli.panel()
            assert not re.search(rb'\x1b\[(?:3[0-9]|9[0-9]|38;)[^m]*m',cli.output)
            cli.close(key);ws.close()
        except BaseException:cli.cleanup();raise
    print('PASS: NO_COLOR, raw Ctrl-C/Ctrl-D exit restore exact terminal modes and cursor')

def channel_questions_without_device_access(binary):
    for flags,question in [([],b'Approve pairing, BLE and USB for this origin?'),(['--disable-usb'],b'Approve pairing and BLE for this origin?'),(['--disable-ble'],b'Approve pairing and USB for this origin?'),(['--disable-ble','--disable-usb'],b'Approve pairing for this origin?')]:
        cli=Cli(binary,channel_flags=flags)
        try:
            ws=cli.pair();cli.panel();assert question in cli.plain()
            mark=len(cli.output);cli.write(b'\x1b[C');cli.pump(.1)
            assert re.search(rb'\x1b\[(?:38;5;14|36)m> \[ Reject \]',cli.output[mark:]), 'Selected Reject is not cyan'
            cli.write(b'\r');outcome(ws,'closed');cli.restored();ws.close();cli.close()
            assert b'USB: finding' not in cli.plain() and b'BLE: starting' not in cli.plain()
        except BaseException:cli.cleanup();raise
    print('PASS: all four CLI channel questions, default BLE+USB wording, cyan Reject, rejection before any device access')

def real_timeout(binary):
    cli=Cli(binary)
    try:
        ws=cli.pair();cli.panel();cli.until(b'Timed out: '+ORIGIN.encode(),timeout=64);outcome(ws,'closed');cli.restored()
        assert cli.plain().count(b'Timed out: '+ORIGIN.encode()) == 1
        assert b'Approved:' not in cli.plain();ws.close();cli.close()
    except BaseException:cli.cleanup();raise
    print('PASS: real 60-second approval timeout clears panel, logs once, restores terminal')

def narrow_and_resize(binary):
    for initial,resize in [(30,False),(100,True)]:
        cli=Cli(binary,columns=initial)
        try:
            ws=cli.pair()
            if resize:
                cli.panel()
                fcntl.ioctl(cli.slave,termios.TIOCSWINSZ,struct.pack('HHHH',32,20,0,0))
                cli.process.send_signal(signal.SIGWINCH)
            cli.process.wait(timeout=8)
            cli.pump(.1)
            assert b'Terminal is too small' in cli.plain(),cli.output
            assert b'Approved:' not in cli.plain()
            assert termios.tcgetattr(cli.slave)==cli.before
            ws.close();cli.close()
        except BaseException:cli.cleanup();raise
    print('PASS: too-narrow initial/resize fail closed and restore terminal')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,default=ROOT/'helper/target/debug/webauthn-helper');parser.add_argument('--skip-timeout',action='store_true');args=parser.parse_args()
    channel_questions_without_device_access(args.binary);normal_and_keyboard(args.binary);withheld_retry_and_local_allow(args.binary);stale_and_cancel(args.binary);control_exit_and_no_color(args.binary);narrow_and_resize(args.binary)
    if not args.skip_timeout:real_timeout(args.binary)
if __name__=='__main__':main()
