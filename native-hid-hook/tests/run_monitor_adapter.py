#!/usr/bin/env python3
"""Normal-build monitor C ABI with explicitly linked mock libudev and anonymous IPC.
No Chromium, USB access, authenticator credential, daemon or privilege changes.
"""
import array
import os
import pathlib
import select
import socket
import struct
import subprocess
import time
ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = os.environ.get('AUTH_BROWSER_TEST_HID_PRELOAD', str(ROOT / 'target/debug/libuserland_hid_hook.so'))
EXE = str(ROOT / 'target/monitor-adapter-native')
MOCK = str(ROOT / 'target/mock-udev-monitor.so')
# Keep the regression genuinely preemptible: a direct local mock call would
# hide the enable -> filter_update interposition deadlock seen in libudev.
relocations = subprocess.check_output(['readelf', '-rW', MOCK], text=True)
assert any('JUMP_SLOT' in line and 'udev_monitor_filter_update' in line
           for line in relocations.splitlines()), 'Mock enable must call filter_update through the PLT'
BROWSER = bytes.fromhex('11' * 16)
GATEWAY = bytes.fromhex('22' * 16)

def frame(op, generation=0, attachment=bytes(16), deadline=0, seq=0, mode=0, gateway=GATEWAY, browser=BROWSER, flags=0):
    return b'UFHC' + bytes([1, op, flags, 0]) + gateway + browser + attachment + struct.pack('!QQQQ', generation, mode, deadline, seq) + bytes(8)

def unpack(data):
    assert len(data) == 96, repr(data)
    return dict(op=data[5], flags=data[6], gateway=data[8:24], browser=data[24:40], attachment=data[40:56], generation=int.from_bytes(data[56:64], 'big'), mode=int.from_bytes(data[64:72], 'big'), deadline=int.from_bytes(data[72:80], 'big'), seq=int.from_bytes(data[80:88], 'big'))

class Case:
    def __init__(self):
        self.parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.parent.settimeout(3)
        self.real_parent, real_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        env = os.environ.copy()
        for key in ('LD_PRELOAD', 'UHF_ENABLE', 'UHF_RELAY_FD', 'UHF_CONTROL_FD', 'UHF_BROWSER_EPOCH', 'UHF_OWNER_PID'):
            env.pop(key, None)
        env.update(LD_PRELOAD=LIB+':'+MOCK, UHF_MOCK_REAL_FD=str(real_child.fileno()), DEVPATH="/devices/virtual/mem/null", SUBSYSTEM="mem", ACTION="change", SEQNUM="1", MAJOR="1", MINOR="3", UHF_ENABLE='1', UHF_CONTROL_FD=str(child.fileno()), UHF_BROWSER_EPOCH=BROWSER.hex())
        self.proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, pass_fds=(child.fileno(),real_child.fileno()), text=True, bufsize=1)
        child.close();real_child.close()
        assert self.line() == 'WAITING'
        self.send(frame(1))
        self.ack(9)
        self.serial = 0
        self.reports = []
    def line(self):
        if not select.select([self.proc.stdout], [], [], 4)[0]:
            raise AssertionError('native command timed out')
        line = self.proc.stdout.readline().strip()
        if not line:
            raise AssertionError(f'native process exited {self.proc.poll()}: {self.proc.stderr.read()}')
        return line
    def command(self, text, prefix):
        self.proc.stdin.write(text+'\n');self.proc.stdin.flush()
        result=self.line();assert result.startswith(prefix),(text,result)
        return result
    def send(self, payload, right=None):
        ancillary=[] if right is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[right.fileno()]))]
        assert self.parent.sendmsg([payload],ancillary)==96
    def ack(self, op, **expected):
        result=unpack(self.parent.recv(1024));assert result['op']==op,result
        assert result['flags']==(1 if op in (2,4,6,11) else 0),result
        for key,value in expected.items():assert result[key]==value,(key,result)
        return result
    def prepare(self, gen, lease=3, gateway=GATEWAY):
        self.serial+=1
        attachment=self.serial.to_bytes(16,'big')
        deadline=time.monotonic_ns()+int(lease*1_000_000_000)
        sender,hook=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        sender.settimeout(3)
        fields=dict(generation=gen,attachment=attachment,deadline=deadline,mode=1,gateway=gateway)
        self.send(frame(3,**fields),hook);hook.close();self.reports.append(sender)
        self.ack(4,generation=gen,attachment=attachment)
        return fields,sender
    def activate(self, fields, slot):
        self.send(frame(5,**fields));self.ack(6,generation=fields['generation'])
        event=self.command(f'event {slot} add','EVENT')
        self.command(f'open {slot}','OPEN')
        return event
    def revoke(self, fields, slot):
        self.send(frame(7,**fields));self.ack(8)
        self.command(f'event {slot} remove','EVENT')
    def finish(self):
        if self.proc.poll() is None:
            self.command('quit','DONE')
        self.proc.wait(timeout=4)
        assert self.proc.returncode==0,self.proc.stderr.read()
        self.parent.close();self.real_parent.close()
        for report in self.reports:report.close()

case=Case()
# An enumeration made before monitor readiness must stay usable. An unfiltered
# monitor exercises the ordinary watcher contract without requiring a hidraw
# filter to manufacture readiness. The genuine monitor remains explicitly mocked.
case.command('enumerator','ENUMERATOR');case.command('enumerated 0 hidden','ENUMERATED')
case.command('new 2 okay','MONITOR');case.ack(2)
f,r=case.prepare(1);case.command('enumerated 0 hidden','ENUMERATED')
first=case.activate(f,0);case.command('enumerated 0 visible','ENUMERATED')
case.revoke(f,1);case.command('enumerated 0 hidden','ENUMERATED');case.command('dead 0','DEAD')
g,s=case.prepare(2);second=case.activate(g,2)
assert first.split()[3:]!=second.split()[3:]
case.command('enumerated 2 visible','ENUMERATED');case.command('dead 0','DEAD')
case.revoke(g,3);case.command('enumerated 2 hidden','ENUMERATED');case.finish()
print('PASS: unfiltered mock monitor, early enumeration hidden until activation, generation-specific udev ancestry/properties/sysattr, sealed descriptor through open64/fopen64 and matching HID ioctls, revoked descriptor paths denied across replacement')

case=Case()
case.command('new 0 okay','MONITOR');case.ack(2)
case.command('ref','REF')
case.command('update','UPDATE')
case.command('refthreads','REFTHREADS')
for _ in range(3):
    case.real_parent.send(b'R');case.command('real','REAL')
case.command('idle','IDLE')
f,r=case.prepare(1);case.command('hidden','HIDDEN');case.activate(f,0)
case.command('io 0','WROTE');assert r.recv(128)==b'Q'*64
r.send(b'Q'*64);case.command('read 0','READ')
case.command('fork 0','FORK')
for _ in range(30):case.real_parent.send(b'R')
for _ in range(30):case.command('real','REAL')
case.command('idle','IDLE')
case.revoke(f,1);case.command('dead 0','DEAD')
g,s=case.prepare(2);case.activate(g,2)
# Last unref terminally revokes handles but keeps the authenticated control
# scope waiting for a newly enabled genuine monitor.
case.command('drop','DROPPED');case.ack(9);case.command('dead 2','DEAD')
case.command('new 0 okay','MONITOR');case.ack(2)
case.command('dead 0','DEAD');case.command('dead 2','DEAD')
h,t=case.prepare(3);case.activate(h,3);case.revoke(h,4)
case.command('drop','DROPPED');case.ack(9)
# Unrelated filters preserve genuine events and do not advertise FIDO readiness.
case.command('new 1 okay','MONITOR')
case.real_parent.send(b'R');case.command('real','REAL')
case.parent.settimeout(.05)
try:case.parent.recv(96);raise AssertionError('input-only monitor advertised FIDO readiness')
except socket.timeout:pass
case.parent.settimeout(3)
case.command('all','ALL');case.ack(2)
case.command('tag','TAG');case.ack(9)
case.command('drop','DROPPED')
case.finish()
print('PASS: normal production adapter under mock genuine ABI: PLT-reentrant enable, untouched prerequisites/update errors, flags=1, real-event forwarding, rearm/no idle spin, synthetic add/remove, opaque HID I/O, active fork, threaded ref/unref racing fork, last-monitor revoke/recovery, unrelated filters and tag suppression')

for failure,prefix in [('new','NEW_ERROR'),('enable','ENABLE_ERROR'),('getfd','FD_ERROR'),('filter','FILTER_ERROR'),('update','UPDATE_ERROR')]:
    case=Case();case.command('new 0 '+failure,prefix)
    case.parent.settimeout(.05)
    try:case.parent.recv(96);raise AssertionError(f'{failure} failure incorrectly advertised readiness')
    except socket.timeout:pass
    case.parent.settimeout(3)
    if failure!='new':case.command('drop','DROPPED')
    case.command('new 0 okay','MONITOR');case.ack(2)
    case.finish();print('PASS:',failure,'original error/errno preserved, no READY until later successful genuine prerequisites')

case=Case();case.command('new 0 okay','MONITOR');case.ack(2)
case.proc.stdin.write('forkrace\n');case.proc.stdin.flush()
for gen in range(1,65):
    f,r=case.prepare(gen);case.send(frame(7,**f));case.ack(8)
assert case.line()=='FORK'
case.finish()
print('PASS: genuine-adapter private capabilities closed in 128 forks racing 64 SCM_RIGHTS report deliveries; unrelated genuine source retained')

case=Case();case.command('new 0 okay','MONITOR');case.ack(2)
case.command('replace','REPLACED')
case.real_parent.send(b'R');case.command('real','REAL');case.command('fork','FORK')
case.command('reuse','REUSE');case.ack(9);case.finish()
print('PASS: public mux raw FD reuse cannot read unrelated data; old monitor drop preserves a newly registered replacement capability and its fork cleanup')

case=Case();case.command('new 0 okay','MONITOR');case.ack(2)
for gen in range(1,17):
    f,r=case.prepare(gen);case.send(frame(5,**f));case.ack(6);case.send(frame(7,**f));case.ack(8)
f,r=case.prepare(17);case.send(frame(5,**f));assert case.parent.recv(1024)==b''
case.command('hidden','HIDDEN');case.command('idle','IDLE')
case.real_parent.send(b'R');case.command('real','REAL');case.command('idle','IDLE')
case.finish()
print('PASS: terminal 32-event synthetic overflow drains wake tokens without busy null loop and continues forwarding unrelated genuine events')

case=Case();case.command('new 0 okay','MONITOR');case.ack(2)
f,r=case.prepare(1);case.activate(f,0)
case.command('changed','CHANGED');case.ack(9);case.command('dead 0','DEAD')
case.command('idle','IDLE');case.finish()
print('PASS: changed genuine FD fails virtual readiness, revokes the generation, and leaves no permanent wake readiness')
