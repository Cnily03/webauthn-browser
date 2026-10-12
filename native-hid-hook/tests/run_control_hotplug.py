#!/usr/bin/env python3
"""Native C ABI plus real anonymous seqpacket control, compile-only simulation.
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
LIB = str(ROOT / 'target/debug/libuserland_hid_hook.so')
EXE = str(ROOT / 'target/control-hotplug-native')
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
        env = os.environ.copy()
        for key in ('LD_PRELOAD', 'UHF_ENABLE', 'UHF_RELAY_FD', 'UHF_CONTROL_FD', 'UHF_BROWSER_EPOCH', 'UHF_OWNER_PID'):
            env.pop(key, None)
        env.update(LD_PRELOAD=LIB, UHF_ENABLE='1', UHF_CONTROL_FD=str(child.fileno()), UHF_BROWSER_EPOCH=BROWSER.hex())
        self.proc = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, pass_fds=(child.fileno(),), text=True, bufsize=1)
        child.close()
        assert self.line() == 'MONITOR'
        self.send(frame(1))
        self.ack(2)
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
        assert result['flags']==(129 if op in (2,4,6,11) else 0),result
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
        self.parent.close()
        for report in self.reports:report.close()

case=Case()
case.command('hidden','HIDDEN')
f,r=case.prepare(1)
case.command('hidden','HIDDEN')
old=case.activate(f,0)
case.command('fork 0','FORK')
case.command('io 0','WROTE');assert r.recv(128)==b'Q'*64
r.send(b'Q'*64);case.command('read 0','READ')
# A renewal preserves the same endpoint and emits no hotplug add event.
f['seq']=1;f['deadline']+=1_000_000_000
case.send(frame(10,**f));case.ack(11,seq=1)
r.send(b'Q'*64)  # Remains queued across revoke; old handles must never consume it.
case.revoke(f,1);case.command('dead 0','DEAD');case.command('hidden','HIDDEN')
# A delayed duplicate revoke cannot touch the following live generation.
g,s=case.prepare(2);new=case.activate(g,2);assert old.split()[2]!=new.split()[2]
case.send(frame(7,**f));case.ack(8)
case.command('dead 0','DEAD');case.command('io 2','WROTE');assert s.recv(128)==b'Q'*64
case.revoke(g,3);case.command('dead 2','DEAD')
# Cancellation while prepared never emits an add/remove event.
h,t=case.prepare(3);case.send(frame(7,**h));case.ack(8);case.command('hidden','HIDDEN')
# Packet HUP revokes even when no process reads a report.
h,t=case.prepare(4);case.activate(h,4);t.close();case.ack(8);case.command('event 5 remove','EVENT');case.command('dead 4','DEAD')
# Expiration also makes every old handle terminal.
h,t=case.prepare(5,lease=.3);case.activate(h,6);case.ack(8);case.command('event 7 remove','EVENT');case.command('dead 6','DEAD')
# Fresh gateway scope can restart its generation counter; synthetic paths differ.
case.send(frame(9));new_gateway=b'\x33'*16;case.send(frame(1,gateway=new_gateway));case.ack(2,gateway=new_gateway)
h,t=case.prepare(1,gateway=new_gateway);case.activate(h,8);case.command('dead 0','DEAD');case.revoke(h,9)
case.finish()
print('PASS: simulated readiness flags, prepare/activate/revoke, fork closure, opaque packet I/O, renewal, queued-packet revocation, repeat attach, stale revoke, cancellation, HUP, expiry, gateway reset')

# Stale Active/ACK input and replayed lease fail the channel rather than resurrect.
for label, bad in [('unexpected Active ACK',6),('duplicate renewal',10),('late activation',5)]:
    case=Case();f,r=case.prepare(1,lease=.2 if bad==5 else 3)
    if bad==5:
        case.ack(8);case.send(frame(5,**f))
    else:
        case.activate(f,0)
        if bad==10:
            f['seq']=1;f['deadline']+=1_000_000_000;case.send(frame(10,**f));case.ack(11)
            case.send(frame(10,**f))
        else:
            case.send(frame(6,**f,flags=129))
    assert case.parent.recv(1024)==b'',label
    if bad!=5:case.command('event 1 remove','EVENT');case.command('dead 0','DEAD')
    case.command('hidden','HIDDEN');case.finish();print('PASS:',label,'fails closed')

# Rights receive/validation/registration and atfork snapshots race deliberately.
case=Case()
case.proc.stdin.write('forkrace\n');case.proc.stdin.flush()
for gen in range(1,65):
    f,r=case.prepare(gen)
    case.send(frame(7,**f));case.ack(8)
assert case.line()=='FORK'
case.finish();print('PASS: 128 standard forks racing 64 SCM_RIGHTS prepare/revoke cycles leave no packet capabilities in children')

for reason in ('generation replay','attachment replay','expired deadline','oversized lease','foreign browser','foreign gateway','wrong mode','malformed rights','EOF'):
    case=Case();f,r=case.prepare(1);case.activate(f,0)
    if reason=='EOF':
        case.parent.close()
    elif reason=='malformed rights':
        payload=bytearray(frame(7,**f));payload[-1]=1
        endpoint,passed=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        endpoint.settimeout(3)
        case.send(bytes(payload),passed);passed.close()
        assert endpoint.recv(1)==b'';endpoint.close()
    elif reason in ('foreign browser','foreign gateway','wrong mode'):
        bad=dict(f)
        bad[{'foreign browser':'browser','foreign gateway':'gateway','wrong mode':'mode'}[reason]]=2 if reason=='wrong mode' else b'\x77'*16
        case.send(frame(5,**bad))
    else:
        case.revoke(f,1)
        # Do not accept another preparation using an old generation, an old
        # attachment, or any deadline outside the absolute monotonic window.
        bad=dict(f)
        bad.update(generation=2,attachment=(100).to_bytes(16,'big'))
        if reason=='generation replay':bad['generation']=1
        elif reason=='attachment replay':bad['attachment']=f['attachment']
        elif reason=='expired deadline':bad['deadline']=time.monotonic_ns()-1
        elif reason=='oversized lease':bad['deadline']=time.monotonic_ns()+31_000_000_000
        endpoint,passed=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        endpoint.settimeout(3);case.send(frame(3,**bad),passed);passed.close()
        assert endpoint.recv(1)==b'';endpoint.close()
    if reason!='EOF':assert case.parent.recv(1024)==b''
    if reason in ('EOF','malformed rights','foreign browser','foreign gateway','wrong mode'):case.command('event 1 remove','EVENT')
    case.command('dead 0','DEAD');case.command('hidden','HIDDEN');case.finish()
    print('PASS:',reason,'is terminal and drops owned report rights')

# A canceled prepare tolerates a revoke carrying a pending, not-yet-applied lease.
case=Case();f,r=case.prepare(1);pending=dict(f,seq=9,deadline=f['deadline']+1)
case.send(frame(7,**pending));case.ack(8,seq=9);case.command('hidden','HIDDEN');case.finish()
print('PASS: revoke matches attachment identity independently of lease fields')

# Bounded event queues fail closed rather than silently lose remove/add order.
case=Case()
for gen in range(1,17):
    f,r=case.prepare(gen)
    case.send(frame(5,**f));case.ack(6)
    case.send(frame(7,**f));case.ack(8)
f,r=case.prepare(17);case.send(frame(5,**f))
assert case.parent.recv(1024)==b''
case.command('hidden','HIDDEN');case.finish()
print('PASS: 32-event queue overflow closes control and revokes visibility')

# A previous gateway epoch is not fresh and cannot reset replay protection.
case=Case();f,r=case.prepare(1);case.activate(f,0);case.revoke(f,1)
case.send(frame(9));case.send(frame(1,gateway=b'\x44'*16));case.ack(2)
case.send(frame(9,gateway=b'\x44'*16));case.send(frame(1))
assert case.parent.recv(1024)==b''
case.command('dead 0','DEAD');case.command('hidden','HIDDEN');case.finish()
print('PASS: replayed previous gateway epoch cannot reset high-water marks or rebind old paths')
