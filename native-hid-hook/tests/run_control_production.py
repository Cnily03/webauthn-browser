#!/usr/bin/env python3
"""Assert the ordinary build cannot claim readiness before genuine monitor prerequisites."""
import os
import pathlib
import socket
import subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
LIB=pathlib.Path(os.environ.get('AUTH_BROWSER_TEST_HID_PRELOAD', str(ROOT/'target/debug/libuserland_hid_hook.so')))
symbols=subprocess.check_output(['nm','-D',str(LIB)],text=True)
assert 'uhf_simulation_monitor_new' not in symbols, 'This check requires a normal non-simulation build'
parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
parent.settimeout(3)
env=os.environ.copy()
for key in ('LD_PRELOAD','UHF_ENABLE','UHF_RELAY_FD','UHF_CONTROL_FD','UHF_BROWSER_EPOCH','UHF_OWNER_PID'):
    env.pop(key,None)
env.update(LD_PRELOAD=str(LIB),UHF_ENABLE='1',UHF_CONTROL_FD=str(child.fileno()),UHF_BROWSER_EPOCH='11'*16,UHF_SIMULATION='1')
proc=subprocess.Popen(['/bin/cat'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,pass_fds=(child.fileno(),))
child.close()
try:
    hello=b'UFHC'+bytes([1,1,0,0])+bytes.fromhex('22'*16)+bytes.fromhex('11'*16)+bytes(56)
    assert len(hello)==96;parent.send(hello)
    reply=parent.recv(1024)
    assert len(reply)==96 and reply[5:8]==bytes([9,0,0]),repr(reply)
    parent.settimeout(.05)
    try: parent.recv(1024); raise AssertionError('Unexpected READY or closed control before genuine monitor exists')
    except socket.timeout: pass
    parent.close()
    proc.stdin.close();proc.wait(timeout=3);assert proc.returncode==0
finally:
    parent.close()
    if proc.poll() is None:proc.kill();proc.wait()
print('PASS: production build exports no simulation constructor, ignores simulation environment, responds Unavailable(flags=0), keeps startup scope pending, and never claims READY without genuine monitor prerequisites')
