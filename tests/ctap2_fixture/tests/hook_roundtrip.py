#!/usr/bin/env python3
"""Actual preload ABI/report test with ephemeral signed CTAP2 results; not a browser."""
import fcntl
import hashlib
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
ROOT=pathlib.Path(__file__).resolve().parents[1]
(ROOT / "evidence").mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/"tests"))
from transport import serve
from hid import frames,BROADCAST,INIT,CBOR,CANCEL
import cborcodec
from test_fixture import make_input,parse_registration,verify_with_openssl,unpack

subprocess.run(["cc","-Wall","-Wextra","-Werror","-O2",str(ROOT/"tests/hook_client.c"),"-o",str(ROOT/"evidence/hook-client")],check=True)
library=pathlib.Path(os.environ.get("AUTH_BROWSER_TEST_HID_PRELOAD", str(ROOT.parents[1]/"native-hid-hook/target/debug/libuserland_hid_hook.so"))).resolve()
assert library.is_file(),"Build the separate authorized hook first; no browser launch needed"
a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
relay=fcntl.fcntl(a.fileno(),fcntl.F_DUPFD_CLOEXEC,198);a.close()
errors=[]
def run_fixture():
    try:serve(b,simulate_presence=True)
    except Exception as error:errors.append(error)
thread=threading.Thread(target=run_fixture);thread.start()
env={key:value for key,value in os.environ.items() if key not in {"LD_PRELOAD","UHF_ENABLE","UHF_RELAY_FD"}}
env.update(LD_PRELOAD=str(library),UHF_ENABLE="1",UHF_RELAY_FD=str(relay))
process=subprocess.Popen([str(ROOT/"evidence/hook-client")],env=env,pass_fds=(relay,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
os.close(relay)
def read_report():
    data=b""
    while len(data)<64:
        assert select.select([process.stdout],[],[],3)[0],"ABI report deadline"
        part=os.read(process.stdout.fileno(),64-len(data));assert part,"ABI client EOF"
        data+=part
    return data
def exchange(cid,command,payload,response_command=None):
    for report in frames(cid,command,payload):process.stdin.write(report)
    process.stdin.flush()
    first=read_report();reports=[first];total=int.from_bytes(first[5:7],"big")
    while 57+(len(reports)-1)*59<total:reports.append(read_report())
    result=unpack(reports);assert result[:2]==(cid,response_command or command),result[:2]
    return result[2]
try:
    nonce=os.urandom(8);hello=exchange(BROADCAST,INIT,nonce)
    assert hello[:8]==nonce and hello[12:]==bytes([2,0,1,0,0x0c])
    cid=int.from_bytes(hello[8:12],"big")
    info=cborcodec.decode(exchange(cid,CBOR,b"\x04")[1:]);assert info[1]==["FIDO_2_0"]
    request=make_input();registration,identifier,public=parse_registration(exchange(cid,CBOR,b"\x01"+cborcodec.encode(request)))
    verify_with_openssl(public,registration[3]["sig"],registration[2]+request[1])
    for counter in [1,2]:
        client_hash=hashlib.sha256(f"synthetic hook assertion {counter}".encode()).digest()
        assertion=cborcodec.decode(exchange(cid,CBOR,b"\x02"+cborcodec.encode({1:"ctap.fixture.test",2:client_hash,3:[{"type":"public-key","id":identifier}]}))[1:])
        assert assertion[2][:32]==hashlib.sha256(b"ctap.fixture.test").digest()
        assert int.from_bytes(assertion[2][33:37],"big")==counter and assertion[2][32]==1
        verify_with_openssl(public,assertion[3],assertion[2]+client_hash)
    # CANCEL clears a fragmented creation before it can generate a key.
    partial=frames(cid,CBOR,b"\x01"+cborcodec.encode(make_input()))
    process.stdin.write(partial[0]);process.stdin.flush()
    assert exchange(cid,CANCEL,b"",CBOR)==b"\x2d"  # Reply belongs to the canceled CBOR, checked below.
finally:
    if process.stdin:process.stdin.close()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait();raise
    thread.join(3)
    if process.returncode:raise RuntimeError(process.stderr.read().decode())
    assert not thread.is_alive() and not errors,errors
print("PASS: actual preload C ABI -> 65-byte hidraw write -> exact64-byte SOCK_SEQPACKET -> CTAPHID INIT/getInfo/makeCredential/getAssertion; OpenSSL verified self-attestation and two bound monotonic assertions; fragmented CANCEL cleanup")
print("NOT TESTED: Chromium discovery/parser/FIDO path, browser WebAuthn UI, real USB devices, production helper relay")
