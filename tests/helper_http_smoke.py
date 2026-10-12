"""Actual terminal helper HTTP/port fallback. Never connects to Bluetooth."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "downloads/webauthn-helper-linux-x86_64")
    binary = parser.parse_args().binary.resolve()
    with tempfile.TemporaryDirectory(prefix='helper-http-') as tmp, socket.socket() as occupied:
        occupied.bind(('127.0.0.1',0)); occupied.listen(1)
        port=occupied.getsockname()[1]
        # Obsolete cached ports must never affect the explicit per-process listen address.
        config=Path(tmp)/'auth-browser-companion'; config.mkdir(); (config/'port').write_text('invalid-obsolete-port')
        process=subprocess.Popen([str(binary),'--listen',f'127.0.0.1:{port}'],
            env=dict(os.environ,XDG_CONFIG_HOME=tmp),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+10; address=None; output=b''
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('CLI unexpectedly exited')
                ready,_,_=select.select([process.stdout,process.stderr],[],[],.2)
                for pipe in ready:
                    output+=os.read(pipe.fileno(),8192)
                    match=re.search(rb'Listening: ws://(127\.0\.0\.1:[0-9]+)',output)
                    if match:address=match.group(1).decode();break
                if address:break
            assert address,'CLI did not print actual listening address'
            assert re.fullmatch(rb'\d{4}-\d{2}-\d{2}T[^ ]+Z +INFO Listening: ws://' + re.escape(address.encode()) + rb'\n', output), output
            assert not select.select([process.stdout,process.stderr],[],[],.25)[0], 'Unexpected idle output'
            assert int(address.rsplit(':',1)[1])!=port
            origin='http://'+address
            client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with client.open(origin,timeout=5) as response:
                assert b'WebAuthn Helper' in response.read()
                assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
            try:
                client.open(origin+'/api/status',timeout=5)
                raise AssertionError('Anonymous controls accepted')
            except urllib.error.HTTPError as error:assert error.code==403
            try:
                client.open(urllib.request.Request(origin+'/',headers={'Host':'attacker.invalid'}),timeout=5)
                raise AssertionError('Foreign Host accepted')
            except urllib.error.HTTPError as error:assert error.code==403
            secret='NeverLogTestPairingToken0123456789'
            stdout,stderr=process.communicate(input=f'{secret}\nstatus\nquit\n'.encode(),timeout=10)
            output+=stdout+stderr
            assert process.returncode==0
            assert secret.encode() not in output
            assert b'[Y/n]' not in output and b'Commands:' not in output
            assert not stderr, stderr
            assert b'connected=false scanning=false' in output
            assert b'Local controls:' not in output and b'/#' not in output
            print('PASS: real CLI explicit occupied-port fallback with ignored obsolete cache, HTTP/Host/control boundary, quiet startup/status/quit and token-free logs; no BLE accessed')
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.communicate(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.communicate()

if __name__=='__main__':main()
