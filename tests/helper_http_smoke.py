"""Actual terminal helper HTTP/port fallback. Never connects to Bluetooth."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
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
            # Unsupported physical USB reports once at the first controller tick.
            # Keep every other unsolicited startup line an error.
            idle_deadline=time.monotonic()+.25
            while time.monotonic()<idle_deadline:
                ready,_,_=select.select([process.stdout,process.stderr],[],[],max(0,idle_deadline-time.monotonic()))
                for pipe in ready:
                    chunk=os.read(pipe.fileno(),8192)
                    assert chunk, 'CLI unexpectedly exited during startup'
                    assert pipe is process.stdout, chunk
                    output+=chunk
            startup_lines=output.splitlines(keepends=True)
            listener_pattern=rb'\d{4}-\d{2}-\d{2}T[^ ]+Z +INFO Listening: ws://' + re.escape(address.encode()) + rb'\n'
            assert sum(bool(re.fullmatch(listener_pattern,line)) for line in startup_lines)==1, output
            other_lines=[line for line in startup_lines if not re.fullmatch(listener_pattern,line)]
            assert not other_lines or (
                sys.platform not in ('linux','win32') and len(other_lines)==1
                and re.fullmatch(rb'\d{4}-\d{2}-\d{2}T[^ ]+Z +WARN USB: unavailable\n',other_lines[0])
            ), output
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
            # The CLI intentionally does not drain its logging worker at exit.
            # Observe the complete status record before requesting shutdown.
            process.stdin.write(f'{secret}\nstatus\n'.encode()); process.stdin.flush()
            status_output=b''; deadline=time.monotonic()+10
            while b'connected=false scanning=false received=0\n' not in status_output:
                assert time.monotonic()<deadline, ('Missing status output',status_output)
                ready,_,_=select.select([process.stdout,process.stderr],[],[],.2)
                for pipe in ready:
                    chunk=os.read(pipe.fileno(),8192)
                    assert chunk, 'CLI exited before status output'
                    assert pipe is process.stdout, chunk
                    status_output+=chunk
            output+=status_output
            stdout,stderr=process.communicate(input=b'quit\n',timeout=10)
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
