#!/usr/bin/env python3
"""Prepared for a future authorized environment. Default execution NEVER launches a browser."""
import argparse
import fcntl
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import threading
from acceptance import Verifier,b64
from transport import serve
from preflight import preflight, PreflightError
from runner_resources import Resources
ROOT=pathlib.Path(__file__).resolve().parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-in-authorized-environment',action='store_true',help='Explicitly start local HTTP + stock browser only in an environment where normal Chromium/libudev are allowed.')
    parser.add_argument('--browser',default='/usr/lib/chromium/chromium')
    parser.add_argument('--hook',default=str(ROOT.parents[1]/'native-hid-hook/target/debug/libuserland_hid_hook.so'))
    args=parser.parse_args()
    if not args.run_in_authorized_environment:
        print('NOT RUN. Prepared acceptance: anonymous packet socket + test fixture + localhost page + fresh browser profile.')
        print('Current environment has confirmed unchanged Chromium singleton EPERM and libudev monitor EPERM; do not retry/bypass here.')
        print('No Chromium launch, listener, credential, profile, or hook installation was performed.')
        return
    # Fail closed before opening a listener or packet socket. Do not continue
    # after a missing library, unsupported target, denied monitor, or loader failure.
    try:
        browser,hook=preflight(args.browser,args.hook)
    except PreflightError as error:
        parser.exit(2, "Prerequisite failed: "+str(error)+"\n")
    # This branch is prepared but intentionally NOT executed/validated in the current environment.
    token=secrets.token_urlsafe(24)
    verifier=None
    results=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup();self.connection.settimeout(2)
        def log_message(self,*_):pass
        def send_json(self,code,value):
            data=json.dumps(value).encode();self.send_response(code)
            self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store')
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def valid_host(self):return self.client_address[0]=='127.0.0.1' and self.headers.get('Host')==origin[7:]
        def do_GET(self):
            if not self.valid_host() or self.path!='/':self.send_error(404);return
            config={'token':token,**{kind:b64(value) for kind,value in verifier.challenges.items()}}
            page=(ROOT/'acceptance.html').read_text().replace('__CONFIG__',json.dumps(config)).encode()
            self.send_response(200);self.send_header('Content-Type','text/html;charset=utf-8')
            self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header('X-Frame-Options','DENY');self.send_header('Content-Length',str(len(page)));self.end_headers();self.wfile.write(page)
        def do_POST(self):
            if not self.valid_host() or self.path!='/result' or self.headers.get('Origin')!=origin or self.headers.get('X-Fixture-Token')!=token or self.headers.get('Content-Type')!='application/json':
                self.send_json(403,{'error':'Local test origin/token required'});return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError('response size')
                result=verifier.accept(json.loads(self.rfile.read(length)))
            except Exception as error:
                self.send_json(400,{'error':type(error).__name__+': '+str(error)});return
            results.append(result);print(json.dumps(result),flush=True);self.send_json(200,result)
    resources=Resources()
    failures=[]
    cleanup_errors=[]
    try:
        resources.server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        origin=f'http://localhost:{resources.server.server_port}';verifier=Verifier(origin)
        resources.http_thread=threading.Thread(target=resources.server.serve_forever,daemon=True)
        resources.http_thread.start()
        resources.host,resources.peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        resources.relay=fcntl.fcntl(resources.host.fileno(),fcntl.F_DUPFD_CLOEXEC,198)
        resources.host.close();resources.host=None
        def fixture():
            try:serve(resources.peer,simulate_presence=True)
            except Exception as error:
                if not resources.closing:failures.append(type(error).__name__+': '+str(error))
        resources.fixture_thread=threading.Thread(target=fixture,daemon=True)
        resources.fixture_thread.start()
        env={k:v for k,v in os.environ.items() if not k.startswith('LD_') and k not in {'UHF_ENABLE','UHF_RELAY_FD'}}
        env.update(LD_PRELOAD=str(hook),UHF_ENABLE='1',UHF_RELAY_FD=str(resources.relay))
        with tempfile.TemporaryDirectory(prefix='ctap-fixture-profile-') as profile:
            command=[str(browser),'--no-first-run','--no-default-browser-check','--disable-background-networking','--user-data-dir='+profile,origin]
            print('Test-only ephemeral credentials/presence. Complete both localhost buttons; maximum runtime 180 seconds.',flush=True)
            resources.process=subprocess.Popen(command,env=env,pass_fds=(resources.relay,))
            os.close(resources.relay);resources.relay=None
            try:resources.process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                resources.process.terminate()
                try:resources.process.wait(timeout=5)
                except subprocess.TimeoutExpired:resources.process.kill();resources.process.wait()
    finally:
        cleanup_errors=resources.close()
    passed={item['ceremony'] for item in results}=={'create','get'} and not failures and not cleanup_errors
    print('PASS: real browser delivered verified creation AND assertion' if passed else 'NOT ACCEPTED: complete browser evidence missing',flush=True)
    if failures:print('Fixture failure:',failures)
    if cleanup_errors:print('Cleanup failure:',cleanup_errors)
    raise SystemExit(0 if passed else 1)

if __name__=='__main__':main()
