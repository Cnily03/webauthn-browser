"""Own all prepared runner resources, including failures before Popen."""
import os
import socket
import subprocess

class Resources:
    def __init__(self):
        self.closing = False
        self.server = self.http_thread = self.fixture_thread = None
        self.host = self.peer = self.process = self.relay = None
    def close(self):
        self.closing = True
        errors = []
        def attempt(operation):
            try:operation()
            except Exception as error:errors.append(type(error).__name__)
        if self.process is not None:
            def stop():
                if self.process.poll() is not None:return
                self.process.terminate()
                try:self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill();self.process.wait(timeout=5)
            attempt(stop)
        if self.relay is not None:
            descriptor,self.relay = self.relay,None
            attempt(lambda:os.close(descriptor))
        if self.host is not None:
            attempt(self.host.close)
        # Close the peer even if fixture thread startup failed. Shutdown wakes a
        # running fixture; joining is bounded and never waits on an unstarted thread.
        if self.peer is not None:
            try:self.peer.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            attempt(self.peer.close)
        if self.fixture_thread is not None and self.fixture_thread.is_alive():
            attempt(lambda:self.fixture_thread.join(timeout=3))
            if self.fixture_thread.is_alive():errors.append("FixtureThreadStillRunning")
        if self.server is not None:
            if self.http_thread is not None and self.http_thread.is_alive():
                attempt(self.server.shutdown)
            attempt(self.server.server_close)
        if self.http_thread is not None and self.http_thread.is_alive():
            attempt(lambda:self.http_thread.join(timeout=3))
            if self.http_thread.is_alive():errors.append("HttpThreadStillRunning")
        return errors
