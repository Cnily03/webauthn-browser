"""Container health includes the gateway, attached WebAuthn proxy, and VNC."""
import socket
import urllib.request


def check():
    # Ignore proxy variables for container-internal readiness checks.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://127.0.0.1:8080/readyz")
    with opener.open(request, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("desktop is not ready")
    with socket.create_connection(("127.0.0.1", 5900), timeout=2) as connection:
        if not connection.recv(12).startswith(b"RFB "):
            raise RuntimeError("VNC is not ready")


if __name__ == "__main__":
    check()
