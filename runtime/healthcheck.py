"""Gateway readiness aggregates its currently active profile contexts."""
import urllib.request


def check():
    # No fixed VNC port: profiles are allocated independently, and an idle
    # deployment can have no desktop processes while management remains healthy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://127.0.0.1:8080/readyz")
    with opener.open(request, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("profile runtime is not ready")


if __name__ == "__main__":
    check()
