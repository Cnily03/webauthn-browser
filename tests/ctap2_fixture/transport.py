"""Owns the authenticator end of an explicit anonymous SOCK_SEQPACKET pair."""
import socket
from hid import Device

def serve(peer, *, simulate_presence=False):
    if peer.family != socket.AF_UNIX or peer.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) != socket.SOCK_SEQPACKET:
        raise ValueError("connected anonymous AF_UNIX SOCK_SEQPACKET required")
    if peer.getsockname() not in ("",b"") or peer.getpeername() not in ("",b""):
        raise ValueError("anonymous socketpair required")
    device = Device(simulate_presence=simulate_presence)
    peer.settimeout(0.1)
    try:
        while True:
            try: packet = peer.recv(65)
            except socket.timeout:
                for response in device.tick(): peer.sendall(response)
                continue
            if not packet: break
            if len(packet) != 64: raise ValueError("malformed peer report length")
            for response in device.report(packet): peer.sendall(response)
    finally:
        device.close()
        peer.close()
