"""Bounded CTAPHID over exact 64-byte reports; no report-ID byte on this side."""
from dataclasses import dataclass
import time
from authenticator import Authenticator

INIT, PING, CBOR, CANCEL, ERROR = 0x86, 0x81, 0x90, 0x91, 0xbf
BROADCAST = 0xffffffff
MAX_MESSAGE, MAX_CHANNELS, PARTIAL_TIMEOUT = 4096, 8, 3.0

def frames(cid, command, payload):
    if len(payload) > MAX_MESSAGE: raise ValueError("message too large")
    first = cid.to_bytes(4,"big") + bytes([command]) + len(payload).to_bytes(2,"big") + payload[:57]
    result = [first.ljust(64,b"\0")]
    payload = payload[57:]
    for sequence in range((len(payload)+58)//59):
        result.append((cid.to_bytes(4,"big")+bytes([sequence])+payload[sequence*59:(sequence+1)*59]).ljust(64,b"\0"))
    return result

@dataclass
class Partial:
    cid: int
    command: int
    total: int
    data: bytes
    next_sequence: int
    deadline: float

class Device:
    def __init__(self, *, simulate_presence=False, clock=time.monotonic):
        self.auth = Authenticator(simulate_presence=simulate_presence)
        self.clock = clock
        self.channels = set()
        self.next_cid = 1
        self.partial = None
    def error(self,cid,code): return frames(cid,ERROR,bytes([code]))
    def tick(self):
        if self.partial is not None and self.clock() >= self.partial.deadline:
            cid = self.partial.cid
            self.partial = None
            return self.error(cid,5)
        return []
    def report(self,packet):
        if type(packet) is not bytes or len(packet) != 64: raise ValueError("exactly 64 report bytes required")
        result = self.tick()
        cid, command = int.from_bytes(packet[:4],"big"), packet[4]
        if command == CANCEL:
            if packet[5:7] != b"\0\0":return result+self.error(cid,3)
            if self.partial is not None and self.partial.cid == cid:
                previous,self.partial = self.partial,None
                if previous.command == CBOR: result += frames(cid,CBOR,b"\x2d")
            return result
        if cid == 0 or (cid != BROADCAST and cid not in self.channels) or (cid == BROADCAST and command != INIT):
            return result+self.error(cid,11)
        if self.partial is not None:
            if self.partial.cid != cid: return result+self.error(cid,6)
            if command != INIT:
                pending = self.partial
                if command & 0x80 or command != pending.next_sequence:
                    self.partial = None
                    return result+self.error(cid,4)
                pending.data += packet[5:5+min(59,pending.total-len(pending.data))]
                pending.next_sequence += 1
                pending.deadline = self.clock()+PARTIAL_TIMEOUT
                if len(pending.data) == pending.total:
                    self.partial = None
                    return result+self.dispatch(cid,pending.command,pending.data)
                return result
            self.partial = None  # INIT synchronizes its allocated channel.
        elif not command & 0x80:
            return result+self.error(cid,4)
        length = int.from_bytes(packet[5:7],"big")
        if length > MAX_MESSAGE: return result+self.error(cid,3)
        if command == INIT and length != 8: return result+self.error(cid,3)
        if command not in (INIT,PING,CBOR): return result+self.error(cid,1)
        data = packet[7:7+min(length,57)]
        if len(data) < length:
            self.partial = Partial(cid,command,length,data,0,self.clock()+PARTIAL_TIMEOUT)
            return result
        return result+self.dispatch(cid,command,data)
    def dispatch(self,cid,command,payload):
        if command == INIT:
            assigned = cid
            if cid == BROADCAST:
                if len(self.channels) >= MAX_CHANNELS: return self.error(cid,6)
                assigned = self.next_cid
                self.next_cid += 1
                self.channels.add(assigned)
            return frames(cid,INIT,payload+assigned.to_bytes(4,"big")+bytes([2,0,1,0,0x0c]))
        if command == PING: return frames(cid,PING,payload)
        return frames(cid,CBOR,self.auth.handle(payload))
    def close(self):
        self.partial = None
        self.channels.clear()
        self.auth.close()
