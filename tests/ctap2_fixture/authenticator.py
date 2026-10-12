"""Disposable synthetic CTAP2 authenticator. NEVER use real accounts or secrets.

Presence is deliberately simulated only when the fixture launcher opts in.
Only allow-listed test RPs are served; private keys never leave process memory.
"""
from dataclasses import dataclass
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import cborcodec

ALLOWED_RPS = frozenset({"localhost", "ctap.fixture.test"})
AAGUID = bytes.fromhex("b35a619911124fe399cf000000000001")  # unregistered test-only identity
MAX_CREDENTIALS = 16
INVALID_COMMAND = 0x01
INVALID_PARAMETER = 0x02
CBOR_UNEXPECTED_TYPE = 0x11
INVALID_CBOR = 0x12
MISSING_PARAMETER = 0x14
CREDENTIAL_EXCLUDED = 0x19
UNSUPPORTED_ALGORITHM = 0x26
OPERATION_DENIED = 0x27
KEY_STORE_FULL = 0x28
UNSUPPORTED_OPTION = 0x2b
INVALID_OPTION = 0x2c
NO_CREDENTIALS = 0x2e
NOT_ALLOWED = 0x30

class CtapError(Exception):
    def __init__(self, code): self.code = code

def require(condition, code=INVALID_PARAMETER):
    if not condition: raise CtapError(code)

def typed(value, kind):
    require(type(value) is kind, CBOR_UNEXPECTED_TYPE)
    return value

def required(data, key, kind):
    require(key in data, MISSING_PARAMETER)
    return typed(data[key], kind)

def rp_id(value):
    typed(value, str)
    require(value in ALLOWED_RPS, OPERATION_DENIED)
    return value

def client_hash(value):
    typed(value, bytes)
    require(len(value) == 32)
    return value

def descriptors(value):
    typed(value, list)
    require(len(value) <= 32)
    ids = []
    for descriptor in value:
        typed(descriptor, dict)
        require(required(descriptor,"type",str) == "public-key")
        credential = required(descriptor,"id",bytes)
        require(1 <= len(credential) <= 1024)
        ids.append(credential)
    return ids

def options(data, field, *, create):
    opts = typed(data.get(field, {}), dict)
    for name, value in opts.items():
        typed(name,str);typed(value,bool)
        if name == "uv" and value: raise CtapError(UNSUPPORTED_OPTION)
        if name == "rk" and (value or not create): raise CtapError(UNSUPPORTED_OPTION if create else INVALID_OPTION)
        if name == "up" and create: raise CtapError(INVALID_OPTION)
    return opts.get("up", True)

@dataclass
class Credential:
    rp: str
    key: object
    counter: int = 0

class Authenticator:
    def __init__(self, *, simulate_presence=False):
        self.simulate_presence = simulate_presence
        self.credentials = {}
    def info(self):
        return {1:["FIDO_2_0"], 3:AAGUID, 4:{"rk":False,"up":True,"plat":False}, 5:4096}
    def handle(self, payload):
        if not payload: return bytes([INVALID_COMMAND])
        command, raw = payload[0], payload[1:]
        try:
            if command == 4:
                require(not raw)
                answer = self.info()
            elif command in (1,2):
                try: data = typed(cborcodec.decode(raw),dict)
                except cborcodec.CborError: raise CtapError(INVALID_CBOR) from None
                answer = self.make(data) if command == 1 else self.get(data)
            else: raise CtapError(INVALID_COMMAND)
            return b"\0" + cborcodec.encode(answer)
        except CtapError as error:
            return bytes([error.code])
    def make(self,data):
        challenge = client_hash(required(data,1,bytes))
        rp = rp_id(required(required(data,2,dict),"id",str))
        user = required(data,3,dict)
        user_id = required(user,"id",bytes)
        require(1 <= len(user_id) <= 64)
        params = required(data,4,list)
        require(1 <= len(params) <= 32)
        supported = False
        for param in params:
            typed(param,dict)
            kind = required(param,"type",str)
            alg = required(param,"alg",int)
            supported |= kind == "public-key" and alg == -7
        require(supported,UNSUPPORTED_ALGORITHM)
        options(data,7,create=True)
        require(8 not in data and 9 not in data,UNSUPPORTED_OPTION)
        if 6 in data: typed(data[6],dict)  # No extensions advertised; unknown extensions ignored.
        exclude = descriptors(data.get(5,[]))
        require(self.simulate_presence,OPERATION_DENIED)
        require(not any(i in self.credentials and self.credentials[i].rp == rp for i in exclude),CREDENTIAL_EXCLUDED)
        require(len(self.credentials) < MAX_CREDENTIALS,KEY_STORE_FULL)
        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key().public_numbers()
        cose = {1:2,3:-7,-1:1,-2:public.x.to_bytes(32,"big"),-3:public.y.to_bytes(32,"big")}
        identifier = secrets.token_bytes(32)
        while identifier in self.credentials: identifier = secrets.token_bytes(32)
        auth = hashlib.sha256(rp.encode()).digest() + b"\x41" + bytes(4)
        auth += AAGUID + len(identifier).to_bytes(2,"big") + identifier + cborcodec.encode(cose)
        signature = private.sign(auth+challenge,ec.ECDSA(hashes.SHA256()))
        self.credentials[identifier] = Credential(rp,private)
        return {1:"packed",2:auth,3:{"alg":-7,"sig":signature}}
    def get(self,data):
        rp = rp_id(required(data,1,str))
        challenge = client_hash(required(data,2,bytes))
        present = options(data,5,create=False)
        require(6 not in data and 7 not in data,UNSUPPORTED_OPTION)
        if 4 in data: typed(data[4],dict)
        allowed = descriptors(data.get(3,[]))
        require(not present or self.simulate_presence,OPERATION_DENIED)
        match = next((i for i in allowed if i in self.credentials and self.credentials[i].rp == rp),None)
        require(match is not None,NO_CREDENTIALS)
        credential = self.credentials[match]
        require(credential.counter < 0xffffffff,NOT_ALLOWED)
        counter = credential.counter + 1
        auth = hashlib.sha256(rp.encode()).digest() + bytes([1 if present else 0]) + counter.to_bytes(4,"big")
        signature = credential.key.sign(auth+challenge,ec.ECDSA(hashes.SHA256()))
        credential.counter = counter
        return {1:{"type":"public-key","id":match},2:auth,3:signature}
    def close(self):
        self.credentials.clear()  # Best effort lifetime cleanup, not a claim of Python memory zeroization.
