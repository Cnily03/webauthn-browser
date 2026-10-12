"""Independent browser-output verifier. Accepts only one synthetic localhost RP run."""
import base64
import hashlib
import json
import secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import cborcodec
from authenticator import AAGUID

def b64(raw): return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
def binary(value):
    if type(value) is not str or len(value)>16384: raise ValueError("invalid binary field")
    raw=base64.b64decode(value+"="*((-len(value))%4),altchars=b"-_",validate=True)
    if b64(raw)!=value: raise ValueError("noncanonical base64url")
    return raw

class Verifier:
    def __init__(self,origin):
        if not origin.startswith("http://localhost:") or not origin[17:].isdigit():raise ValueError("localhost origin required")
        self.origin=origin
        self.challenges={"create":secrets.token_bytes(32),"get":secrets.token_bytes(32)}
        self.used=set()
        self.public=None
        self.identifier=None
        self.counter=0
    def client(self,data,kind):
        raw=binary(data["clientDataJSON"])
        client=json.loads(raw)
        if client.get("type")!="webauthn."+kind or client.get("origin")!=self.origin or client.get("crossOrigin",False) is not False:
            raise ValueError("client data origin/type/cross-origin mismatch")
        if client.get("challenge")!=b64(self.challenges[kind]):raise ValueError("challenge mismatch")
        return hashlib.sha256(raw).digest()
    def auth(self,auth,attested):
        if len(auth)<37 or auth[:32]!=hashlib.sha256(b"localhost").digest():raise ValueError("RP binding mismatch")
        if auth[32]!=(0x41 if attested else 0x01):raise ValueError("unexpected presence/UV/extension flags")
        return int.from_bytes(auth[33:37],"big")
    def accept(self,data):
        kind=data.get("kind")
        if kind not in ("create","get") or kind in self.used:raise ValueError("unexpected/replayed ceremony")
        # Consume before verification, so a rejected browser result cannot be retried under the same challenge.
        self.used.add(kind)
        challenge=self.client(data,kind)
        raw_id=binary(data["rawId"])
        if kind=="create":
            obj=cborcodec.decode(binary(data["attestationObject"]))
            if obj.get("fmt")!="packed":raise ValueError("browser did not return verifiable packed self-attestation")
            statement=obj["attStmt"];auth=obj["authData"]
            counter=self.auth(auth,True)
            if type(statement) is not dict or statement.get("alg")!=-7 or set(statement)!={"alg","sig"}:raise ValueError("unexpected attestation statement")
            if len(auth)<55:raise ValueError("truncated attested credential")
            if auth[37:53]!=AAGUID or counter!=0:raise ValueError("unexpected fixture identity/initial counter")
            length=int.from_bytes(auth[53:55],"big")
            identifier=auth[55:55+length]
            if length!=32 or identifier!=raw_id:raise ValueError("credential ID mismatch")
            cose=cborcodec.decode(auth[55+length:])
            if set(cose)!={1,3,-1,-2,-3} or cose[1]!=2 or cose[3]!=-7 or cose[-1]!=1 or len(cose[-2])!=32 or len(cose[-3])!=32:
                raise ValueError("unsupported credential public key")
            public=ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2],"big"),int.from_bytes(cose[-3],"big"),ec.SECP256R1()).public_key()
            public.verify(statement["sig"],auth+challenge,ec.ECDSA(hashes.SHA256()))
            self.public,self.identifier,self.counter=public,identifier,counter
        else:
            if self.public is None or raw_id!=self.identifier:raise ValueError("assertion without matching registration")
            auth=binary(data["authenticatorData"]);counter=self.auth(auth,False)
            if len(auth)!=37 or counter<=self.counter:raise ValueError("nonmonotonic assertion counter")
            self.public.verify(binary(data["signature"]),auth+challenge,ec.ECDSA(hashes.SHA256()))
            self.counter=counter
        return {"ok":True,"ceremony":kind,"signature_verified":True,"counter":self.counter}
