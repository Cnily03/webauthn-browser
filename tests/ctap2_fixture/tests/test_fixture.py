import copy
import hashlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import cborcodec
from authenticator import *
from hid import *
from transport import serve

def unpack(reports):
    first=reports[0]
    cid,command,total=struct.unpack(">IBH",first[:7])
    data=first[7:]
    for sequence,report in enumerate(reports[1:]):
        assert int.from_bytes(report[:4],"big")==cid and report[4]==sequence
        data+=report[5:]
    assert len(data)>=total
    return cid,command,data[:total]

def make_input(rp="ctap.fixture.test",client_hash=None):
    return {1:client_hash or hashlib.sha256(b"synthetic creation client data").digest(),
            2:{"id":rp,"name":"Disposable test RP"},3:{"id":b"synthetic-user","name":"fixture"},
            4:[{"type":"public-key","alg":-7}],7:{"rk":False,"uv":False}}

def parse_registration(result):
    assert result[0]==0,result
    response=cborcodec.decode(result[1:]);auth=response[2]
    assert response[1]=="packed" and response[3]["alg"]==-7
    length=int.from_bytes(auth[53:55],"big")
    credential=auth[55:55+length]
    cose=cborcodec.decode(auth[55+length:])
    assert cose[1]==2 and cose[3]==-7 and cose[-1]==1
    public=ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2],"big"),int.from_bytes(cose[-3],"big"),ec.SECP256R1()).public_key()
    return response,credential,public

def verify_with_openssl(public,signature,message):
    with tempfile.TemporaryDirectory(prefix="fixture-public-proof-") as directory:
        directory=pathlib.Path(directory)
        (directory/"public.pem").write_bytes(public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        (directory/"signature.der").write_bytes(signature)
        (directory/"message.bin").write_bytes(message)
        result=subprocess.run(["openssl","dgst","-sha256","-verify",str(directory/"public.pem"),"-signature",str(directory/"signature.der"),str(directory/"message.bin")],capture_output=True,text=True,timeout=5)
        assert result.returncode==0,(result.stdout,result.stderr)

class CborTests(unittest.TestCase):
    def test_fixed_canonical_vectors(self):
        vectors=[(0,"00"),(-7,"26"),(24,"1818"),(b"ab","426162"),("test","6474657374"),
                 ({1:2,3:-7,-1:1},"a3010203262001"),([True,False,None],"83f5f4f6")]
        for value,hexadecimal in vectors:
            self.assertEqual(cborcodec.encode(value).hex(),hexadecimal)
            self.assertEqual(cborcodec.decode(bytes.fromhex(hexadecimal)),value)
    def test_malformed_duplicate_nonminimal_order_and_bounds(self):
        for raw in [b"",b"\x18\x00",b"\xa2\x01\x00\x01\x01",b"\xa2\x02\x00\x01\x00",b"\xbf\xff",b"\xc0\x00",b"\x61\xff",b"\xf9\0\0",b"\x00\x00",b"\x59\x20\x00",b"\x81"*10+b"\x00",b"\x80"*4097]:
            with self.assertRaises(cborcodec.CborError,msg=raw[:20].hex()):cborcodec.decode(raw)

class AuthenticatorTests(unittest.TestCase):
    def setUp(self): self.auth=Authenticator(simulate_presence=True)
    def call(self,command,data=None):return self.auth.handle(bytes([command])+(b"" if data is None else cborcodec.encode(data)))
    def test_info_does_not_claim_uv_pin_resident_or_u2f(self):
        info=cborcodec.decode(self.call(4)[1:])
        self.assertEqual(info[1],["FIDO_2_0"]);self.assertEqual(len(info[3]),16)
        self.assertEqual(info[4],{"rk":False,"up":True,"plat":False})
        self.assertNotIn(6,info)
    def test_real_self_attestation_assertion_binding_and_monotonic_counters(self):
        creation=json.dumps({"type":"webauthn.create","challenge":"c3ludGhldGlj","origin":"https://ctap.fixture.test","crossOrigin":False},separators=(",",":")).encode()
        creation_hash=hashlib.sha256(creation).digest()
        result=self.call(1,make_input(client_hash=creation_hash))
        registration,identifier,public=parse_registration(result)
        auth=registration[2]
        self.assertEqual(auth[:32],hashlib.sha256(b"ctap.fixture.test").digest())
        self.assertEqual(auth[32],0x41);self.assertEqual(auth[33:37],bytes(4))
        self.assertEqual(auth[37:53],AAGUID);self.assertEqual(len(identifier),32)
        public.verify(registration[3]["sig"],auth+creation_hash,ec.ECDSA(hashes.SHA256()))
        verify_with_openssl(public,registration[3]["sig"],auth+creation_hash)
        with self.assertRaises(InvalidSignature):public.verify(registration[3]["sig"],auth+bytes(32),ec.ECDSA(hashes.SHA256()))
        for counter in [1,2,3]:
            client=json.dumps({"type":"webauthn.get","challenge":f"synthetic-{counter}","origin":"https://ctap.fixture.test"},separators=(",",":")).encode()
            challenge=hashlib.sha256(client).digest()
            assertion=cborcodec.decode(self.call(2,{1:"ctap.fixture.test",2:challenge,3:[{"type":"public-key","id":identifier}]} )[1:])
            self.assertEqual(assertion[1]["id"],identifier)
            self.assertEqual(len(assertion[2]),37);self.assertEqual(assertion[2][:32],auth[:32])
            self.assertEqual(assertion[2][32],1)
            self.assertEqual(int.from_bytes(assertion[2][33:37],"big"),counter)
            public.verify(assertion[3],assertion[2]+challenge,ec.ECDSA(hashes.SHA256()))
            verify_with_openssl(public,assertion[3],assertion[2]+challenge)
            with self.assertRaises(InvalidSignature):public.verify(assertion[3],assertion[2]+creation_hash,ec.ECDSA(hashes.SHA256()))
    def test_allow_list_rp_exclusion_and_ephemeral_lifetime(self):
        registration,identifier,_=parse_registration(self.call(1,make_input()))
        request={1:"ctap.fixture.test",2:bytes(32),3:[{"type":"public-key","id":identifier}]}
        self.assertEqual(self.call(2,dict(request,**{}))[0],0)
        request[1]="localhost";self.assertEqual(self.call(2,request),bytes([NO_CREDENTIALS]))
        request[1]="example.com";self.assertEqual(self.call(2,request),bytes([OPERATION_DENIED]))
        self.assertEqual(self.call(2,{1:"ctap.fixture.test",2:bytes(32)}),bytes([NO_CREDENTIALS]))
        excluded=make_input();excluded[5]=[{"type":"public-key","id":identifier}]
        self.assertEqual(self.call(1,excluded),bytes([CREDENTIAL_EXCLUDED]))
        self.auth.close();self.assertFalse(self.auth.credentials)
        self.assertFalse(Authenticator(simulate_presence=True).credentials)
    def test_presence_and_unsupported_options_never_set_uv(self):
        self.assertEqual(Authenticator().handle(b"\x01"+cborcodec.encode(make_input())),bytes([OPERATION_DENIED]))
        for field,value,error in [(7,{"uv":True},UNSUPPORTED_OPTION),(7,{"rk":True},UNSUPPORTED_OPTION),(7,{"up":True},INVALID_OPTION),(8,b"pinAuth",UNSUPPORTED_OPTION),(9,1,UNSUPPORTED_OPTION)]:
            data=make_input();data[field]=value
            self.assertEqual(self.call(1,data),bytes([error]))
        _,identifier,public=parse_registration(self.call(1,make_input()))
        request={1:"ctap.fixture.test",2:bytes(32),3:[{"type":"public-key","id":identifier}]}
        for value,error in [({"uv":True},UNSUPPORTED_OPTION),({"rk":False},INVALID_OPTION),({"up":1},CBOR_UNEXPECTED_TYPE)]:
            data=copy.deepcopy(request);data[5]=value
            self.assertEqual(self.call(2,data),bytes([error]))
        request[5]={"up":False}
        response=cborcodec.decode(self.call(2,request)[1:]);self.assertEqual(response[2][32],0)
        public.verify(response[3],response[2]+bytes(32),ec.ECDSA(hashes.SHA256()))
    def test_counter_overflow_fails_without_wrapping(self):
        _,identifier,_=parse_registration(self.call(1,make_input()))
        self.auth.credentials[identifier].counter=0xffffffff
        request={1:"ctap.fixture.test",2:bytes(32),3:[{"type":"public-key","id":identifier}]}
        self.assertEqual(self.call(2,request),bytes([NOT_ALLOWED]))
        self.assertEqual(self.auth.credentials[identifier].counter,0xffffffff)
    def test_parameter_bounds_algorithms_unknown_commands_and_capacity(self):
        for data,error in [({},MISSING_PARAMETER),({1:b"short",2:{"id":"localhost"},3:{"id":b"x"},4:[]},INVALID_PARAMETER)]:
            self.assertEqual(self.call(1,data),bytes([error]))
        for alteration,error in [({1:"wrong"},CBOR_UNEXPECTED_TYPE),({4:[{"type":"public-key","alg":-257}]},UNSUPPORTED_ALGORITHM),({3:{"id":b"a"*65}},INVALID_PARAMETER),({7:{"uv":"false"}},CBOR_UNEXPECTED_TYPE)]:
            data=make_input();data.update(alteration);self.assertEqual(self.call(1,data),bytes([error]))
        self.assertEqual(self.auth.handle(b"\x01\xa1\x01"),bytes([INVALID_CBOR]))
        self.assertEqual(self.call(0x06),bytes([INVALID_COMMAND]))
        for _ in range(MAX_CREDENTIALS):self.assertEqual(self.call(1,make_input())[0],0)
        self.assertEqual(self.call(1,make_input()),bytes([KEY_STORE_FULL]))

class HidTests(unittest.TestCase):
    def setUp(self):
        self.now=10.0
        self.device=Device(simulate_presence=True,clock=lambda:self.now)
        self.cid=self.allocate()
    def allocate(self):
        nonce=os.urandom(8)
        cid,command,response=unpack(self.device.report(frames(BROADCAST,INIT,nonce)[0]))
        self.assertEqual((cid,command),(BROADCAST,INIT));self.assertEqual(response[:8],nonce)
        self.assertEqual(response[12:],bytes([2,0,1,0,0x0c]))
        return int.from_bytes(response[8:12],"big")
    def send(self,cid,command,payload):
        out=[]
        for report in frames(cid,command,payload):out+=self.device.report(report)
        return unpack(out)
    def test_fragmented_ping_and_real_cbor(self):
        payload=os.urandom(MAX_MESSAGE)
        self.assertEqual(self.send(self.cid,PING,payload),(self.cid,PING,payload))
        cid,command,result=self.send(self.cid,CBOR,b"\x01"+cborcodec.encode(make_input()))
        parse_registration(result);self.assertEqual((cid,command),(self.cid,CBOR))
        self.assertIsNone(self.device.partial)
    def test_invalid_channels_lengths_commands_sequences_and_report_sizes(self):
        for cid,command,payload,error in [(0,INIT,bytes(8),11),(99,CBOR,b"\x04",11),(BROADCAST,PING,b"",11),(self.cid,INIT,b"short",3),(self.cid,0x88,b"",1)]:
            self.assertEqual(unpack(self.device.report(frames(cid,command,payload)[0]))[2],bytes([error]))
        large=self.cid.to_bytes(4,"big")+bytes([PING])+b"\xff\xff"+bytes(57)
        self.assertEqual(unpack(self.device.report(large))[2],b"\x03")
        pending=frames(self.cid,CBOR,b"\x01"+cborcodec.encode(make_input()))
        self.assertEqual(self.device.report(pending[0]),[])
        wrong=bytearray(pending[1]);wrong[4]=1
        self.assertEqual(unpack(self.device.report(bytes(wrong)))[2],b"\x04")
        self.assertIsNone(self.device.partial)
        for size in [0,63,65,1024]:
            with self.assertRaises(ValueError):self.device.report(bytes(size))
    def test_cancel_resync_timeout_foreign_channel_and_channel_bound(self):
        other=self.allocate()
        request=frames(self.cid,CBOR,b"\x01"+cborcodec.encode(make_input()))
        self.device.report(request[0])
        self.assertEqual(unpack(self.device.report(frames(other,PING,b"x")[0]))[2],b"\x06")
        self.assertEqual(self.device.report(frames(other,CANCEL,b"")[0]),[])
        self.assertIsNotNone(self.device.partial)
        self.assertEqual(unpack(self.device.report(frames(self.cid,CANCEL,b"bad")[0]))[2],b"\x03")
        self.assertIsNotNone(self.device.partial)
        canceled=unpack(self.device.report(frames(self.cid,CANCEL,b"")[0]))
        self.assertEqual(canceled,(self.cid,CBOR,b"\x2d"));self.assertIsNone(self.device.partial)
        self.assertFalse(self.device.auth.credentials)
        self.assertEqual(self.device.report(frames(self.cid,CANCEL,b"")[0]),[])
        self.device.report(request[0]);nonce=bytes(range(8))
        self.assertEqual(unpack(self.device.report(frames(self.cid,INIT,nonce)[0]))[2][:12],nonce+self.cid.to_bytes(4,"big"))
        self.assertIsNone(self.device.partial)
        self.device.report(request[0]);self.now+=PARTIAL_TIMEOUT
        self.assertEqual(unpack(self.device.tick())[2],b"\x05");self.assertEqual(self.device.tick(),[])
        for _ in range(MAX_CHANNELS-2):self.allocate()
        self.assertEqual(unpack(self.device.report(frames(BROADCAST,INIT,bytes(8))[0]))[2],b"\x06")
        self.device.close();self.assertIsNone(self.device.partial);self.assertFalse(self.device.channels)

class PacketSocketTests(unittest.TestCase):
    def test_actual_anonymous_packet_socket_signed_round_trip_and_eof(self):
        host,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        failures=[]
        def run():
            try:serve(peer,simulate_presence=True)
            except Exception as error:failures.append(error)
        thread=threading.Thread(target=run);thread.start();host.settimeout(2)
        def exchange(cid,command,payload):
            for report in frames(cid,command,payload):self.assertEqual(host.send(report),64)
            first=host.recv(65);total=int.from_bytes(first[5:7],"big");reports=[first]
            while 57+(len(reports)-1)*59<total:reports.append(host.recv(65))
            self.assertTrue(all(len(r)==64 for r in reports))
            return unpack(reports)[2]
        nonce=bytes(range(8));cid=int.from_bytes(exchange(BROADCAST,INIT,nonce)[8:12],"big")
        data=make_input();response,identifier,public=parse_registration(exchange(cid,CBOR,b"\x01"+cborcodec.encode(data)))
        public.verify(response[3]["sig"],response[2]+data[1],ec.ECDSA(hashes.SHA256()))
        assertion=cborcodec.decode(exchange(cid,CBOR,b"\x02"+cborcodec.encode({1:"ctap.fixture.test",2:bytes(32),3:[{"type":"public-key","id":identifier}]}))[1:])
        public.verify(assertion[3],assertion[2]+bytes(32),ec.ECDSA(hashes.SHA256()))
        host.close();thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(failures,[])
    def test_packet_size_and_stream_transport_fail_closed(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        with self.assertRaises(ValueError):serve(b)
        a.close();b.close()
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        a.send(bytes(65))
        with self.assertRaises(ValueError):serve(b)
        a.close()

class BrowserVerifierTests(unittest.TestCase):
    def result(self,verifier,kind,auth,identifier=None):
        from acceptance import b64
        client=json.dumps({"type":"webauthn."+kind,"origin":verifier.origin,"crossOrigin":False,"challenge":b64(verifier.challenges[kind])},separators=(",",":")).encode()
        digest=hashlib.sha256(client).digest()
        if kind=="create":
            reply=auth.handle(b"\x01"+cborcodec.encode(make_input("localhost",digest)))
            registration,identifier,_=parse_registration(reply)
            return {"kind":"create","rawId":b64(identifier),"clientDataJSON":b64(client),"attestationObject":b64(cborcodec.encode({"fmt":registration[1],"authData":registration[2],"attStmt":registration[3]}))},identifier
        reply=cborcodec.decode(auth.handle(b"\x02"+cborcodec.encode({1:"localhost",2:digest,3:[{"type":"public-key","id":identifier}]}))[1:])
        return {"kind":"get","rawId":b64(identifier),"clientDataJSON":b64(client),"authenticatorData":b64(reply[2]),"signature":b64(reply[3])},identifier
    def test_verified_browser_output_shapes_and_one_use_challenges(self):
        from acceptance import Verifier
        verifier=Verifier("http://localhost:54321");auth=Authenticator(simulate_presence=True)
        creation,identifier=self.result(verifier,"create",auth)
        self.assertTrue(verifier.accept(creation)["signature_verified"])
        with self.assertRaises(ValueError):verifier.accept(creation)
        assertion,_=self.result(verifier,"get",auth,identifier)
        self.assertEqual(verifier.accept(assertion)["counter"],1)
        with self.assertRaises(ValueError):verifier.accept(assertion)
    def test_wrong_browser_origin_challenge_rp_signature_and_id_are_rejected(self):
        from acceptance import Verifier,b64,binary
        for field in ["origin","challenge","crossOrigin","signature","rawId","rp"]:
            verifier=Verifier("http://localhost:54321");auth=Authenticator(simulate_presence=True)
            creation,_=self.result(verifier,"create",auth)
            if field in ("origin","challenge","crossOrigin"):
                client=json.loads(binary(creation["clientDataJSON"]))
                client[field]=True if field=="crossOrigin" else "wrong"
                creation["clientDataJSON"]=b64(json.dumps(client).encode())
            elif field=="rawId":creation[field]=b64(bytes(32))
            else:
                obj=cborcodec.decode(binary(creation["attestationObject"]))
                if field=="signature":obj["attStmt"]["sig"]=bytes(70)
                else:obj["authData"]=bytes(32)+obj["authData"][32:]
                creation["attestationObject"]=b64(cborcodec.encode(obj))
            with self.assertRaises((ValueError,InvalidSignature),msg=field):verifier.accept(creation)
            self.assertIsNone(verifier.public)
    def test_browser_plan_default_never_launches(self):
        result=subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve().parents[1]/"future_browser_acceptance.py")],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertIn("NOT RUN",result.stdout)
        self.assertIn("No Chromium launch",result.stdout)

if __name__=="__main__":unittest.main(verbosity=2)
