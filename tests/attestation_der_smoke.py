#!/usr/bin/env python3
"""Independent strict X.509 regression against the actual backend (no browser).

Requires tests/requirements.txt (cryptography >= 43) and a built backend; absence
is a hard failure, never a silent skip. Verified with cryptography 50.0.0. Run:
  python3 tests/attestation_der_smoke.py --backend-binary target/debug/webauthn-browser

Uses a temporary store, synthetic identities, and free localhost port 8080 only.
No external RP registration or user data is touched. This proves DER/API behavior,
not Yubico trust acceptance or a live browser registration.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier


ROOT = Path(__file__).resolve().parents[1]
MODEL = "00112233-4455-4677-8899-aabbccddeeff"
AAGUID_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


class Api:
    def __init__(self):
        self.token = ""
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, body=None):
        request = urllib.request.Request(
            "http://127.0.0.1:8080" + path,
            None if body is None else json.dumps(body).encode(),
            {"Content-Type": "application/json", "X-CSRF-Token": self.token})
        with self.opener.open(request, timeout=12) as response:
            return json.load(response)


@contextmanager
def backend(binary, store):
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", 8080)) == 0:
            raise RuntimeError("Port 8080 must be free for this isolated test")
    env = dict(os.environ, AUTH_BROWSER_STORE=str(store),
               AUTH_BROWSER_PROXY_SOCKET=str(store.parent / "run" / "proxy.sock"))
    process = subprocess.Popen([str(binary)], cwd=ROOT, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        api = Api()
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError("Synthetic backend exited before readiness")
            try:
                api.token = api.request("/api/status")["csrf_token"]
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("Synthetic backend did not become ready")
        yield api
    finally:
        process.terminate()
        try:
            process.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def fixture(noncanonical=False):
    """Generate both independently signed certificates without rcgen/x509-parser."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synthetic independent lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic DER fixture"),
    ])
    now = datetime.now(timezone.utc)
    constraints = (
        x509.UnrecognizedExtension(ExtensionOID.BASIC_CONSTRAINTS,
                                   bytes.fromhex("3003010100"))
        if noncanonical else x509.BasicConstraints(ca=False, path_length=None)
    )
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(constraints, critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                        key_encipherment=False, data_encipherment=False,
                                        key_agreement=False, key_cert_sign=False,
                                        crl_sign=False, encipher_only=False,
                                        decipher_only=False), critical=True)
            .add_extension(x509.UnrecognizedExtension(
                AAGUID_OID, b"\x04\x10" + bytes.fromhex(MODEL.replace("-", ""))),
                critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def import_input(cert, key):
    return dict(kind="import",
                certificate_chain_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
                private_key_pem=key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()).decode())


def create(api, name, attestation):
    return api.request("/api/keys", dict(
        name=name, provider_label="Independent test", model_aaguid=MODEL,
        attestation_mode="basic", attestation=attestation))["key"]


def strict_certificate(der):
    cert = x509.load_der_x509_certificate(der)
    # Extension parsing is lazy: loading alone would miss the exact regression.
    constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert constraints.value.ca is False
    assert constraints.value.path_length is None
    assert cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature
    assert cert.extensions.get_extension_for_oid(AAGUID_OID).value.value == (
        b"\x04\x10" + bytes.fromhex(MODEL.replace("-", "")))
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                             ec.ECDSA(cert.signature_hash_algorithm))
    return cert


def run(binary):
    bad_cert, bad_key = fixture(noncanonical=True)
    bad_der = bad_cert.public_bytes(serialization.Encoding.DER)
    try:
        x509.load_der_x509_certificate(bad_der).extensions
    except ValueError as error:
        text = str(error)
        assert "EncodedDefault" in text and "BasicConstraints::ca" in text, text
        print("PASS: strict parser reproduces EncodedDefault at BasicConstraints::ca")
    else:
        raise AssertionError("Independent parser accepted the noncanonical DEFAULT FALSE")

    good_cert, good_key = fixture()
    good_der = good_cert.public_bytes(serialization.Encoding.DER)
    strict_certificate(good_der)
    with tempfile.TemporaryDirectory() as temporary:
        store = Path(temporary) / "store.json"
        with backend(binary, store) as api:
            generated = create(api, "Synthetic generated certificate", dict(
                kind="generate", country="US", organization="Synthetic lab",
                common_name="Synthetic generated device", valid_days=365))
            summary = generated["attestation_certificate"]
            assert summary["registration_usable"] and summary["warning"] is None
            generated_key = api.request("/api/backup")["keys"][0]
            der = base64.b64decode(generated_key["attestation_identity"]["certificate_chain_der"][0])
            strict_certificate(der)
            imported = create(api, "Synthetic imported certificate", import_input(good_cert, good_key))
            before = api.request("/api/backup")["keys"]
            imported_key = next(key for key in before if key["id"] == imported["id"])
            imported_der = base64.b64decode(
                imported_key["attestation_identity"]["certificate_chain_der"][0])
            assert imported_der == good_der, "Import must preserve original signed DER bytes"
            try:
                create(api, "Rejected synthetic certificate", import_input(bad_cert, bad_key))
            except urllib.error.HTTPError as error:
                assert error.code == 400
                message = error.read().decode()
                assert "Noncanonical basicConstraints DER" in message
                assert "PRIVATE KEY" not in message
            else:
                raise AssertionError("Backend imported noncanonical BasicConstraints")
            assert api.request("/api/backup")["keys"] == before
        print("PASS: generated/imported certificates parse and verify independently; bad import is atomic")

        # Simulate an existing old store, never a new import. Only this temporary
        # synthetic store is changed, and startup must retain its identity bytes.
        data = json.loads(store.read_text())
        legacy = data["keys"][0]
        legacy["attestation_identity"] = dict(
            private_key_pkcs8=base64.b64encode(bad_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())).decode(),
            certificate_chain_der=[base64.b64encode(bad_der).decode()])
        expected = json.loads(json.dumps(data["keys"]))
        store.write_text(json.dumps(data))
        with backend(binary, store) as api:
            public = next(key for key in api.request("/api/keys")["keys"]
                          if key["id"] == legacy["id"])
            summary = public["attestation_certificate"]
            assert summary["currently_valid"] is True
            assert summary["registration_usable"] is False
            assert "DER" in summary["warning"]
            assert api.request("/api/backup")["keys"] == expected
        assert json.loads(store.read_text())["keys"] == expected
        assert store.stat().st_mode & 0o777 == 0o600
        print("PASS: legacy certificate store reopens unchanged and exposes a registration warning")
    print("Independent X.509 implementation: cryptography " + cryptography.__version__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-binary", type=Path,
                        default=ROOT / "target/release/webauthn-browser")
    run(parser.parse_args().backend_binary.resolve())
