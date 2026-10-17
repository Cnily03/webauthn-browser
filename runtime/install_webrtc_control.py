#!/usr/bin/env python3
"""Verify and install the official pinned CRX as read-only image assets."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import struct
import urllib.parse
import urllib.request
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

LIMIT = 32 * 1024 * 1024
EXTENSION_ID = 'fjkmabmdepjfammlpliljpnbhleegehm'


def extension_id(key):
    return ''.join(chr(97 + int(c, 16)) for c in hashlib.sha256(key).hexdigest()[:32])


def fields(data):
    """Read the length-delimited fields used by the CRX3 header protobuf."""
    def varint(offset):
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError('Truncated CRX header')
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, offset
        raise ValueError('Invalid CRX varint')

    offset = 0
    while offset < len(data):
        tag, offset = varint(offset)
        if tag & 7 != 2 or tag >> 3 == 0:
            raise ValueError('Unsupported CRX header field')
        length, offset = varint(offset)
        end = offset + length
        if end > len(data):
            raise ValueError('Truncated CRX header field')
        yield tag >> 3, data[offset:end]
        offset = end


def verified_zip(data, lock):
    if len(data) < 12 or data[:8] != b'Cr24\x03\x00\x00\x00':
        raise ValueError('Expected CRX3 archive')
    size = struct.unpack('<I', data[8:12])[0]
    if size > len(data) - 12:
        raise ValueError('Truncated CRX3 archive')
    header = list(fields(data[12:12 + size]))
    signed = [value for tag, value in header if tag == 10000]
    key = base64.b64decode(lock['manifest_key'], validate=True)
    if len(signed) != 1 or extension_id(key) != EXTENSION_ID or lock['extension_id'] != EXTENSION_ID:
        raise ValueError('Extension key/ID mismatch')
    if list(fields(signed[0])) != [(1, hashlib.sha256(key).digest()[:16])]:
        raise ValueError('CRX signed ID mismatch')
    payload = data[12 + size:]
    message = b'CRX3 SignedData\0' + struct.pack('<I', len(signed[0])) + signed[0] + payload
    for tag, proof in header:
        if tag == 2:
            parts = list(fields(proof))
            if len(parts) == 2 and dict(parts).get(1) == key:
                serialization.load_der_public_key(key).verify(
                    dict(parts)[2], message, padding.PKCS1v15(), hashes.SHA256())
                return payload
    raise ValueError('Missing publisher signature')


def install(lock, target, provenance_target):
    if target.exists() or provenance_target.exists():
        raise ValueError('Refusing to replace an existing asset directory')
    url = lock['archive']['url']
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'clients2.googleusercontent.com'
            or not parsed.path.startswith('/crx/blobs/') or parsed.query or parsed.fragment):
        raise ValueError('Unexpected asset source')
    with urllib.request.urlopen(url, timeout=60) as response:
        # Pinned blob URLs need no redirects. Reject any changed destination.
        if response.geturl() != url:
            raise ValueError('Unexpected asset redirect')
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != lock['archive']['sha256']:
        raise ValueError('Pinned asset SHA-256 mismatch')
    archive = verified_zip(data, lock)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 2048 or len(set(names)) != len(names) or sum(e.file_size for e in entries) > LIMIT:
            raise ValueError('Invalid archive bounds')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('Unsafe archive entry')
        manifest = json.loads(bundle.read('manifest.json'))
        if (manifest.get('manifest_version') != 3 or manifest.get('version') != lock['version']
                or manifest.get('name') != 'WebRTC Control'):
            raise ValueError('Unexpected extension version or identity')
        worker = manifest.get('background', {}).get('service_worker')
        if not worker or worker not in names:
            raise ValueError('Missing MV3 service worker')
        if manifest.get('key', lock['manifest_key']) != lock['manifest_key']:
            raise ValueError('Conflicting manifest key')
        target.mkdir(parents=True)
        # Store verification metadata is reserved in unpacked extensions. Preserve
        # the original CRX separately; omit only that metadata from loaded assets.
        for entry in entries:
            if PurePosixPath(entry.filename).parts[0] != '_metadata':
                bundle.extract(entry, target)
    manifest['key'] = lock['manifest_key']
    (target / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    provenance_target.mkdir(parents=True)
    (provenance_target / lock['archive']['filename']).write_bytes(data)
    (provenance_target / 'release.json').write_text(json.dumps(lock, indent=2) + '\n')
    for root in (target, provenance_target):
        for path in root.rglob('*'):
            path.chmod(0o555 if path.is_dir() else 0o444)
        root.chmod(0o555)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--provenance-target', type=Path, required=True)
    args = parser.parse_args()
    install(json.loads(args.lock.read_text()), args.target, args.provenance_target)
