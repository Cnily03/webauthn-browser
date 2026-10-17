#!/usr/bin/env python3
"""Install pinned image assets only. Never opens or edits a Chromium profile."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import urllib.request
import zipfile

LIMIT = 32 * 1024 * 1024


def verified_bytes(record, cache):
    # The image build deliberately supplies no local cache. An explicit cache
    # remains available for offline installer tests or a separate manual run.
    path = cache / record['filename'] if cache is not None else None
    if path is not None and path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Asset cache must contain ordinary files')
        if path.stat().st_size > LIMIT:
            raise ValueError('Asset exceeds size limit')
        data = path.read_bytes()
    else:
        # Only build-time official, pinned sources; no startup download/update.
        if not record['url'].startswith('https://github.com/zero-peak/ZeroOmega/'):
            raise ValueError('Unexpected asset source')
        with urllib.request.urlopen(record['url'], timeout=60) as response:
            data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('Pinned asset SHA-256 mismatch')
    return data


def install(lock, cache, target, source_target):
    archive = verified_bytes(lock['archive'], cache)
    source = verified_bytes(lock['source'], cache)
    if target.exists() or source_target.exists():
        raise ValueError('Refusing to replace an existing asset directory')
    key = base64.b64decode(lock['manifest_key'], validate=True)
    extension_id = ''.join(chr(97 + int(c, 16)) for c in hashlib.sha256(key).hexdigest()[:32])
    if extension_id != lock['extension_id']:
        raise ValueError('Extension key/ID mismatch')
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
        if manifest.get('manifest_version') != 3 or manifest.get('version') != lock['version']:
            raise ValueError('Unexpected extension version')
        for required in ('COPYING', 'AUTHORS', manifest['background']['service_worker']):
            if required not in names:
                raise ValueError('Missing extension/license asset')
        target.mkdir(parents=True)
        bundle.extractall(target)
    # The official ZIP omits its public key. Preserve the verified CRX/Store ID
    # across image rebuilds so Chromium retains the user's extension settings.
    manifest['key'] = lock['manifest_key']
    (target / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    source_target.mkdir(parents=True)
    (source_target / lock['source']['filename']).write_bytes(source)
    (source_target / 'release.json').write_text(json.dumps(lock, indent=2) + '\n')
    for name in ('COPYING', 'AUTHORS'):
        shutil.copyfile(target / name, source_target / name)
    for root in (target, source_target):
        for path in root.rglob('*'):
            path.chmod(0o555 if path.is_dir() else 0o444)
        root.chmod(0o555)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--cache', type=Path, help='Optional verified local cache; omitted for image builds')
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--source-target', type=Path, required=True)
    args = parser.parse_args()
    install(json.loads(args.lock.read_text()), args.cache, args.target, args.source_target)
