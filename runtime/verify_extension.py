#!/usr/bin/env python3
"""Validate the image's own broker assets; never read or edit Chromium profiles."""
import base64
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_VERSION = "1.0.29"
EXPECTED_ID = "hjfbndgjlhfjaplmakeicgoibanbncaf"
ASSETS = ("manifest.json", "background.js", "upgrade.html", "upgrade.js", "local_navigation.js", "browser_window.js")
BUILD_FILE = "build.sha256"
BUILD_STAMP = re.compile(rb"const extensionBuild = '[0-9a-f]{64}';")


def read_assets(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Unsafe packaged extension directory")
    if set(path.name for path in source.iterdir()) - set((*ASSETS, BUILD_FILE)):
        raise ValueError("Unexpected packaged extension asset")
    contents = {}
    for name in ASSETS:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or unsafe packaged extension asset: {name}")
        contents[name] = path.read_bytes()
    return contents


def validate_identity(contents, host_manifest):
    manifest = json.loads(contents["manifest.json"])
    if manifest.get("version") != EXPECTED_VERSION:
        raise ValueError("Packaged extension manifest has an incompatible version")
    if manifest.get("background") != {"service_worker": "background.js"}:
        raise ValueError("Unexpected broker service worker")
    if set(manifest.get("permissions", [])) != {"webAuthenticationProxy", "nativeMessaging", "alarms", "webNavigation", "webRequest", "tabs", "tabGroups"}:
        raise ValueError("Unexpected broker permissions")
    if set(manifest.get("host_permissions", [])) != {
        "http://*/*", "https://*/*"
    }:
        raise ValueError("Unexpected navigation observer hosts")
    if any(manifest.get(name) for name in ("web_accessible_resources", "externally_connectable", "content_scripts")):
        raise ValueError("Broker recovery resources must remain extension-private")
    digest = hashlib.sha256(base64.b64decode(manifest["key"], validate=True)).hexdigest()[:32]
    extension_id = ''.join(chr(ord('a') + int(char, 16)) for char in digest)
    if extension_id != EXPECTED_ID:
        raise ValueError("Packaged extension identity changed")
    host = json.loads(Path(host_manifest).read_text())
    if host.get("allowed_origins") != [f"chrome-extension://{EXPECTED_ID}/"]:
        raise ValueError("Native host does not allow exactly the packaged extension")
    for filename, constant in (("background.js", "extensionVersion"), ("upgrade.js", "version")):
        if not re.search(r"const " + constant + r" = ['\"]" + re.escape(EXPECTED_VERSION) + r"['\"];", contents[filename].decode()):
            raise ValueError(f"Packaged {filename} has an incompatible build stamp")


def fingerprint(contents):
    """Hash every executable/recovery asset, excluding only its own digest literal.

    The literal is compiled into the running worker, rather than fetched from
    disk, so an old worker with the same manifest version still reports its old
    build. Chromium's shared service-worker database is deliberately untouched.
    """
    digest = hashlib.sha256()
    for name in ASSETS:
        content = contents[name]
        if name in ("background.js", "upgrade.js"):
            if len(BUILD_STAMP.findall(content)) != 1:
                raise ValueError(f"Missing or ambiguous image fingerprint: {name}")
            content = BUILD_STAMP.sub(b"const extensionBuild = '" + b'0' * 64 + b"';", content)
        digest.update(name.encode() + b'\0' + content + b'\0')
    return digest.hexdigest()


def verify(source, host_manifest):
    source = Path(source)
    contents = read_assets(source)
    validate_identity(contents, host_manifest)
    expected = fingerprint(contents)
    build = source / BUILD_FILE
    if build.is_symlink() or not build.is_file() or build.read_bytes() != expected.encode():
        raise ValueError("Packaged extension fingerprint does not match its image assets")
    for name in ("background.js", "upgrade.js"):
        if BUILD_STAMP.search(contents[name]).group() != b"const extensionBuild = '" + expected.encode() + b"';":
            raise ValueError(f"Packaged {name} has a stale image fingerprint")
    return EXPECTED_VERSION, expected


def stamp(source, host_manifest):
    """Explicit source-build step only. Normal image startup is read-only."""
    source = Path(source)
    contents = read_assets(source)
    validate_identity(contents, host_manifest)
    expected = fingerprint(contents)
    build = source / BUILD_FILE
    if build.is_symlink() or (build.exists() and not build.is_file()):
        raise ValueError("Unsafe image fingerprint file")
    for name in ("background.js", "upgrade.js"):
        (source / name).write_bytes(BUILD_STAMP.sub(
            b"const extensionBuild = '" + expected.encode() + b"';", contents[name]))
    build.write_bytes(expected.encode())
    return verify(source, host_manifest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", default="/opt/webauthn-browser/extension")
    parser.add_argument("host", nargs="?", default="/etc/chromium/native-messaging-hosts/com.auth_browser.proxy.json")
    parser.add_argument("--stamp", action="store_true", help="Explicitly stamp edited source assets before building; never used at startup")
    args = parser.parse_args()
    try:
        version, digest = (stamp if args.stamp else verify)(args.source, args.host)
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f"Packaged authentication extension check failed: {error}")
    print(f"[supervisor] packaged extension={version} build={digest}; browser profile untouched (Chromium manages its shared worker cache)", flush=True)
