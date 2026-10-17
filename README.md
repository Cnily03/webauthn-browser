# WebAuthn Browser

A Chromium desktop with software WebAuthn authenticators and native FIDO relay,
built with Rust and React / Material UI. The web interface remains in Chinese.

The Compose `.data` directory must belong exclusively to this service; never share
it with a concurrently running container or Chromium. Compose explicitly enables
safe, narrowly scoped singleton-link recovery after container recreation; see
[profile ownership and storage](docs/runtime-storage.md#exclusive-profile-ownership-and-container-recreation).

## Quick start

For a new deployment:

```sh
docker compose up --build -d
```

The single `docker-compose.yml` publishes `8080:8080` on all host interfaces and
uses `restart: unless-stopped`. Passwords are off by default: configure access
passwords and a trusted network boundary before exposing the service.

- [Browser](http://localhost:8080/): software/native mode and movable controls.
- [Settings](http://localhost:8080/settings): security, browser profiles, shared
  authenticators and credential backups.
- [Downloads](http://localhost:8080/downloads): filename, creation time when
  available, size and direct downloads. Public without a password; publish only
  files intended for everyone who can reach the server.

The host bind is now `./.data:/data`. **Existing deployments using `./data` must
stop the container and back up that directory before renaming it to `./.data`;
do not overwrite an existing destination.** Otherwise Compose can start with an
empty profile. See [migration](docs/data-migration.md) before rebuilding older
container-only deployments. No automatic filesystem migration is performed.

`./.data` retains browser history, cookies, user extension settings and keys.
Image-owned engine and ZeroOmega assets update with the image. Mode and helper
address preferences remain in the outer browser's localStorage without a TTL;
pairing tokens do not. Noto CJK fonts provide Chinese glyphs without changing the
browser's language or adding an input method.

Enable multi-profile mode in Browser settings to create independent browser
desktops at `/profile/{name}`. Each has its own cookies, extensions, optional
password and engine idle timeout. The authenticator library is shared. Multiple
viewers can open a profile; its first eligible viewer owns the authentication
engine until release or inactivity (180 seconds by default). Remembered profile
access expires after 30 unused days. See [profiles](docs/profiles.md).

Initial page entry ensures one maximized browser window. Manual reconnect closes
and relaunches Chromium, then verifies saved tabs; unsaved page state and
session-only cookies are not guaranteed. See [browser lifecycle](docs/browser-lifecycle.md).
[Local-address offers](docs/local-navigation.md) open a detected URL in the outer
browser only after a click.

## Deployment boundary

Compose explicitly selects `--no-sandbox` and publishes all host interfaces;
the gateway does not restrict Host/Origin admission. Use trusted content, HTTPS
and access passwords. Keep `./.data` and private-key backups private, and never
share a live profile between containers. Native relay requires exact-Origin
approval in the local helper; see [platform and validation limits](TESTING.md).

## Source and development

- `src/`: modular Rust gateway; `src/fido-relay/` is the shared protocol library.
- `web/`: React / MUI; `extension/`: managed browser engine; `runtime/`: supervision.
- `helper/`: CLI/Desktop; `native-hid-hook/`: FIDO HID adapter; `tests/`: integration contracts.

[Development guidance](AGENTS.md) · [Tests and evidence](TESTING.md) ·
[Usage](docs/usage-guide.md) · [Helper builds](helper/README.md) ·
[Startup troubleshooting](docs/startup-troubleshooting.md)

Third-party notices are in [NOTICE](NOTICE).
The source ZIP contains tracked source and an empty `downloads/` directory.
Docker builds from a fresh checkout, including web assets and hash-verified
ZeroOmega downloads. Runtime `./downloads` is mounted separately; existing files
are not removed. Git history, compiled outputs and build caches are excluded.

## License

Copyright (c) Cnily03. All rights reserved.

Licensed under the [GPL-3.0-or-later](LICENSE) license.
