# WebAuthn Browser

A Chromium desktop with software WebAuthn authenticators and native FIDO relay,
built with Rust and React / Material UI. The web interface remains in Chinese.

## Quick start

For a new deployment:

```sh
docker compose up --build -d
```

The single `docker-compose.yml` publishes `8080:8080` on all host interfaces and
uses `restart: unless-stopped`. Passwords are off by default: configure access
passwords and a trusted network boundary before exposing the service.

- [Browser](http://localhost:8080/): software/native mode and movable controls.
- [Settings](http://localhost:8080/settings): authenticators, credentials, backups
  and separate settings/desktop passwords.
- [Downloads](http://localhost:8080/downloads): filename, creation time when
  available, size and direct downloads.

The host bind is now `./.data:/data`. **Existing deployments using `./data` must
stop the container and back up that directory before renaming it to `./.data`;
do not overwrite an existing destination.** Otherwise Compose can start with an
empty profile. See [migration](docs/data-migration.md) before rebuilding older
container-only deployments. No automatic migration is performed.

`./.data` retains browser history, cookies, user extension settings and keys.
Image-owned engine and ZeroOmega assets update with the image. Mode and helper
address preferences remain in the outer browser's localStorage without a TTL;
pairing tokens do not. Noto CJK fonts provide Chinese glyphs without changing the
browser's language or adding an input method.

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
The source ZIP contains tracked source plus release files under `downloads/`.
It excludes Git history, `web/dist/`, dependency folders and build caches. Docker
builds the web assets from source; downloads are not tracked in Git.

## License

Copyright (c) Cnily03. All rights reserved.

Licensed under the [GPL-3.0-or-later](LICENSE) license.
