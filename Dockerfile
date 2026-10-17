# Compile React + Material UI locally. Only the static output reaches runtime.
FROM node:24-bookworm-slim AS frontend
WORKDIR /build/web
RUN npm install --global pnpm@latest --no-audit --no-fund
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web ./
RUN pnpm run build

# Chromium and its sandbox come from Debian's security-maintained packages.
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY native-hid-hook ./native-hid-hook
# Path dev-dependency is used by the report-adapter integration tests.
COPY helper ./helper
# The native handshake is compiled against the same image-owned asset digest.
COPY extension ./extension
COPY --from=frontend /build/web/dist ./web/dist
RUN cargo build --locked --release \
    && mkdir -p /build/native-hid-runtime \
    && if [ "$(rustc -vV | sed -n 's/^host: //p')" = "x86_64-unknown-linux-gnu" ]; then \
       cargo build --locked --release --manifest-path native-hid-hook/Cargo.toml \
       && install -m 0444 native-hid-hook/target/release/libuserland_hid_hook.so /build/native-hid-runtime/; \
       fi

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates chromium chromium-sandbox fontconfig fonts-dejavu-core \
       fonts-liberation fonts-noto-cjk novnc openbox python3 python3-cryptography python3-xlib python3-dbus python3-gi dbus tini wmctrl x11-utils x11-xserver-utils x11vnc xvfb \
    && fc-cache -f -s \
    && fc-list --quiet 'Noto Sans CJK SC:charset=4e2d 6587' \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 authbrowser \
    && useradd --uid 10001 --gid authbrowser --home-dir /data --no-create-home authbrowser \
    && install -d -o authbrowser -g authbrowser -m 0700 /data /data/run \
    && install -d -o root -g root -m 0755 /downloads \
    && install -d -o authbrowser -g authbrowser -m 0700 /tmp/webauthn-browser-cache \
    && install -d -o root -g root -m 1777 /tmp/.X11-unix \
    && test -u /usr/lib/chromium/chrome-sandbox
COPY --from=builder /build/target/release/webauthn-browser /usr/local/bin/webauthn-browser
COPY --from=builder /build/native-hid-runtime /opt/webauthn-browser/native
COPY native-hid-hook/LICENSE /opt/webauthn-browser/licenses/native-hid-hook/LICENSE
COPY native-hid-hook/licenses /opt/webauthn-browser/licenses/native-hid-hook/dependencies
COPY runtime /opt/webauthn-browser/runtime
COPY extension /opt/webauthn-browser/extension
COPY vendor/zeroomega /opt/webauthn-browser/vendor/zeroomega
RUN python3 /opt/webauthn-browser/runtime/install_zeroomega.py \
    --lock /opt/webauthn-browser/vendor/zeroomega/release.json \
    --target /opt/webauthn-browser/extensions/zeroomega \
    --source-target /opt/webauthn-browser/licenses/zeroomega
COPY vendor/webrtc-control /opt/webauthn-browser/vendor/webrtc-control
RUN python3 /opt/webauthn-browser/runtime/install_webrtc_control.py \
    --lock /opt/webauthn-browser/vendor/webrtc-control/release.json \
    --target /opt/webauthn-browser/extensions/webrtc-control \
    --provenance-target /opt/webauthn-browser/licenses/webrtc-control
# Fixed system path avoids ambiguity from --user-data-dir and XDG_CONFIG_HOME.
COPY runtime/com.auth_browser.proxy.json /etc/chromium/native-messaging-hosts/com.auth_browser.proxy.json
RUN chmod 0555 /opt/webauthn-browser/extension \
    && chmod 0444 /opt/webauthn-browser/extension/* \
    && python3 /opt/webauthn-browser/runtime/verify_extension.py
COPY runtime/openbox-menu.xml /var/lib/openbox/debian-menu.xml
COPY --from=frontend /build/web/dist /opt/webauthn-browser/web/dist
COPY LICENSE NOTICE /opt/webauthn-browser/
ENV HOME=/data \
    DISPLAY=:99 \
    XDG_RUNTIME_DIR=/data/run \
    XDG_CACHE_HOME=/tmp/webauthn-browser-cache \
    AUTH_BROWSER_FIDO_HOOK_PATH=/opt/webauthn-browser/native/libuserland_hid_hook.so \
    AUTH_BROWSER_STORE=/data/auth-browser.json \
    AUTH_BROWSER_DOWNLOADS_DIR=/downloads
WORKDIR /opt/webauthn-browser
# Root is used only to prepare an empty /data mount. The entrypoint drops to
# UID/GID 10001 before starting Python supervisor, gateway or Chromium.
USER root
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python3", "/opt/webauthn-browser/runtime/healthcheck.py"]
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "/opt/webauthn-browser/runtime/entrypoint.py"]
