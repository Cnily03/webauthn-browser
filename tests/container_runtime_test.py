"""Dependency-free runtime contract tests: python3 -m unittest discover -s tests -p '*_test.py'."""
import importlib.util
import io
from pathlib import Path
import signal
import tempfile
import json
import re
import tomllib
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("supervisor", ROOT / "runtime/supervisor.py")
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)


class ContainerContractTests(unittest.TestCase):
    def test_single_port_dedicated_mount_explicit_flag_and_default_seccomp(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertEqual([line for line in dockerfile.splitlines() if line.startswith("EXPOSE ")], ["EXPOSE 8080"])
        self.assertIn("USER root", dockerfile)
        self.assertIn("runtime/entrypoint.py", dockerfile)
        self.assertNotIn("VOLUME", dockerfile)
        self.assertIn('"8080:8080"', compose)
        self.assertIn('restart: unless-stopped', compose)
        self.assertIn('command: ["--no-sandbox"]', compose)
        self.assertIn('"./.data:/data"', compose)
        self.assertNotIn('"./data:/data"', compose)
        for forbidden in ("security_opt:", "devices:", "privileged:", "cap_add:", "env_file:"):
            self.assertNotIn(forbidden, compose)

    def test_project_name_matches_packages_image_and_runtime_entrypoints(self):
        package = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(package["package"]["name"], "webauthn-browser")
        frontend = json.loads((ROOT / "web/package.json").read_text())
        self.assertEqual(frontend["name"], "webauthn-browser-frontend")
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("  webauthn-browser:", compose)
        self.assertIn("    image: webauthn-browser", compose)
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY --from=builder /build/target/release/webauthn-browser /usr/local/bin/webauthn-browser", dockerfile)
        self.assertIn("WORKDIR /opt/webauthn-browser", dockerfile)
        manifest = json.loads((ROOT / "runtime/com.auth_browser.proxy.json").read_text())
        self.assertEqual(manifest["name"], "com.auth_browser.proxy")
        self.assertEqual(manifest["path"], "/opt/webauthn-browser/runtime/native-proxy-host")
        self.assertIn("<title>WebAuthn Browser</title>", (ROOT / "web/index.html").read_text())

    def test_native_proxy_is_private_and_packaged(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY extension /opt/webauthn-browser/extension", dockerfile)
        self.assertIn("/etc/chromium/native-messaging-hosts/com.auth_browser.proxy.json", dockerfile)
        self.assertIn("--load-extension=/opt/webauthn-browser/extension", (ROOT / "runtime/supervisor.py").read_text())
        host = ROOT / "runtime/native-proxy-host"
        self.assertTrue(host.stat().st_mode & 0o111)
        self.assertIn('exec /usr/local/bin/webauthn-browser --native-proxy "$@"', host.read_text())
        manifest = json.loads((ROOT / "runtime/com.auth_browser.proxy.json").read_text())
        self.assertEqual(manifest["type"], "stdio")
        self.assertEqual(len(manifest["allowed_origins"]), 1)
        self.assertNotIn("*", manifest["allowed_origins"][0])

    def test_tini_is_pid_one_and_sandbox_helper_is_kept(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn('ENTRYPOINT ["/usr/bin/tini", "--",', dockerfile)
        self.assertIn("chromium-sandbox", dockerfile)
        self.assertIn("test -u /usr/lib/chromium/chrome-sandbox", dockerfile)
        runtime = (ROOT / "runtime/supervisor.py").read_text()
        for forbidden in ("--disable-setuid-sandbox", "--disable-seccomp-filter-sandbox", "--disable-namespace-sandbox", "--single-process"):
            self.assertNotIn(forbidden, runtime)

    def test_image_installs_and_checks_chinese_glyph_fonts(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        runtime_image = dockerfile.split("FROM debian:bookworm-slim\n", 1)[1]
        packages = runtime_image.split("apt-get install -y --no-install-recommends", 1)[1].split("&&", 1)[0].split()
        for package in ("fontconfig", "fonts-noto-cjk", "fonts-dejavu-core", "fonts-liberation"):
            self.assertIn(package, packages)
        self.assertIn("&& fc-cache -f -s", runtime_image)
        # fc-list --quiet fails when no installed face contains both 中 and 文;
        # fc-match alone can succeed with a fallback that lacks the glyphs.
        self.assertIn("&& fc-list --quiet 'Noto Sans CJK SC:charset=4e2d 6587'", runtime_image)

    def test_chinese_font_support_does_not_override_browser_language(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        for forbidden in ("chromium-l10n", "locale-gen", "zh_CN", "LANG=", "LANGUAGE=", "LC_ALL=", "LC_MESSAGES="):
            self.assertNotIn(forbidden, dockerfile)
        instance = supervisor.Supervisor()
        for options in ({}, {"new_window": True}, {"restore_session": True}):
            command = instance.browser_command(**options)
            self.assertFalse(any(flag.startswith(("--lang=", "--accept-lang=")) for flag in command))
        for name in ("entrypoint.py", "supervisor.py"):
            self.assertNotIn("Preferences", (ROOT / "runtime" / name).read_text())

    def test_runtime_flag_is_explicit_and_reaches_only_chromium(self):
        self.assertFalse(supervisor.parse_args([]).no_sandbox)
        self.assertTrue(supervisor.parse_args(["--no-sandbox"]).no_sandbox)
        for enabled in (False, True):
            instance = supervisor.Supervisor(no_sandbox=enabled)
            calls = []
            instance.spawn = lambda name, command: calls.append((name, command))
            instance.wait_ready = Mock()
            with patch.object(supervisor, "prepare_x_socket_dir"):
                instance.start_desktop()
            chrome = next(command for name, command in calls if name == "Chromium")
            self.assertEqual("--no-sandbox" in chrome, enabled)
            for name, command in calls:
                if name != "Chromium":
                    self.assertNotIn("--no-sandbox", command)
        self.assertNotIn("sandbox intact", supervisor.Supervisor(True).browser_failure())

    def test_persistent_data_is_excluded_from_source_and_build(self):
        self.assertIn("/data/", (ROOT / ".gitignore").read_text())
        self.assertIn("data", (ROOT / ".dockerignore").read_text().splitlines())
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("AUTH_BROWSER_STORE=/data/auth-browser.json", dockerfile)
        self.assertIn("--user-data-dir=/data/chromium", (ROOT / "runtime/supervisor.py").read_text())

    def test_runtime_and_cache_are_transient_without_changing_profile_paths(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn('"/data/run:uid=10001,gid=10001,mode=0700"', compose)
        self.assertIn('"/tmp/webauthn-browser-cache:uid=10001,gid=10001,mode=0700"', compose)
        command = supervisor.Supervisor().browser_command()
        self.assertIn("--disk-cache-dir=/tmp/webauthn-browser-cache/chromium", command)
        self.assertIn("--user-data-dir=/data/chromium", command)
        source = (ROOT / "runtime/supervisor.py").read_text()
        self.assertIn('"XDG_CACHE_HOME": str(CACHE_PATH)', source)
        self.assertNotIn('"/data/cache"', source)
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("XDG_CACHE_HOME=/tmp/webauthn-browser-cache", dockerfile)
        self.assertIn("-m 0700 /tmp/webauthn-browser-cache", dockerfile)

    def test_transient_cache_is_private_and_never_repairs_existing_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "data/cache"
            legacy.mkdir(parents=True)
            (legacy / "existing").write_bytes(b"keep old cache; no cleanup authorized")
            path = root / "new-cache"
            supervisor.prepare_cache_dir(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            supervisor.prepare_cache_dir(path)
            (path / "cached").write_bytes(b"cache survives repeated setup")
            path.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "mode 0700"):
                supervisor.prepare_cache_dir(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertEqual((path / "cached").read_bytes(), b"cache survives repeated setup")
            self.assertEqual((legacy / "existing").read_bytes(), b"keep old cache; no cleanup authorized")
            link = root / "cache-link"
            link.symlink_to(path, target_is_directory=True)
            with self.assertRaises(OSError):
                supervisor.prepare_cache_dir(link)

    def test_web_source_and_generated_assets_are_separate(self):
        self.assertTrue((ROOT / "web/src/App.tsx").is_file())
        self.assertFalse((ROOT / "frontend").exists())
        self.assertIn("outDir: 'dist'", (ROOT / "web/vite.config.ts").read_text())
        ignores = (ROOT / ".gitignore").read_text().splitlines()
        self.assertIn("/web/dist/", ignores)
        self.assertIn("/web/node_modules/", ignores)
        self.assertNotIn("/web/", ignores)
        self.assertIn('read_to_string("web/dist/index.html")', (ROOT / "src/http/assets.rs").read_text())
        self.assertIn('ServeDir::new("web/dist")', (ROOT / "src/http/mod.rs").read_text())
        self.assertNotIn('include_str!("web/dist', (ROOT / "src/http/assets.rs").read_text())

    def test_frontend_uses_latest_pnpm_with_frozen_dependencies(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("FROM node:24-bookworm-slim AS frontend", dockerfile)
        self.assertIn("COPY web/package.json web/pnpm-lock.yaml ./", dockerfile)
        self.assertIn("RUN pnpm install --frozen-lockfile", dockerfile)
        self.assertIn("RUN pnpm run build", dockerfile)
        bootstrap = "RUN npm install --global pnpm@latest --no-audit --no-fund"
        self.assertIn(bootstrap, dockerfile)
        self.assertNotIn("npm ", dockerfile.replace(bootstrap, "").replace("pnpm ", ""))
        self.assertIn("COPY --from=frontend /build/web/dist /opt/webauthn-browser/web/dist", dockerfile)
        self.assertIn("COPY web ./", dockerfile)
        self.assertIn("web/dist", (ROOT / ".dockerignore").read_text().splitlines())
        self.assertIn("web/node_modules", (ROOT / ".dockerignore").read_text().splitlines())
        package = json.loads((ROOT / "web/package.json").read_text())
        self.assertNotIn("packageManager", package, "Do not override the installed latest pnpm with an exact version")
        self.assertNotIn("packageManager", package.get("devEngines", {}))
        self.assertNotIn("corepack", dockerfile)
        self.assertFalse((ROOT / "web/package-lock.json").exists())
        self.assertFalse((ROOT / "web/yarn.lock").exists())
        lock = (ROOT / "web/pnpm-lock.yaml").read_text()
        self.assertTrue(lock.startswith("lockfileVersion: '9.0'\n"))
        self.assertIn("\npackages:\n", lock)
        self.assertIn("\nsnapshots:\n", lock)
        # Inspect only pnpm's generated root importer, keeping this suite free of
        # a YAML dependency. Frozen installation validates the complete graph.
        importer = lock.split("\n  .:\n", 1)[1].split("\npackages:\n", 1)[0]
        for group in ("dependencies", "devDependencies"):
            with self.subTest(group=group):
                section = re.search(rf"(?ms)^    {group}:\n(.*?)(?=^    \S|\Z)", importer)
                self.assertIsNotNone(section)
                entries = re.findall(r"(?m)^      (?:'([^']+)'|([^:\n]+)):\n        specifier: ([^\n]+)\n", section[1])
                self.assertEqual({quoted or plain: specifier for quoted, plain, specifier in entries}, package[group])
        self.assertIn("@mui/material", package["dependencies"])
        self.assertIn("@emotion/react", package["dependencies"])
        self.assertIn("react", package["dependencies"])

    def test_browser_test_harness_keeps_sandbox(self):
        frontend = (ROOT / "tests/frontend_test.py").read_text()
        self.assertIn("chromium_sandbox=True", frontend)
        self.assertNotIn("--no-sandbox", frontend)
        self.assertNotIn("chromium_sandbox=False", frontend)

    def test_gateway_starts_before_desktop_for_diagnostics(self):
        instance = supervisor.Supervisor()
        calls = []
        instance.spawn = lambda name, command: calls.append(("spawn", name, command))
        instance.wait_ready = lambda name, check, **kwargs: calls.append(("ready", name))
        instance.check_children = Mock(side_effect=InterruptedError("stop test"))
        instance.write_status = Mock()
        instance.open_control = Mock()
        with patch.object(supervisor.os, "getuid", return_value=10001), patch.object(supervisor.os, "umask"), patch.object(supervisor.Path, "mkdir"), patch.object(supervisor, "prepare_cache_dir"), patch.object(supervisor, "prepare_x_socket_dir"), patch.dict(supervisor.os.environ, {}, clear=False):
            with self.assertRaises(InterruptedError):
                instance.run()
        order = [(item[0], item[1]) for item in calls]
        self.assertLess(order.index(("spawn", "gateway")), order.index(("ready", "Chromium")))
        self.assertLess(order.index(("spawn", "gateway")), order.index(("ready", "x11vnc")))
        chrome = next(item[2] for item in calls if item[:2] == ("spawn", "Chromium"))
        self.assertFalse(any(arg.startswith("--remote-debugging") for arg in chrome))
        vnc = next(item[2] for item in calls if item[:2] == ("spawn", "x11vnc"))
        self.assertIn("-localhost", vnc)

    def test_chromium_failure_keeps_gateway_and_reports_failure(self):
        instance = supervisor.Supervisor()
        launches = []
        instance.spawn = lambda name, command: launches.append(name)
        def ready(name, check, **kwargs):
            if name == "Chromium":
                raise RuntimeError(supervisor.SANDBOX_FAILURE)
        instance.wait_ready = ready
        instance.write_status = Mock()
        instance.open_control = Mock()
        instance.shutdown = Mock()
        instance.check_children = Mock(side_effect=InterruptedError("stop test"))
        with patch.object(supervisor.os, "getuid", return_value=10001), patch.object(supervisor.os, "umask"), patch.object(supervisor.Path, "mkdir"), patch.object(supervisor, "prepare_cache_dir"), patch.object(supervisor, "prepare_x_socket_dir"), patch.dict(supervisor.os.environ, {}, clear=False):
            with self.assertRaises(InterruptedError):
                instance.run()
        self.assertIn("gateway", launches)
        instance.write_status.assert_called_with("failed", supervisor.SANDBOX_FAILURE)
        instance.shutdown.assert_called_once_with(desktop_only=True)

    def test_any_child_failure_stops_service(self):
        instance = supervisor.Supervisor()
        instance.children = [("Chromium", Mock(poll=Mock(return_value=1)))]
        with self.assertRaisesRegex(RuntimeError, "sandbox intact"):
            instance.check_children()
        instance.children = [("Xvfb", Mock(poll=Mock(return_value=0)))]
        with self.assertRaisesRegex(RuntimeError, "Xvfb exited"):
            instance.check_children()

    def test_shutdown_signals_process_groups_even_for_exited_launchers(self):
        instance = supervisor.Supervisor()
        child = Mock(pid=123, poll=Mock(return_value=1))
        instance.children = [("Chromium", child)]
        with patch.object(supervisor.os, "killpg") as kill:
            instance.shutdown()
        kill.assert_any_call(123, signal.SIGTERM)
        kill.assert_any_call(123, signal.SIGKILL)
        child.wait.assert_called_once()

    def test_cancellation_aborts_readiness(self):
        instance = supervisor.Supervisor()
        instance.request_stop(signal.SIGTERM, None)
        with self.assertRaises(InterruptedError):
            instance.wait_ready("Chromium", lambda: False)

    def test_desktop_cleanup_does_not_kill_gateway(self):
        instance = supervisor.Supervisor()
        gateway = Mock(pid=123, poll=Mock(return_value=None))
        chrome = Mock(pid=456, poll=Mock(return_value=1))
        instance.children = [("gateway", gateway), ("Chromium", chrome)]
        with patch.object(supervisor.os, "killpg") as kill:
            instance.shutdown(desktop_only=True)
        self.assertEqual(instance.children, [("gateway", gateway)])
        self.assertEqual({call.args[0] for call in kill.call_args_list}, {456})
        gateway.wait.assert_not_called()

    def test_x_socket_directory_image_and_tmpfs(self):
        self.assertIn("-o root -g root -m 1777 /tmp/.X11-unix", (ROOT / "Dockerfile").read_text())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".X11-unix"
            previous = supervisor.os.umask(0o077)
            try:
                supervisor.prepare_x_socket_dir(path)
            finally:
                supervisor.os.umask(previous)
            self.assertEqual(path.stat().st_mode & 0o7777, 0o1777)
            supervisor.prepare_x_socket_dir(path)
            link = Path(temp) / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, "symbolic"):
                supervisor.prepare_x_socket_dir(link)

    def test_status_is_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runtime.json"
            with patch.object(supervisor, "STATUS_PATH", path):
                supervisor.Supervisor().write_status("failed", "namespace denied")
            self.assertEqual(json.loads(path.read_text())["state"], "failed")
            self.assertFalse(path.with_suffix(".tmp").exists())

    def test_healthcheck_uses_readiness(self):
        healthcheck = (ROOT / "runtime/healthcheck.py").read_text()
        self.assertIn("/readyz", healthcheck)
        self.assertNotIn("9222", healthcheck)
        self.assertNotIn("CDP_ENDPOINT", (ROOT / "Dockerfile").read_text())

    def test_startup_readiness_requires_attached_native_proxy(self):
        instance = supervisor.Supervisor()
        for payload, expected in (({}, False), ({"engine_connected": False}, False),
                                  ({"engine_connected": "true"}, False), ({"engine_connected": True}, True)):
            instance.opener = Mock()
            instance.opener.open.return_value = io.BytesIO(json.dumps(payload).encode())
            with patch.dict(supervisor.os.environ, {"AUTH_BROWSER_ALLOWED_HOSTS": " , browser.example:8080, localhost:8080"}):
                self.assertEqual(instance.proxy_ready(), expected)
            request = instance.opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "http://127.0.0.1:8080/api/status")
            self.assertIsNone(request.get_header("Host"))  # Obsolete allowlist has no effect.

    def test_native_readiness_requires_control_and_private_bridge(self):
        instance = supervisor.Supervisor()
        instance.children = [(name, Mock(poll=Mock(return_value=None)))
                             for name in ("private D-Bus", "BlueZ bridge")]
        for control, socket_live, expected in ((True, True, True), (False, True, False),
                                                (True, False, False)):
            instance.opener = Mock()
            instance.opener.open.return_value = io.BytesIO(json.dumps({
                "engine_connected": False, "native_qr_mode": True,
                "control_connected": control}).encode())
            with patch.object(supervisor.Path, "is_socket", return_value=socket_live):
                self.assertEqual(instance.proxy_ready(), expected)
        instance.children.pop()
        instance.opener.open.return_value = io.BytesIO(json.dumps({
            "engine_connected": True, "native_qr_mode": True,
            "control_connected": True}).encode())
        with patch.object(supervisor.Path, "is_socket", return_value=True):
            self.assertFalse(instance.proxy_ready())

    def test_bus_and_bridge_are_ready_before_chromium(self):
        instance = supervisor.Supervisor()
        calls = []
        instance.spawn = lambda name, command: calls.append(("spawn", name))
        instance.wait_ready = lambda name, check, **kwargs: calls.append(("ready", name))
        with patch.object(supervisor, "prepare_x_socket_dir"):
            instance.start_desktop()
        self.assertLess(calls.index(("ready", "private D-Bus")), calls.index(("spawn", "BlueZ bridge")))
        self.assertLess(calls.index(("ready", "BlueZ bridge")), calls.index(("spawn", "Chromium")))

    def test_root_is_rejected(self):
        instance = supervisor.Supervisor()
        with patch.object(supervisor.os, "getuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "non-root"):
                instance.run()


if __name__ == "__main__":
    unittest.main()
