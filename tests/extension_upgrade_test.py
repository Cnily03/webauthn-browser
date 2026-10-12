"""Profile-safe upgrade contracts with actual assets and mocked Chromium launch."""
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


supervisor = module("upgrade_supervisor", ROOT / "runtime/supervisor.py")
verifier = module("extension_verifier", ROOT / "runtime/verify_extension.py")


class UpgradeTests(unittest.TestCase):
    def runtime(self):
        runtime = supervisor.Supervisor()
        runtime.children = [("Chromium", Mock(poll=Mock(return_value=None)))]
        runtime.spawn = Mock()
        runtime.write_status = Mock()
        runtime.browser_windows = Mock(return_value=["0x04000007"])
        return runtime

    def status(self, runtime, body):
        runtime.opener.open = Mock(return_value=io.StringIO(json.dumps(body)))
        return runtime.proxy_ready()

    def expire_attempt(self, runtime):
        runtime.extension_upgrade_deadline = 0
        runtime.extension_upgrade_expires_ms = 0

    def test_legacy_handshake_opens_only_own_upgrade_page_once(self):
        runtime = self.runtime()
        body = {"mode_error": "extension_upgrade_required", "engine_connected": True,
                "native_qr_mode": True, "control_connected": True}
        self.assertFalse(self.status(runtime, body))
        self.assertFalse(self.status(runtime, body))
        runtime.spawn.assert_called_once()
        name, command = runtime.spawn.call_args.args
        self.assertEqual(name, "Chromium window launcher")
        target = urlsplit(command[-1])
        self.assertEqual(target.scheme + "://" + target.netloc + target.path, supervisor.EXTENSION_UPGRADE_URL)
        query = parse_qs(target.query)
        self.assertEqual(set(query), {"attempt", "expires"})
        self.assertEqual(query["attempt"], [runtime.extension_upgrade_episode + "-1"])
        self.assertEqual(query["expires"], [str(runtime.extension_upgrade_expires_ms)])
        self.assertIn("--user-data-dir=/data/chromium", command)
        self.assertFalse(any("remote-debugging" in arg for arg in command))
        self.assertNotIn("--no-sandbox", command)
        self.assertTrue(self.status(runtime, {"engine_connected": True}))
        self.assertEqual(runtime.spawn.call_count, 1)
        self.assertFalse(runtime.extension_upgrade_recovering)
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")

    def test_first_stale_attempt_retries_once_then_current_handshake_recovers(self):
        runtime = self.runtime()
        body = {"mode_error": "extension_upgrade_required"}
        self.assertFalse(self.status(runtime, body))
        first_url = runtime.spawn.call_args.args[1][-1]
        self.expire_attempt(runtime)
        self.assertFalse(self.status(runtime, body))
        self.assertEqual(runtime.spawn.call_count, 2)
        second_url = runtime.spawn.call_args.args[1][-1]
        self.assertNotEqual(first_url, second_url)
        self.assertEqual(parse_qs(urlsplit(second_url).query)["attempt"], [runtime.extension_upgrade_episode + "-2"])
        self.assertFalse(runtime.extension_upgrade_failed)
        self.assertFalse(self.status(runtime, body))
        self.assertEqual(runtime.spawn.call_count, 2)
        self.assertTrue(self.status(runtime, {"engine_connected": True}))
        self.assertFalse(runtime.extension_upgrade_recovering)
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")

    def test_exhaustion_reports_failure_once_and_late_current_handshake_recovers(self):
        runtime = self.runtime()
        body = {"mode_error": "extension_upgrade_required"}
        for _ in range(supervisor.EXTENSION_UPGRADE_ATTEMPTS):
            self.assertFalse(self.status(runtime, body))
            self.expire_attempt(runtime)
        self.assertFalse(self.status(runtime, body))
        self.assertTrue(runtime.extension_upgrade_failed)
        self.assertEqual(runtime.write_status.call_args.args[0], "failed")
        count = runtime.write_status.call_count
        self.assertFalse(self.status(runtime, body))
        self.assertEqual(runtime.write_status.call_count, count)
        self.assertTrue(self.status(runtime, {"engine_connected": True}))
        self.assertFalse(runtime.extension_upgrade_failed)
        self.assertEqual(runtime.write_status.call_args.args[0], "ready")
        self.assertEqual(runtime.spawn.call_count, 2)

    def test_disconnected_result_after_first_reload_can_retry_without_rejection_flag(self):
        runtime = self.runtime()
        self.assertFalse(self.status(runtime, {"mode_error": "extension_upgrade_required"}))
        self.expire_attempt(runtime)
        self.assertFalse(self.status(runtime, {"engine_connected": False, "control_connected": False}))
        self.assertEqual(runtime.spawn.call_count, 2)
        self.assertTrue(self.status(runtime, {"engine_connected": True}))

    def test_both_clocks_expire_before_retry_and_stopping_blocks_new_attempt(self):
        runtime = self.runtime()
        with patch.object(supervisor.time, "monotonic", return_value=100) as monotonic, \
                patch.object(supervisor.time, "time", return_value=1800000000) as wall:
            runtime.request_extension_upgrade()
            monotonic.return_value = 115
            runtime.request_extension_upgrade()
            self.assertEqual(runtime.spawn.call_count, 1)
            wall.return_value += 15
            runtime.stopping = True
            runtime.request_extension_upgrade()
            self.assertEqual(runtime.spawn.call_count, 1)
            runtime.stopping = False
            runtime.request_extension_upgrade()
            self.assertEqual(runtime.spawn.call_count, 2)

    def test_only_explicit_reconnect_after_exhaustion_starts_new_bounded_episode(self):
        runtime = self.runtime()
        runtime.children.append(("Xvfb", Mock(poll=Mock(return_value=None))))
        runtime.display_ready = Mock(return_value=True)
        runtime.vnc_ready = Mock(return_value=True)
        runtime.browser_windows = Mock(return_value=["0x123"])
        runtime.wait_ready = Mock()
        runtime.restore_browser = Mock()
        runtime.extension_upgrade_attempts = supervisor.EXTENSION_UPGRADE_ATTEMPTS
        runtime.extension_upgrade_attempted = True
        runtime.extension_upgrade_recovering = True
        runtime.extension_upgrade_failed = True
        self.expire_attempt(runtime)
        previous = runtime.extension_upgrade_episode
        runtime.reconnect()  # Automatic recovery cannot grant more attempts.
        self.assertEqual(runtime.extension_upgrade_episode, previous)
        self.assertEqual(runtime.extension_upgrade_attempts, 2)
        runtime.reconnect(allow_extension_retry=True)
        current = runtime.extension_upgrade_episode
        self.assertNotEqual(current, previous)
        self.assertFalse(runtime.extension_upgrade_failed)
        self.assertEqual(runtime.extension_upgrade_attempts, 0)
        runtime.request_extension_upgrade()
        runtime.reconnect(allow_extension_retry=True)  # Duplicate user action while active.
        self.assertEqual(runtime.extension_upgrade_episode, current)
        self.assertEqual(runtime.extension_upgrade_attempts, 1)
        self.assertEqual(runtime.spawn.call_count, 1)

    def test_current_worker_never_reloads(self):
        runtime = self.runtime()
        self.assertTrue(self.status(runtime, {"engine_connected": True}))
        runtime.spawn.assert_not_called()

    def test_no_browser_no_recovery_and_existing_launcher_defers(self):
        runtime = self.runtime()
        runtime.children = []
        runtime.request_extension_upgrade()
        self.assertFalse(runtime.extension_upgrade_attempted)
        runtime.children = [("Chromium", Mock(poll=Mock(return_value=None))),
                            ("Chromium window launcher", Mock())]
        runtime.request_extension_upgrade()
        self.assertFalse(runtime.extension_upgrade_attempted)
        runtime.spawn.assert_not_called()

    def test_transient_failed_spawn_consumes_one_attempt_and_can_recover(self):
        runtime = self.runtime()
        runtime.spawn.side_effect = OSError("launch failed")
        with self.assertRaises(OSError):
            runtime.request_extension_upgrade()
        runtime.request_extension_upgrade()
        self.assertEqual(runtime.spawn.call_count, 1)
        runtime.spawn.side_effect = None
        self.expire_attempt(runtime)
        runtime.request_extension_upgrade()
        self.assertEqual(runtime.spawn.call_count, 2)
        self.assertTrue(self.status(runtime, {"engine_connected": True}))
        runtime.start_browser()
        self.assertFalse(runtime.extension_upgrade_attempted)
        self.assertEqual(runtime.extension_upgrade_attempts, 0)

    def test_packaged_assets_and_native_identity_match(self):
        version, digest = verifier.verify(ROOT / "extension", ROOT / "runtime/com.auth_browser.proxy.json")
        self.assertEqual(version, "1.0.29")
        self.assertEqual(len(digest), 64)
        self.assertEqual((ROOT / "extension/build.sha256").read_text(), digest)

    def test_navigation_observer_packaging_and_permission_contract(self):
        contents = verifier.read_assets(ROOT / "extension")
        self.assertIn("local_navigation.js", verifier.ASSETS)
        self.assertIn("browser_window.js", verifier.ASSETS)
        self.assertIn(b"importScripts('browser_window.js')", contents["background.js"])
        self.assertIn(b"importScripts('local_navigation.js')", contents["background.js"])
        manifest = json.loads(contents["manifest.json"])
        self.assertEqual(set(manifest["host_permissions"]), {"http://*/*", "https://*/*"})
        self.assertNotIn("webRequestBlocking", manifest["permissions"])
        self.assertTrue({"tabs", "tabGroups"}.issubset(manifest["permissions"]))
        self.assertIn("COPY extension /opt/webauthn-browser/extension", (ROOT / "Dockerfile").read_text())
        for extra in ["<all_urls>", "file:///*", "*://*/*"]:
            changed = dict(contents)
            modified = dict(manifest, host_permissions=manifest["host_permissions"] + [extra])
            changed["manifest.json"] = json.dumps(modified).encode()
            with self.assertRaisesRegex(ValueError, "observer hosts"):
                verifier.validate_identity(changed, ROOT / "runtime/com.auth_browser.proxy.json")

    def test_same_version_code_change_requires_a_new_image_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "extension"
            shutil.copytree(ROOT / "extension", source)
            version, original = verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            worker = source / "background.js"
            worker.write_bytes(worker.read_bytes() + b"\n// New image, same manifest version.\n")
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            new_version, new_build = verifier.stamp(source, ROOT / "runtime/com.auth_browser.proxy.json")
            self.assertEqual(version, new_version)
            self.assertNotEqual(original, new_build)
            self.assertEqual(verifier.stamp(source, ROOT / "runtime/com.auth_browser.proxy.json"),
                             (new_version, new_build))
            self.assertIn(new_build, worker.read_text())
            self.assertIn(new_build, (source / "upgrade.js").read_text())

    def test_all_packaged_assets_and_stamps_are_checked(self):
        for name in verifier.ASSETS:
            with self.subTest(asset=name), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "extension"
                shutil.copytree(ROOT / "extension", source)
                asset = source / name
                asset.write_bytes(asset.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
        for name in ("background.js", "upgrade.js", "build.sha256"):
            with self.subTest(stamp=name), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "extension"
                shutil.copytree(ROOT / "extension", source)
                asset = source / name
                original = (source / "build.sha256").read_bytes()
                asset.write_bytes(asset.read_bytes().replace(original, b"0" * 64))
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")

    def test_startup_verification_never_touches_shared_or_user_profile_state(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            fixtures = {
                "auth-browser.json": b'{"keys":["private-key"],"settings_password_hash":"unchanged"}',
                "chromium/Default/History": b"user browsing history",
                "chromium/Default/Cookies": b"website sign-in cookies",
                "chromium/Default/Login Data": b"saved passwords",
                "chromium/Default/Preferences": b'{"safebrowsing":{"enabled":true},"extensions":{"settings":{"user-plugin":{"state":1}}}}',
                "chromium/Default/Secure Preferences": b"protected preferences and MACs",
                "chromium/Default/Service Worker/Database/000001.ldb": b"shared user-plugin and built-in registrations",
                "chromium/Default/Service Worker/ScriptCache/12": b"shared worker cache, do not guess ownership",
                "chromium/Default/Extension State/000001.ldb": b"shared extension data",
                "chromium/Default/Extensions/user-plugin/1.0/manifest.json": b"user-installed extension",
                "chromium/Default/Local Extension Settings/user-plugin/000001.ldb": b"user extension settings",
                "chromium/Local State": b"profile security settings",
            }
            for relative, content in fixtures.items():
                path = data / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o600)
            def snapshot():
                return {str(path.relative_to(data)): (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                        for path in data.rglob("*") if path.is_file()}
            before = snapshot()
            for _ in range(2):
                verifier.verify(ROOT / "extension", ROOT / "runtime/com.auth_browser.proxy.json")
            self.assertEqual(before, snapshot())

    def test_packaging_and_startup_fail_closed_without_mutating_profiles(self):
        source = (ROOT / "runtime/supervisor.py").read_text()
        self.assertIn('"/opt/webauthn-browser/runtime/verify_extension.py"', source)
        self.assertNotIn('"--stamp"', source)
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY extension ./extension", dockerfile)
        self.assertIn("chmod 0555 /opt/webauthn-browser/extension", dockerfile)
        self.assertIn("chmod 0444 /opt/webauthn-browser/extension/*", dockerfile)
        self.assertIn('include_str!("../../extension/build.sha256")', (ROOT / "src/browser/broker.rs").read_text())

    def test_invalid_image_stops_before_chromium_is_spawned(self):
        runtime = supervisor.Supervisor()
        error = subprocess.CalledProcessError(1, ["verify_extension.py"])
        with patch.object(supervisor.subprocess, "run", side_effect=error), \
                patch.object(supervisor.subprocess, "Popen") as spawn:
            with self.assertRaises(subprocess.CalledProcessError):
                runtime.start_browser()
        spawn.assert_not_called()
        self.assertEqual(runtime.children, [])

    def test_symlink_and_unexpected_packaged_assets_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "extension"
            shutil.copytree(ROOT / "extension", source)
            link = Path(directory) / "link"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory"):
                verifier.verify(link, ROOT / "runtime/com.auth_browser.proxy.json")
            (source / "unexpected.js").write_text("unverified code")
            with self.assertRaisesRegex(ValueError, "Unexpected"):
                verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            (source / "unexpected.js").unlink()
            stamp = source / "build.sha256"
            stamp.unlink()
            outside = Path(directory) / "outside"
            outside.write_text("keep")
            stamp.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                verifier.stamp(source, ROOT / "runtime/com.auth_browser.proxy.json")
            self.assertEqual(outside.read_text(), "keep")

    def test_stale_image_files_detected_and_current_copy_validates_without_profile_writes(self):
        # Simulate a reused profile beside old/current image assets. This tests
        # packaging and data preservation, not Chromium's worker cache behavior.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "data/chromium/Default"
            profile.mkdir(parents=True)
            for name, value in (("Cookies", b"cookie fixture"), ("Login Data", b"password fixture"),
                                ("Preferences", b'{"unchanged":true}')):
                (profile / name).write_bytes(value)
            before = {path.name: path.read_bytes() for path in profile.iterdir()}
            source = root / "extension"
            shutil.copytree(ROOT / "extension", source)
            worker = source / "background.js"
            worker.write_text(worker.read_text().replace("1.0.29", "1.0.27"))
            with self.assertRaisesRegex(ValueError, "build stamp"):
                verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            shutil.copytree(ROOT / "extension", source, dirs_exist_ok=True)
            verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")
            self.assertEqual(before, {path.name: path.read_bytes() for path in profile.iterdir()})

    def test_upgrade_resources_are_not_web_accessible_and_identity_is_unchanged(self):
        manifest = json.loads((ROOT / "extension/manifest.json").read_text())
        for name in ("web_accessible_resources", "externally_connectable", "content_scripts"):
            self.assertNotIn(name, manifest)
        self.assertNotIn("management", manifest["permissions"])
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "extension"
            shutil.copytree(ROOT / "extension", source)
            manifest["web_accessible_resources"] = [{"resources": ["upgrade.html"], "matches": ["<all_urls>"]}]
            (source / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "extension-private"):
                verifier.verify(source, ROOT / "runtime/com.auth_browser.proxy.json")


if __name__ == '__main__':
    unittest.main()
