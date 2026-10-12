"""Static source/image layout checks; never launches Docker, Chromium or devices."""
import pathlib
import re
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOOK = ROOT / "native-hid-hook"


class FidoSourceLayoutTests(unittest.TestCase):
    def test_shared_codec_is_relocatable_and_exact_source(self):
        source = (HOOK / "src/lib.rs").read_text()
        path = re.search(r'#\[path = "([^"]+)"\]\s*mod control_wire;', source)
        self.assertIsNotNone(path)
        included = (HOOK / "src" / path.group(1)).resolve()
        self.assertEqual(included, ROOT / "src/fido-relay/src/control.rs")
        self.assertIn("SPDX-License-Identifier: MIT", included.read_text())
        for name in ("Cargo.toml", "Cargo.lock", "build.rs", "LICENSE", "native/abi.c",
                     "src/monitor.rs", "tests/mock_udev_monitor.c"):
            self.assertTrue((HOOK / name).is_file(), name)

    def test_report_protocol_is_one_shared_library_under_backend_source(self):
        shared = ROOT / "src/fido-relay"
        for directory in (ROOT, ROOT / "helper"):
            config = tomllib.loads((directory / "Cargo.toml").read_text())
            dependency = config["dependencies"]["fido-report-relay"]
            self.assertEqual((directory / dependency["path"]).resolve(), shared)
        config = tomllib.loads((shared / "Cargo.toml").read_text())
        self.assertEqual(config["package"]["name"], "fido-report-relay")
        self.assertNotIn("bin", config)
        self.assertTrue((shared / "src/lib.rs").is_file())
        self.assertFalse((shared / "src/main.rs").exists())
        self.assertFalse((shared / "src/bin").exists())
        self.assertFalse((ROOT / "fido-relay/Cargo.toml").exists())
        docker = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY src ./src", docker)
        self.assertNotIn("COPY fido-relay ", docker)
        workflow = (ROOT / ".github/workflows/helper.yml").read_text()
        self.assertEqual(workflow.count("'src/fido-relay/**'"), 2)
        self.assertIn("/src/fido-relay/target/", (ROOT / ".gitignore").read_text())
        self.assertIn("src/fido-relay/target", (ROOT / ".dockerignore").read_text())

    def test_default_build_cannot_enable_compile_only_simulation(self):
        config = tomllib.loads((HOOK / "Cargo.toml").read_text())
        self.assertEqual(config["features"]["default"], [])
        self.assertEqual(config["lib"]["crate-type"], ["cdylib"])
        docker = (ROOT / "Dockerfile").read_text()
        self.assertIn("COPY native-hid-hook ./native-hid-hook", docker)
        self.assertIn("x86_64-unknown-linux-gnu", docker)
        self.assertIn("--manifest-path native-hid-hook/Cargo.toml", docker)
        self.assertNotIn("--features simulation", docker)
        self.assertNotIn("AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY=1", docker)
        self.assertIn("install -m 0444 native-hid-hook/target/release/libuserland_hid_hook.so", docker)
        self.assertIn("AUTH_BROWSER_FIDO_HOOK_PATH=/opt/webauthn-browser/native/libuserland_hid_hook.so", docker)
        self.assertIn("COPY --from=builder /build/native-hid-runtime /opt/webauthn-browser/native", docker)

    def test_single_compose_has_no_hidden_usb_activation_flag(self):
        files = sorted(path.name for pattern in ("compose*.yaml", "compose*.yml", "docker-compose*.yaml", "docker-compose*.yml") for path in ROOT.glob(pattern))
        self.assertEqual(files, ["docker-compose.yml"])
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertNotIn('AUTH_BROWSER_EXPERIMENTAL_FIDO_RELAY', compose)
        self.assertNotIn('privileged:', compose)
        self.assertNotIn('/dev/hidraw', compose)
        self.assertNotIn('/dev/uhid', compose)

    def test_generated_native_targets_are_excluded_from_source(self):
        self.assertIn("/native-hid-hook/target/", (ROOT / ".gitignore").read_text())
        self.assertIn("native-hid-hook/target", (ROOT / ".dockerignore").read_text())
        for directory in (HOOK / "src", HOOK / "native", HOOK / "tests", HOOK / "licenses"):
            for path in directory.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts:
                    self.assertNotIn(path.suffix, (".so", ".o", ".exe", ".dll", ".a"), str(path))
                    self.assertNotIn(b"/workspace/scratch/", path.read_bytes(), str(path))


if __name__ == "__main__":
    unittest.main()
