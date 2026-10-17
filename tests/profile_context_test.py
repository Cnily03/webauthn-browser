"""Profile-path contracts using temporary directories only; never touches /data."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_profile_context", ROOT / "runtime/profile_context.py")
context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context)
PROFILE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROFILE_B = "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb"


class ProfileContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="profile-context-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.roots = {"data": self.root / "data", "run": self.root / "run" / "profiles",
                      "cache": self.root / "cache"}

    def paths(self, profile_id="default", slot=0):
        return context.ProfilePaths(profile_id, slot, **self.roots)

    def test_concurrent_profiles_can_create_the_same_private_root(self):
        shared=self.root/'shared';barrier=threading.Barrier(2);errors=[]
        original=Path.mkdir
        def mkdir(path,*args,**kwargs):
            if path==shared:barrier.wait(timeout=2)
            return original(path,*args,**kwargs)
        def prepare(name):
            try:context.private_directory(shared/name)
            except Exception as error:errors.append(error)
        with patch.object(Path,'mkdir',mkdir):
            threads=[threading.Thread(target=prepare,args=(name,)) for name in ('a','b')]
            for thread in threads:thread.start()
            for thread in threads:thread.join(3)
        self.assertEqual(errors,[])
        self.assertTrue((shared/'a').is_dir());self.assertTrue((shared/'b').is_dir())

    def test_default_uses_existing_persistent_home_profile_and_config(self):
        paths = self.paths()
        self.assertEqual(paths.home, self.roots["data"])
        self.assertEqual(paths.profile, self.roots["data"] / "chromium")
        self.assertEqual(paths.config, self.roots["data"] / "config")
        self.assertEqual(paths.runtime, self.roots["run"] / "default")
        self.assertEqual(paths.cache, self.roots["cache"] / "default")

    def test_prepare_preserves_existing_history_config_and_internal_lock_symlink(self):
        paths = self.paths()
        paths.home.mkdir(mode=0o700)
        paths.profile.mkdir(mode=0o700)
        paths.config.mkdir(mode=0o700)
        history = paths.profile / "History"
        settings = paths.config / "user-settings"
        store = paths.home / "auth-browser.json"
        history.write_bytes(b"existing history fixture")
        settings.write_bytes(b"existing config fixture")
        store.write_bytes(b"existing software credential fixture")
        lock = paths.profile / "SingletonLock"
        lock.symlink_to("existing-browser-123")
        inodes = {path: path.stat().st_ino for path in (history, settings, store)}
        paths.prepare()
        paths.prepare()
        for path, inode in inodes.items():
            self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(history.read_bytes(), b"existing history fixture")
        self.assertEqual(settings.read_bytes(), b"existing config fixture")
        self.assertEqual(store.read_bytes(), b"existing software credential fixture")
        self.assertTrue(lock.is_symlink())
        self.assertEqual(os.readlink(lock), "existing-browser-123")
        self.assertFalse((paths.home / "profiles" / "default").exists())

    def test_accepts_only_default_or_canonical_version_four_uuid(self):
        for profile_id in ("default", PROFILE_A, PROFILE_B):
            with self.subTest(profile_id=profile_id):
                self.assertTrue(context.valid_profile_id(profile_id))
        for profile_id in (None, True, 1, {}, "", "Default", "../default", "/tmp/other",
                           "work", PROFILE_A.upper(), "{" + PROFILE_A + "}",
                           PROFILE_A.replace("-", ""), PROFILE_A + "\n",
                           "aaaaaaaa-aaaa-3aaa-8aaa-aaaaaaaaaaaa",
                           "aaaaaaaa-aaaa-4aaa-0aaa-aaaaaaaaaaaa"):
            with self.subTest(profile_id=profile_id):
                self.assertFalse(context.valid_profile_id(profile_id))
                with self.assertRaises(ValueError):
                    self.paths(profile_id)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_slot_is_bounded_integer_and_never_derived_from_display_names(self):
        for slot in (0, context.MAX_PROFILES - 1):
            paths = self.paths(PROFILE_A, slot)
            self.assertEqual(paths.display, f":{99 + slot}")
            self.assertEqual(paths.vnc_port, 5900 + slot)
        for slot in (-1, context.MAX_PROFILES, 999999, True, False, "1", 1.0, None):
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                self.paths(PROFILE_A, slot)

    def test_persistent_identity_is_stable_across_runtime_slot_changes(self):
        before = self.paths(PROFILE_A, 1)
        after = self.paths(PROFILE_A, 7)
        for attribute in ("home", "profile", "config", "runtime", "cache"):
            self.assertEqual(getattr(before, attribute), getattr(after, attribute))
        self.assertNotEqual(before.display, after.display)
        self.assertNotEqual(before.vnc_port, after.vnc_port)

    def test_profile_files_runtime_endpoints_and_displays_are_distinct(self):
        profiles = [self.paths(), self.paths(PROFILE_A, 1), self.paths(PROFILE_B, 2)]
        for attribute in ("home", "profile", "config", "runtime", "cache", "display", "vnc_port"):
            self.assertEqual(len({getattr(paths, attribute) for paths in profiles}), 3, attribute)
        self.assertEqual(profiles[1].home, self.roots["data"] / "profiles" / PROFILE_A)
        for key in profiles[0].metadata():
            self.assertEqual(len({paths.metadata()[key] for paths in profiles}), 3, key)
        for paths in profiles:
            metadata = paths.metadata()
            for key in ("control_path", "proxy_path", "clipboard_path", "ble_path", "status_path"):
                self.assertEqual(Path(metadata[key]).parent, paths.runtime)

    def test_environment_copies_and_scrubs_old_descriptors_and_control_secrets(self):
        inherited = {
            "HOME": "/old/home", "DISPLAY": ":1", "PATH": "/usr/bin",
            "LD_PRELOAD": "/old/hook.so", "UHF_CONTROL_FD": "198",
            "UHF_ENABLE": "1", "UHF_BROWSER_EPOCH": "old epoch",
            "AUTH_BROWSER_FIDO_CONTROL_FD": "199", "AUTH_BROWSER_FIDO_GATEWAY_EPOCH": "old epoch",
            "AUTH_BROWSER_FIDO_OTHER": "old capability",
            "AUTH_BROWSER_PROFILE_WORKER_FD": "200", "AUTH_BROWSER_PROFILE_CONTROL_TOKEN": "old token",
            "AUTH_BROWSER_PROFILE_CONTROL_PATH": "/old/control.sock",
            "AUTH_BROWSER_FIDO_HOOK_PATH": "/packaged/libuserland_hid_hook.so",
            "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/old/system",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/old/session",
        }
        original = dict(inherited)
        global_environment = dict(os.environ)
        paths = self.paths(PROFILE_A, 1)
        result = paths.environment(inherited)
        self.assertEqual(inherited, original)
        self.assertEqual(dict(os.environ), global_environment)
        for key in inherited:
            if key.startswith("UHF_") or (key.startswith("AUTH_BROWSER_FIDO_")
                                          and key != "AUTH_BROWSER_FIDO_HOOK_PATH"):
                self.assertNotIn(key, result)
        for key in ("LD_PRELOAD", "AUTH_BROWSER_PROFILE_WORKER_FD",
                    "AUTH_BROWSER_PROFILE_CONTROL_TOKEN", "AUTH_BROWSER_PROFILE_CONTROL_PATH"):
            self.assertNotIn(key, result)
        self.assertEqual(result["PATH"], "/usr/bin")
        self.assertEqual(result["AUTH_BROWSER_FIDO_HOOK_PATH"], original["AUTH_BROWSER_FIDO_HOOK_PATH"])
        self.assertEqual(result["HOME"], str(paths.home))
        self.assertEqual(result["DISPLAY"], paths.display)
        self.assertEqual(result["XDG_RUNTIME_DIR"], str(paths.runtime))
        self.assertEqual(result["XDG_CONFIG_HOME"], str(paths.config))
        self.assertEqual(result["XDG_CACHE_HOME"], str(paths.cache))
        self.assertEqual(result["AUTH_BROWSER_PROFILE_DATA_DIR"], str(paths.profile))
        self.assertEqual(result["AUTH_BROWSER_PROFILE_ID"], PROFILE_A)
        self.assertEqual(result["AUTH_BROWSER_PROFILE_SLOT"], "1")
        self.assertEqual(result["AUTH_BROWSER_PROFILE_VNC_PORT"], str(paths.vnc_port))
        self.assertEqual(result["AUTH_BROWSER_PROXY_SOCKET"], str(paths.runtime / "webauthn.sock"))
        for variable, name in (("DBUS_SYSTEM_BUS_ADDRESS", "dbus-system.sock"),
                               ("DBUS_SESSION_BUS_ADDRESS", "dbus-session.sock")):
            self.assertEqual(result[variable], f"unix:path={paths.runtime}/{name}")

    def test_environment_does_not_invent_hook_path(self):
        self.assertNotIn("AUTH_BROWSER_FIDO_HOOK_PATH", self.paths().environment({}))

    def test_prepare_creates_private_directories_without_existing_data_mutation(self):
        profiles = [self.paths(), self.paths(PROFILE_A, 1), self.paths(PROFILE_B, 2)]
        for paths in profiles:
            paths.prepare()
            for path in (paths.home, paths.profile, paths.config, paths.runtime, paths.cache):
                self.assertTrue(path.is_dir())
                self.assertFalse(path.is_symlink())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                self.assertEqual(path.stat().st_uid, os.getuid())

    def test_preexisting_nonprivate_directory_is_rejected_without_chmod(self):
        path = self.root / "public"
        path.mkdir(mode=0o755)
        path.chmod(0o755)
        with self.assertRaises(ValueError):
            context.private_directory(path)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_wrong_directory_owner_is_rejected_without_chown(self):
        path = self.root / "private"
        path.mkdir(mode=0o700)
        owner = path.stat().st_uid
        with patch.object(context.os, "getuid", return_value=owner + 1):
            with self.assertRaises(ValueError):
                context.private_directory(path)
        self.assertEqual(path.stat().st_uid, owner)

    def test_existing_file_cannot_become_profile_directory(self):
        path = self.root / "ordinary-file"
        path.write_bytes(b"preserve")
        with self.assertRaises(ValueError):
            context.private_directory(path)
        self.assertEqual(path.read_bytes(), b"preserve")

    def test_direct_and_ancestor_symlinks_rejected_without_following_or_writing(self):
        destination = self.root / "destination"
        destination.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(destination, target_is_directory=True)
        for path in (alias, alias / "child" / "nested"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                context.private_directory(path)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertTrue(alias.is_symlink())

    def test_dangling_symlink_is_rejected_without_replacement(self):
        alias = self.root / "dangling"
        alias.symlink_to(self.root / "missing", target_is_directory=True)
        with self.assertRaises(ValueError):
            context.private_directory(alias)
        self.assertTrue(alias.is_symlink())
        self.assertFalse((self.root / "missing").exists())

    def test_prepare_rejects_profile_runtime_and_cache_root_symlinks(self):
        for root_name in ("data", "run", "cache"):
            with self.subTest(root_name=root_name), tempfile.TemporaryDirectory(dir=self.root) as name:
                root = Path(name)
                roots = {"data": root / "data", "run": root / "run", "cache": root / "cache"}
                target = root / "untouched"
                target.mkdir(mode=0o700)
                roots[root_name].symlink_to(target, target_is_directory=True)
                paths = context.ProfilePaths(PROFILE_A, 1, **roots)
                with self.assertRaises(ValueError):
                    paths.prepare()
                self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
