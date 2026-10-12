"""No privileged execution is needed: ownership and ID-drop syscalls are mocked."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("entrypoint", ROOT / "runtime/entrypoint.py")
entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entrypoint)


class EntrypointTests(unittest.TestCase):
    def test_fresh_data_changes_only_open_directory_and_private_mode(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(entrypoint.os, "fchown") as chown:
            entrypoint.prepare_data(Path(temp))
            chown.assert_called_once()
            self.assertEqual(chown.call_args.args[1:], (10001, 10001))
            self.assertEqual(Path(temp).stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_existing_data_preserved_without_ownership_changes(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(entrypoint.os, "fchown") as chown:
            path = Path(temp)
            (path / "auth-browser.json").write_text('{"keys": ["existing"]}')
            (path / "chromium").mkdir()
            (path / "chromium/Profile").write_bytes(b"existing browser profile")
            # Repeated preparation simulates repeated starts against the same data.
            for _ in range(2):
                entrypoint.prepare_data(path, uid=os.getuid(), gid=os.getgid())
            chown.assert_not_called()
            self.assertEqual((path / "auth-browser.json").read_text(), '{"keys": ["existing"]}')
            self.assertEqual((path / "chromium/Profile").read_bytes(), b"existing browser profile")

    def test_nonempty_wrong_owner_refuses_without_changing_files(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(entrypoint.os, "fchown") as chown:
            path = Path(temp)
            (path / "unrelated").write_bytes(b"untouched")
            with self.assertRaisesRegex(RuntimeError, "Refusing"):
                entrypoint.prepare_data(path, uid=os.getuid() + 1)
            chown.assert_not_called()
            self.assertEqual((path / "unrelated").read_bytes(), b"untouched")

    def test_fresh_bind_with_empty_private_runtime_tmpfs_initializes_only_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            run = path / "run"
            run.mkdir(mode=0o700)
            original = os.fstat
            run_inode = run.stat().st_ino
            def mounted_info(fd):
                info = original(fd)
                fields = list(info)
                if info.st_ino == run_inode:
                    fields[2] += 1  # A separate tmpfs device, without mounting in tests.
                return os.stat_result(fields)
            with patch.object(entrypoint.os, "fstat", side_effect=mounted_info), \
                    patch.object(entrypoint.os, "fchown") as chown:
                entrypoint.prepare_data(path, uid=os.getuid())
            chown.assert_called_once()
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(run.iterdir()), [])

    def test_arbitrary_existing_run_directory_does_not_count_as_fresh_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "run").mkdir(mode=0o700)
            with patch.object(entrypoint.os, "fchown") as chown:
                with self.assertRaisesRegex(RuntimeError, "Refusing"):
                    entrypoint.prepare_data(path, uid=os.getuid() + 1)
            chown.assert_not_called()

    def test_runtime_mount_detection_requires_private_empty_exact_child(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            run = path / "run"
            run.mkdir(mode=0o700)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            info = os.fstat(fd)
            fields = list(info)
            fields[2] += 1
            other_device_parent = os.stat_result(fields)
            try:
                self.assertTrue(entrypoint.only_empty_runtime_mount(fd, ["run"], other_device_parent, os.getuid()))
                self.assertFalse(entrypoint.only_empty_runtime_mount(fd, ["run", "chromium"], other_device_parent, os.getuid()))
                self.assertFalse(entrypoint.only_empty_runtime_mount(fd, ["run"], info, os.getuid()))
                self.assertFalse(entrypoint.only_empty_runtime_mount(fd, ["run"], other_device_parent, os.getuid() + 1))
                run.chmod(0o755)
                self.assertFalse(entrypoint.only_empty_runtime_mount(fd, ["run"], other_device_parent, os.getuid()))
                run.chmod(0o700)
                (run / "existing").write_bytes(b"untouched")
                self.assertFalse(entrypoint.only_empty_runtime_mount(fd, ["run"], other_device_parent, os.getuid()))
                self.assertEqual((run / "existing").read_bytes(), b"untouched")
            finally:
                os.close(fd)

    def test_symlink_mountpoint_and_managed_child_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            real = path / "real"
            real.mkdir(mode=0o700)
            link = path / "link"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                entrypoint.prepare_data(link)
            (real / "auth-browser.json").symlink_to(path / "outside")
            with self.assertRaisesRegex(RuntimeError, "symbolic link"):
                entrypoint.prepare_data(real, uid=os.getuid())
            self.assertFalse((path / "outside").exists())

    def test_root_prepares_then_drops_groups_gid_uid_before_exec(self):
        steps = []
        def mark(name):
            return lambda *args: steps.append((name, args))
        with patch.object(entrypoint.os, "getuid", return_value=0), \
             patch.object(entrypoint, "prepare_data", side_effect=mark("prepare")), \
             patch.object(entrypoint.os, "setgroups", side_effect=mark("groups")), \
             patch.object(entrypoint.os, "setgid", side_effect=mark("gid")), \
             patch.object(entrypoint.os, "setuid", side_effect=mark("uid")), \
             patch.object(entrypoint.os, "umask", side_effect=mark("umask")), \
             patch.object(entrypoint.os, "execv", side_effect=mark("exec")):
            entrypoint.main(["--no-sandbox"])
        self.assertEqual([s[0] for s in steps], ["prepare", "groups", "gid", "uid", "umask", "exec"])
        self.assertEqual(steps[1][1], ([],))
        self.assertEqual(steps[2][1], (10001,))
        self.assertEqual(steps[3][1], (10001,))
        self.assertEqual(steps[-1][1][1][-1], "--no-sandbox")

    def test_nonroot_never_attempts_privileged_setup(self):
        with patch.object(entrypoint.os, "getuid", return_value=10001), \
             patch.object(entrypoint, "prepare_data") as prepare, \
             patch.object(entrypoint.os, "setuid") as setuid, \
             patch.object(entrypoint.os, "umask"), \
             patch.object(entrypoint.os, "execv") as execute:
            entrypoint.main([])
        prepare.assert_not_called()
        setuid.assert_not_called()
        self.assertNotIn("--no-sandbox", execute.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
