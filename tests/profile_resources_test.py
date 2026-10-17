"""Real disposable process reconciliation; no named sockets, X servers or browsers."""
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('resource_manager_tests', ROOT / 'runtime/profile_manager.py')
manager_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager_module)
resources = manager_module.resources


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.roots = dict(data=self.root/'data', run=self.root/'run', cache=self.root/'cache')
        self.paths = manager_module.context.ProfilePaths('default', 0, **self.roots)
        self.paths.prepare()
        self.manifest = resources.create(self.paths, secrets.token_hex(16), secrets.token_hex(32))
        self.children = []
        self.xroot = patch.object(resources, 'X_ROOT', self.root/'display')
        self.xroot.start()
        self.addCleanup(self.xroot.stop)
        self.lease_root = patch.object(resources, 'DISPLAY_ROOT', self.root/'leases')
        self.lease_root.start()
        self.addCleanup(self.lease_root.stop)

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # Only disposable Popen handles created by this fixture.
                child.kill()
                child.wait(timeout=2)
        self.temp.cleanup()

    def spawn(self, role='desktop', generation=None, script='import time; time.sleep(30)'):
        env = dict(os.environ)
        env.update({resources.GENERATION_KEY: generation or self.manifest['generation'],
                    resources.ROLE_KEY: role})
        child = subprocess.Popen([sys.executable, '-c', script], env=env, start_new_session=True,
                                 stdout=subprocess.PIPE, text=True)
        self.children.append(child)
        deadline = time.monotonic() + 2
        while resources.process(child.pid, self.manifest, any_generation=True) is None:
            if time.monotonic() >= deadline:
                self.fail('Disposable child did not publish ownership')
            time.sleep(.01)
        self.addCleanup(child.stdout.close)
        return child

    def test_ownership_manifest_is_durable_before_worker_exec(self):
        (self.paths.runtime/resources.MANIFEST).unlink()
        captured = []
        def reject_exec(command, **options):
            manifest = resources.read(self.paths)
            self.assertEqual(options['env'][resources.GENERATION_KEY], manifest['generation'])
            self.assertEqual(options['env'][resources.EPOCH_KEY], manifest['runtime_epoch'])
            captured.append(manifest)
            raise OSError('Disposable launch rejection')
        with patch.object(manager_module.subprocess, 'Popen', side_effect=reject_exec):
            with self.assertRaises(OSError):
                manager_module.Worker(self.paths, 'a'*64)
        self.assertEqual(len(captured),1)
        self.assertEqual(resources.read(self.paths),captured[0])

    def test_real_pidfd_reconciliation_terminates_only_exact_generation(self):
        owned = self.spawn()
        other = self.spawn(generation='f'*64)
        self.assertTrue(resources.reconcile(self.manifest, time.monotonic()+2))
        self.assertEqual(owned.wait(timeout=2), -signal.SIGTERM)
        self.assertIsNone(other.poll())
        self.assertEqual(resources.scan(self.manifest), [])

    def test_browser_receives_term_without_kill_and_blocked_term_remains_pending(self):
        child = self.spawn('browser', script='import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(30)')
        self.assertEqual(child.stdout.readline().strip(), 'ready')
        with patch.object(resources.signal, 'pidfd_send_signal', wraps=signal.pidfd_send_signal) as send:
            self.assertFalse(resources.reconcile(self.manifest, time.monotonic()+.15))
        self.assertEqual([call.args[1] for call in send.call_args_list], [signal.SIGTERM])
        self.assertIsNone(child.poll())

    def test_forced_cleanup_kills_only_verified_term_resistant_generation(self):
        script = ('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                  'print("ready",flush=True); time.sleep(30)')
        browser = self.spawn('browser', script=script)
        desktop = self.spawn('desktop', script=script)
        worker = self.spawn('worker', script=script)
        other = self.spawn('browser', generation='f'*64, script=script)
        for child in (browser, desktop, worker, other):
            self.assertEqual(child.stdout.readline().strip(), 'ready')
        with patch.object(resources.signal, 'pidfd_send_signal', wraps=signal.pidfd_send_signal) as send:
            self.assertTrue(resources.reconcile(self.manifest, time.monotonic()+1, force=True))
        self.assertEqual(browser.wait(timeout=2), -signal.SIGKILL)
        self.assertEqual(desktop.wait(timeout=2), -signal.SIGKILL)
        self.assertEqual(worker.wait(timeout=2), -signal.SIGKILL)
        self.assertIsNone(other.poll())
        self.assertEqual([call.args[1] for call in send.call_args_list],
                         [signal.SIGTERM] * 3 + [signal.SIGKILL] * 3)
        self.assertTrue(resources.reconcile(self.manifest, time.monotonic()+1, force=True))
        resources.remove_transient(self.paths, self.manifest)
        self.assertFalse((self.paths.runtime/resources.MANIFEST).exists())

    def test_force_revalidates_start_generation_and_namespace_before_signal(self):
        child = self.spawn()
        owned = resources.process(child.pid, self.manifest)
        with patch.object(resources.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(resources.ResourceError, 'identity_changed'):
                resources.terminate(dict(owned, start=owned['start']+1), self.manifest, force=True)
            resources.terminate(owned, dict(self.manifest, generation='0'*64), force=True)
            with self.assertRaisesRegex(resources.ResourceError, 'foreign_resource_namespace'):
                resources.terminate(owned, dict(self.manifest, pid_namespace='foreign'), force=True)
            send.assert_not_called()
        self.assertIsNone(child.poll())

    def test_force_unknown_ownership_and_timeout_have_concrete_errors(self):
        child = self.spawn('unknown')
        with patch.object(resources.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(resources.ResourceError, 'owned_process_role_unconfirmed: pid='):
                resources.reconcile(self.manifest, time.monotonic()+1, force=True)
            with self.assertRaisesRegex(resources.ResourceError, 'resource_cleanup_timeout: process_exit_unconfirmed'):
                resources.reconcile(self.manifest, time.monotonic(), force=True)
            send.assert_not_called()
        self.assertIsNone(child.poll())

    def test_live_worker_and_unknown_role_are_preserved(self):
        for role in ('worker', 'unknown'):
            child = self.spawn(role)
            with patch.object(resources.signal, 'pidfd_send_signal') as send:
                self.assertFalse(resources.reconcile(self.manifest, time.monotonic()+1))
                send.assert_not_called()
            self.assertIsNone(child.poll())
            child.terminate();child.wait(timeout=2)

    def test_real_pidfd_rechecks_start_identity_before_signal(self):
        child = self.spawn()
        owned = resources.process(child.pid, self.manifest)
        owned['start'] += 1  # A stale inventory must not signal a reused PID.
        with patch.object(resources.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(resources.ResourceError, 'identity_changed'):
                resources.terminate(owned, self.manifest)
            send.assert_not_called()
        self.assertIsNone(child.poll())

    def test_new_generation_and_foreign_namespace_are_never_signaled(self):
        child = self.spawn()
        owned = resources.process(child.pid, self.manifest)
        changed = dict(self.manifest, generation='0'*64)
        with patch.object(resources.signal, 'pidfd_send_signal') as send:
            resources.terminate(owned, changed)
            with self.assertRaisesRegex(resources.ResourceError, 'foreign_resource_namespace'):
                resources.reconcile(dict(self.manifest, pid_namespace='pid:[foreign]'), time.monotonic()+1)
            send.assert_not_called()
        self.assertIsNone(child.poll())

    def test_owned_subprocess_inherits_marker_and_separate_group_is_reconciled(self):
        script = ('import subprocess,sys,time; '
                  'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],start_new_session=True); '
                  'print(p.pid,flush=True); time.sleep(30)')
        parent = self.spawn(script=script)
        child_pid = int(parent.stdout.readline())
        self.assertIn(child_pid, [item['pid'] for item in resources.scan(self.manifest)])
        self.assertTrue(resources.reconcile(self.manifest, time.monotonic()+2))
        parent.wait(timeout=2)
        self.assertEqual(resources.scan(self.manifest), [])

    def test_unreadable_child_of_other_verified_generation_does_not_block_cleanup(self):
        own = self.spawn()
        other = self.spawn(generation='e'*64)
        real_process = resources.process
        real_identity = resources.identity
        fake_pid = 987654321
        def inspect(pid, manifest, **kwargs):
            if pid == fake_pid:
                raise PermissionError()
            return real_process(pid, manifest, **kwargs)
        def identity(pid):
            if pid == fake_pid:
                info = real_identity(other.pid)
                return info[0], 'S', info[2]+1, other.pid
            return real_identity(pid)
        names = os.listdir('/proc') + [str(fake_pid)]
        with patch.object(resources.os, 'listdir', return_value=names), \
                patch.object(resources, 'process', side_effect=inspect), \
                patch.object(resources, 'identity', side_effect=identity):
            found = resources.scan(self.manifest)
        self.assertIn(own.pid, [item['pid'] for item in found])
        self.assertNotIn(fake_pid, [item['pid'] for item in found])

    def test_pristine_inventory_accounts_for_verified_nondumpable_children(self):
        leader = self.spawn()
        real_identity = resources.identity
        real_open = Path.open
        fake_pid = 987654321
        def identity(pid):
            if pid == fake_pid:
                info = real_identity(leader.pid)
                return info[0], 'S', info[2]+1, leader.pid
            return real_identity(pid)
        def open_path(path, *args, **kwargs):
            if str(path) == f'/proc/{fake_pid}/environ':
                raise PermissionError()
            return real_open(path, *args, **kwargs)
        names = [str(leader.pid), str(fake_pid)]
        with patch.object(resources.os, 'listdir', return_value=names), \
                patch.object(resources, 'identity', side_effect=identity), \
                patch.object(Path, 'open', new=open_path):
            self.assertTrue(resources.pristine_start(self.paths.runtime.parent, 16,
                allowed_generations=[self.manifest['generation']], allowed_slots=[0]))
            self.assertFalse(resources.pristine_start(self.paths.runtime.parent, 16,
                allowed_generations=['e'*64], allowed_slots=[0]))
            # A child cannot derive authority from a missing or reused leader.
            with patch.object(resources, 'process', return_value=None):
                self.assertFalse(resources.pristine_start(self.paths.runtime.parent, 16,
                    allowed_generations=[self.manifest['generation']], allowed_slots=[0]))
            owner = resources.process(leader.pid, self.manifest, any_generation=True)
            with patch.object(resources, 'process', side_effect=[owner, None]):
                self.assertFalse(resources.pristine_start(self.paths.runtime.parent, 16,
                    allowed_generations=[self.manifest['generation']], allowed_slots=[0]))
            def older_child(pid):
                if pid == fake_pid:
                    info = real_identity(leader.pid)
                    return info[0], 'S', info[2]-1, leader.pid
                return real_identity(pid)
            with patch.object(resources, 'identity', side_effect=older_child):
                self.assertFalse(resources.pristine_start(self.paths.runtime.parent, 16,
                    allowed_generations=[self.manifest['generation']], allowed_slots=[0]))

    def test_pristine_inventory_unknown_nondumpable_process_blocks_admission(self):
        with patch.object(resources.os, 'listdir', return_value=['987654321']), \
                patch.object(resources, 'identity', return_value=(os.getuid(), 'S', 10, 987654321)), \
                patch.object(Path, 'open', side_effect=PermissionError()):
            self.assertFalse(resources.pristine_start(self.paths.runtime.parent, 16))

    def test_unreadable_unknown_process_fails_closed(self):
        with patch.object(resources.os, 'listdir', return_value=['111']), \
                patch.object(resources, 'process', side_effect=PermissionError()), \
                patch.object(resources, 'identity', return_value=(os.getuid(),'S',10,111)):
            with self.assertRaisesRegex(resources.ResourceError, 'inventory_unavailable'):
                resources.scan(self.manifest)

    def test_reused_group_with_unreadable_new_process_has_no_cached_authority(self):
        old = self.spawn()
        original = resources.scan(self.manifest)
        self.assertTrue(original)
        group = old.pid
        old.terminate();old.wait(timeout=2)
        with patch.object(resources.os, 'listdir', return_value=[str(group)]), \
                patch.object(resources, 'process', side_effect=PermissionError()), \
                patch.object(resources, 'identity', return_value=(os.getuid(),'S',999999999,group)), \
                patch.object(resources.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(resources.ResourceError, 'inventory_unavailable'):
                resources.scan(self.manifest)
            send.assert_not_called()

    def test_non_dumpable_member_requires_live_matching_leader_at_signal_time(self):
        leader = self.spawn()
        child = self.spawn()
        owned = resources.process(child.pid, self.manifest)
        owned['owner'] = resources.process(leader.pid, self.manifest, any_generation=True)
        # Simulate a matching group snapshot followed by leader replacement.
        with patch.object(resources, 'process', return_value=None), \
                patch.object(resources.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(resources.ResourceError, 'group_owner_changed'):
                resources.terminate(owned, self.manifest)
            send.assert_not_called()
        self.assertIsNone(child.poll())

    def test_stale_display_lock_needs_exact_lease_and_dead_owner(self):
        display = self.root/'display';display.mkdir()
        child = self.spawn()
        lock = display/'.X99-lock';lock.write_text(str(child.pid))
        resources.record_display(self.paths.runtime, self.manifest['runtime_epoch'],
                                 self.manifest['generation'], child.pid, self.paths.slot)
        with self.assertRaisesRegex(resources.ResourceError, 'owner_unconfirmed'):
            resources.remove_display(self.paths, self.manifest)
        self.assertTrue(lock.exists())
        child.terminate();child.wait(timeout=2)
        resources.remove_display(self.paths, self.manifest)
        self.assertFalse(lock.exists())

    def test_unknown_or_replaced_display_lock_stays_pending(self):
        display = self.root/'display';display.mkdir()
        lock = display/'.X99-lock';lock.write_text('1234')
        with self.assertRaises(FileNotFoundError):
            resources.remove_display(self.paths, self.manifest)
        self.assertTrue(lock.exists())
        child = self.spawn()
        resources.record_display(self.paths.runtime, self.manifest['runtime_epoch'],
                                 self.manifest['generation'], child.pid, self.paths.slot)
        child.terminate();child.wait(timeout=2)
        with self.assertRaisesRegex(resources.ResourceError, 'lock_changed'):
            resources.remove_display(self.paths, self.manifest)
        self.assertEqual(lock.read_text(), '1234')

    def test_replaced_display_artifact_is_preserved_even_after_old_owner_exit(self):
        display = self.root/'display';display.mkdir()
        child = self.spawn()
        lock = display/'.X99-lock';lock.write_text(str(child.pid))
        resources.record_display(self.paths.runtime, self.manifest['runtime_epoch'],
                                 self.manifest['generation'], child.pid, self.paths.slot)
        child.terminate();child.wait(timeout=2)
        replacement = display/'replacement';replacement.write_text(str(child.pid))
        replacement.replace(lock)
        with self.assertRaisesRegex(resources.ResourceError, 'artifact_changed'):
            resources.remove_display(self.paths, self.manifest)
        self.assertTrue(lock.exists())

    def test_replaced_socket_inode_is_not_removed_or_probed(self):
        display = self.root/'display';(display/'.X11-unix').mkdir(parents=True)
        socket_path = display/'.X11-unix'/'X99'
        socket_path.write_text('ordinary fixture, never a named socket')
        child = self.spawn()
        real_lstat = Path.lstat
        def inode(path):
            info = real_lstat(path)
            if path == socket_path:
                return SimpleNamespace(st_uid=info.st_uid, st_mode=stat.S_IFSOCK|0o600,
                                       st_dev=info.st_dev, st_ino=info.st_ino, st_ctime_ns=info.st_ctime_ns)
            return info
        with patch.object(Path,'lstat',inode):
            resources.record_display(self.paths.runtime, self.manifest['runtime_epoch'],
                                     self.manifest['generation'], child.pid, self.paths.slot)
        child.terminate();child.wait(timeout=2)
        replacement = display/'replacement';replacement.write_text('replacement')
        replacement.replace(socket_path)
        with patch.object(Path,'lstat',inode), patch.object(resources.socket,'socket') as probe:
            with self.assertRaisesRegex(resources.ResourceError,'artifact_changed'):
                resources.remove_display(self.paths,self.manifest)
            probe.assert_not_called()
        self.assertEqual(socket_path.read_text(),'replacement')

    def test_foreign_uid_orphan_without_surviving_leader_blocks_absence_receipt(self):
        with patch.object(resources.os, 'listdir', return_value=['987654321']), \
                patch.object(resources, 'identity', return_value=(os.getuid()+1,'S',10,987654321)), \
                patch.object(resources, 'manager_ancestors', return_value={os.getpid()}):
            with self.assertRaisesRegex(resources.ResourceError, 'foreign_process_inventory_unavailable'):
                resources.scan(self.manifest)

    def test_real_docker_environment_on_manager_does_not_block_pristine_start(self):
        script = ('import importlib.util,pathlib,sys; '
                  's=importlib.util.spec_from_file_location("resources",sys.argv[1]); '
                  'm=importlib.util.module_from_spec(s);s.loader.exec_module(m); '
                  'm.X_ROOT=pathlib.Path(sys.argv[2]); '
                  'print(m.pristine_start(pathlib.Path(sys.argv[3]),16))')
        env = dict(os.environ, DISPLAY=':99', XDG_RUNTIME_DIR=str(self.root))
        result = subprocess.run([sys.executable,'-c',script,str(ROOT/'runtime/profile_resources.py'),
                                 str(self.root/'display'),str(self.paths.runtime.parent)],
                                env=env,capture_output=True,text=True,check=True,timeout=3)
        self.assertEqual(result.stdout.strip(),'True')

    def test_transient_removal_preserves_all_user_data_and_unknown_files(self):
        keep = [self.paths.profile/'history', self.paths.config/'preferences',
                self.paths.cache/'cache-data', self.paths.runtime/'unknown']
        for path in keep:
            path.write_text('preserve')
        status = self.paths.runtime/'runtime.json'
        status.write_text('{}')
        resources.remove_transient(self.paths, self.manifest)
        self.assertFalse(status.exists())
        self.assertFalse((self.paths.runtime/resources.MANIFEST).exists())
        self.assertTrue(all(path.read_text() == 'preserve' for path in keep))

    def test_transient_cleanup_retry_accepts_only_verified_missing_state(self):
        resources.remove_transient(self.paths, self.manifest)
        resources.remove_transient(self.paths, self.manifest)
        status = self.paths.runtime/'runtime.json'
        status.write_text('{}')
        with self.assertRaisesRegex(resources.ResourceError, 'resource_manifest_missing_with_resources'):
            resources.remove_transient(self.paths, self.manifest)
        self.assertTrue(status.exists())
        status.unlink()
        self.paths.runtime.rmdir()
        resources.remove_transient(self.paths, self.manifest)

    def test_symlink_transient_and_changed_manifest_block_cleanup(self):
        target = self.root/'keep';target.write_text('preserve')
        (self.paths.runtime/'runtime.json').symlink_to(target)
        with self.assertRaisesRegex(resources.ResourceError, 'unsafe_transient_resource'):
            resources.remove_transient(self.paths, self.manifest)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertTrue((self.paths.runtime/resources.MANIFEST).exists())
        (self.paths.runtime/'runtime.json').unlink()
        changed = dict(self.manifest, runtime_epoch='0'*32)
        (self.paths.runtime/resources.MANIFEST).write_text(json.dumps(changed))
        with self.assertRaisesRegex(resources.ResourceError, 'generation_changed'):
            resources.remove_transient(self.paths, self.manifest)

    def test_fifo_manifest_is_rejected_without_waiting(self):
        path = self.paths.runtime/resources.MANIFEST
        path.unlink();os.mkfifo(path, 0o600)
        with self.assertRaisesRegex(resources.ResourceError, 'unsafe_resource_manifest'):
            resources.read(self.paths)
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stderr', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertTrue(manager.startup_blocked)

    def test_single_manager_lock_prevents_socket_open_before_unlink(self):
        first = manager_module.ProfileManager(roots=self.roots)
        second = manager_module.ProfileManager(roots=self.roots)
        lock = self.root/'profiles-manager.lock'
        first.acquire_manager_lock(lock)
        try:
            with self.assertRaisesRegex(manager_module.ManagerError, 'manager_already_running'):
                second.acquire_manager_lock(lock)
            self.assertIsNone(second.manager_lock)
        finally:
            first.shutdown();second.shutdown()
        second.acquire_manager_lock(lock)
        second.shutdown()

    def test_startup_reconciles_manifest_orphans_once_before_slot_reuse(self):
        child = self.spawn()
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
        self.assertFalse(manager.records);self.assertFalse(manager.slots)
        self.assertEqual(manager.stopped_epochs['default'], self.manifest['runtime_epoch'])
        with patch.object(manager, 'cleanup') as cleanup:
            manager.startup_cleanup();cleanup.assert_not_called()
        manager.shutdown()

    def test_startup_stops_verified_worker_before_releasing_epoch_and_slot(self):
        child = self.spawn('worker')
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertEqual(child.wait(timeout=2), -signal.SIGTERM)
        self.assertNotIn('default', manager.records)
        self.assertFalse(manager.slots)
        self.assertEqual(manager.stopped_epochs['default'], self.manifest['runtime_epoch'])
        manager.shutdown()

    def test_pristine_start_can_prove_unknown_absent_profile_without_epoch(self):
        (self.paths.runtime/resources.MANIFEST).unlink()
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertTrue(manager.startup_pristine)
        profile = '12345678-1234-4234-8234-123456789abc'
        request = dict(version=1, token=manager.token, request_id='12345678-1234-4234-8234-123456789abc',
                       profile_id='default', revision=1, action='cleanup_status', cleanup_profiles=[profile])
        with patch.object(manager, 'reconcile_record') as reconcile:
            result,rights = manager.handle(request)
            reconcile.assert_not_called()
        self.assertEqual(rights, [])
        self.assertEqual(result['results'], [dict(profile_id=profile, runtime_epoch=None, stopped=True)])
        manager.shutdown()

    def test_empty_registry_without_manifest_cannot_hide_live_old_generation(self):
        child = self.spawn()
        (self.paths.runtime/resources.MANIFEST).unlink()
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertFalse(manager.startup_pristine)
        self.assertTrue(manager.startup_unaccounted)
        self.assertIsNone(child.poll())
        request = dict(version=1,token=manager.token,request_id='12345678-1234-4234-8234-123456789abc',
                       action='ensure',profile_id='default',revision=1)
        with patch.object(manager,'worker_factory') as launch:
            with self.assertRaisesRegex(manager_module.ManagerError,'cleanup_unconfirmed'):
                manager.handle(request)
            launch.assert_not_called()
        child.terminate();child.wait(timeout=2)
        manager.cleanup(dict(request,action='cleanup'))
        self.assertFalse(manager.startup_unaccounted)
        manager.shutdown()

    def test_known_manifest_does_not_hide_unaccounted_live_generation(self):
        known = self.spawn('worker')
        unknown = self.spawn('worker',generation='b'*64)
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout',new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertNotIn('default',manager.records)
        self.assertTrue(manager.startup_unaccounted)
        request = dict(version=1,token=manager.token,request_id='12345678-1234-4234-8234-123456789abc',
                       action='ensure',profile_id='12345678-1234-4234-8234-123456789abc',revision=1)
        with patch.object(manager,'worker_factory') as launch:
            with self.assertRaisesRegex(manager_module.ManagerError,'cleanup_unconfirmed'):
                manager.handle(request)
            launch.assert_not_called()
        self.assertEqual(known.wait(timeout=2), -signal.SIGTERM)
        self.assertIsNone(unknown.poll())
        manager.shutdown()

    def test_container_restart_uses_surviving_inode_lease_without_signaling_old_pids(self):
        display = self.root/'display';display.mkdir()
        child = self.spawn()
        lock = display/'.X99-lock';lock.write_text(str(child.pid))
        resources.record_display(self.paths.runtime, self.manifest['runtime_epoch'],
                                 self.manifest['generation'], child.pid, self.paths.slot)
        child.terminate();child.wait(timeout=2)
        lease = resources.read_display('default')
        lease['pid_namespace'] = 'pid:[previous-container]'
        (resources.DISPLAY_ROOT/'default.json').write_text(json.dumps(lease))
        # /data/run's tmpfs was reset, while the container's /tmp survived.
        (self.paths.runtime/resources.MANIFEST).unlink()
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO), \
                patch.object(resources.signal, 'pidfd_send_signal') as send:
            manager.startup_cleanup()
            send.assert_not_called()
        self.assertFalse(manager.records);self.assertFalse(lock.exists())
        self.assertFalse((resources.DISPLAY_ROOT/'default.json').exists())
        self.assertEqual(manager.stopped_epochs['default'], self.manifest['runtime_epoch'])
        manager.shutdown()

    def test_cleaned_empty_runtime_directory_is_proved_after_manager_restart(self):
        resources.remove_transient(self.paths, self.manifest)
        self.assertTrue(self.paths.runtime.is_dir())
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stdout', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertTrue(manager.startup_pristine)
        request = dict(version=1, token=manager.token, request_id='12345678-1234-4234-8234-123456789abc',
                       profile_id='default', revision=1, action='cleanup_status', cleanup_profiles=['default'])
        result,rights = manager.handle(request)
        self.assertTrue(result['results'][0]['stopped'])
        self.assertIsNone(result['results'][0]['runtime_epoch']);self.assertEqual(rights, [])
        manager.shutdown()

    def test_unknown_prior_runtime_files_do_not_count_as_cleanup(self):
        (self.paths.runtime/resources.MANIFEST).unlink()
        (self.paths.runtime/'runtime.json').write_text('{}')
        manager = manager_module.ProfileManager(roots=self.roots)
        with patch('sys.stderr', new_callable=io.StringIO):
            manager.startup_cleanup()
        self.assertTrue(manager.startup_blocked)
        self.assertTrue((self.paths.runtime/'runtime.json').exists())
        manager.shutdown()


if __name__ == '__main__':
    unittest.main()
