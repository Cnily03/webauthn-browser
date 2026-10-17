"""Deletion tests use disposable directories only; no installed runtime data."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location('erasure_manager_tests', Path(__file__).resolve().parents[1]/'runtime/profile_manager.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class ErasureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root/'data'
        self.profile = str(uuid.uuid4())
        self.home = self.data/'profiles'/self.profile
        (self.home/'chromium'/'nested').mkdir(parents=True)
        (self.home/'chromium'/'nested'/'cookie').write_text('fixture')
        (self.home/'config').mkdir()
        (self.home/'config'/'extension').write_text('fixture')
        self.other = self.data/'profiles'/str(uuid.uuid4())
        self.other.mkdir()
        (self.other/'marker').write_text('other')
        (self.data/'default-marker').write_text('default')
        self.manager = runtime.ProfileManager(roots=dict(data=self.data, run=self.root/'run'))
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = True

    def tearDown(self):
        self.temp.cleanup()

    def request(self, **fields):
        value = dict(version=1, token=self.manager.token, request_id=str(uuid.uuid4()),
                     action='delete_data', profile_id=self.profile, revision=2)
        value.update(fields)
        return value

    def delete(self, **fields):
        return self.manager.handle(self.request(**fields))

    def assert_preserved(self):
        self.assertEqual((self.other/'marker').read_text(), 'other')
        self.assertEqual((self.data/'default-marker').read_text(), 'default')

    def test_exact_home_and_child_symlinks_removed_repeat_is_success(self):
        (self.home/'external').symlink_to(self.other, target_is_directory=True)
        for _ in range(2):
            reply, rights = self.delete()
            self.assertTrue(reply['browser_data_deleted'])
            self.assertEqual(reply['revision'], 2)
            self.assertEqual(rights, [])
        self.assertFalse(self.home.exists())
        self.assert_preserved()

    def test_acknowledged_deletion_reclaims_history_and_blocks_delayed_lifecycle(self):
        self.manager.stopped_epochs[self.profile] = 'a' * 32
        self.assertTrue(self.delete()[0]['browser_data_deleted'])
        self.assertIn(self.profile, self.manager.deleted_profiles)
        self.assertIn(self.profile, self.manager.revisions)
        for _ in range(2):
            reply, rights = self.delete(action='forget_deleted', revision=3)
            self.assertTrue(reply['forgotten'])
            self.assertEqual(rights, [])
        self.assertFalse(self.manager.records)
        self.assertFalse(self.manager.revisions)
        self.assertFalse(self.manager.stopped_epochs)
        self.assertFalse(self.manager.deleted_profiles)
        self.assertEqual(self.manager.retired_revision, 3)
        for action in ('ensure', 'stop', 'delete_data'):
            for revision in (1, 2, 3):
                with self.subTest(action=action, revision=revision):
                    with self.assertRaisesRegex(runtime.ManagerError, 'stale_revision'):
                        self.delete(action=action, revision=revision)
        self.assertFalse(self.home.exists())
        self.assertFalse(self.manager.revisions)
        self.assert_preserved()

    def test_more_than_history_capacity_deletions_leave_no_per_identity_metadata(self):
        # A small capacity exercises exhaustion with real disposable erasures,
        # rather than spending thousands of filesystem syncs per test run.
        with patch.object(runtime, 'MAX_HISTORY', 3):
            for index in range(12):
                profile = str(uuid.uuid4())
                home = self.data / 'profiles' / profile
                home.mkdir()
                (home / 'marker').write_text('disposable')
                revision = index * 3 + 1
                self.delete(profile_id=profile, action='stop', revision=revision)
                self.manager.stopped_epochs[profile] = f'{index + 1:032x}'
                self.assertTrue(self.delete(profile_id=profile, revision=revision + 1)[0]['browser_data_deleted'])
                self.assertTrue(self.delete(profile_id=profile, action='forget_deleted', revision=revision + 2)[0]['forgotten'])
                self.assertFalse(home.exists())
                self.assertFalse(self.manager.revisions)
                self.assertFalse(self.manager.stopped_epochs)
                self.assertFalse(self.manager.deleted_profiles)
        self.assertEqual(self.manager.retired_revision, 36)
        self.assert_preserved()

    def test_acknowledgement_never_discards_unconfirmed_or_live_profile(self):
        self.manager.revisions[self.profile] = 1
        self.manager.stopped_epochs[self.profile] = 'a' * 32
        reply, _ = self.delete(action='forget_deleted')
        self.assertTrue(reply['forgotten'])
        self.assertEqual(self.manager.revisions, {self.profile: 1})
        self.assertEqual(self.manager.stopped_epochs, {self.profile: 'a' * 32})
        self.assertTrue(self.home.exists())
        self.manager.records[self.profile] = object()
        with self.assertRaisesRegex(runtime.ManagerError, 'cleanup_unconfirmed'):
            self.delete(action='forget_deleted')
        self.assertEqual(self.manager.retired_revision, 0)

    def test_failed_erasure_keeps_all_replay_proof_and_cannot_be_acknowledged(self):
        self.manager.stopped_epochs[self.profile] = 'a' * 32
        with patch.object(runtime.erasure, 'erase', side_effect=OSError('fixture')):
            with self.assertRaisesRegex(runtime.ManagerError, 'profile_data_delete_failed'):
                self.delete()
        self.assertFalse(self.manager.deleted_profiles)
        self.delete(action='forget_deleted', revision=3)
        self.assertEqual(self.manager.revisions, {self.profile: 2})
        self.assertEqual(self.manager.stopped_epochs, {self.profile: 'a' * 32})
        self.assertTrue(self.home.exists())

    def test_pending_erasure_proof_is_bounded_and_cannot_be_restarted_before_ack(self):
        self.assertTrue(self.delete()[0]['browser_data_deleted'])
        with self.assertRaisesRegex(runtime.ManagerError, 'stale_revision'):
            self.delete(action='ensure', revision=3)
        with patch.object(runtime, 'MAX_HISTORY', 1):
            with self.assertRaisesRegex(runtime.ManagerError, 'revision_capacity'):
                self.delete(profile_id=str(uuid.uuid4()), revision=3)
        self.assertEqual(self.manager.deleted_profiles, {self.profile})
        self.assertEqual(len(self.manager.revisions), 1)

    def test_gateway_rotation_preserves_only_unacknowledged_erasure_proof(self):
        self.manager.stopped_epochs[self.profile] = 'a' * 32
        self.manager.stopped_epochs['default'] = 'b' * 32
        self.assertTrue(self.delete()[0]['browser_data_deleted'])
        token = self.manager.token
        self.manager.retired_revision = 1
        self.manager.gateway_lost()
        self.assertNotEqual(token, self.manager.token)
        self.assertEqual(self.manager.deleted_profiles, {self.profile})
        self.assertFalse(self.manager.revisions)
        self.assertEqual(self.manager.stopped_epochs, {self.profile: 'a' * 32})
        self.assertEqual(self.manager.retired_revision, 0)
        with self.assertRaisesRegex(runtime.ManagerError, 'unauthorized'):
            self.delete(token=token, action='forget_deleted', revision=3)
        self.manager.startup_pristine = False
        self.assertTrue(self.delete(revision=1)[0]['browser_data_deleted'])
        self.assertTrue(self.delete(action='forget_deleted', revision=2)[0]['forgotten'])
        self.assertFalse(self.manager.deleted_profiles)
        self.assertFalse(self.manager.revisions)
        self.assertFalse(self.manager.stopped_epochs)

    def test_unacknowledged_erasure_capacity_stays_bounded_across_gateway_rotation(self):
        self.assertTrue(self.delete()[0]['browser_data_deleted'])
        self.manager.gateway_lost()
        with patch.object(runtime, 'MAX_HISTORY', 1):
            with self.assertRaisesRegex(runtime.ManagerError, 'revision_capacity'):
                self.delete(profile_id=str(uuid.uuid4()), revision=1)
        self.assertEqual(self.manager.deleted_profiles, {self.profile})
        self.assertFalse(self.manager.revisions)

    def test_unacknowledged_completion_receipts_are_batched_without_duplicates(self):
        profiles = [str(uuid.uuid4()) for _ in range(40)]
        for revision, profile in enumerate(profiles, 1):
            self.delete(profile_id=profile, revision=revision)
        first, _ = self.delete(action='cleanup_status', profile_id='default', revision=41,
                               cleanup_profiles=[profiles[0]])
        reported = [item['profile_id'] for item in first['results']]
        self.assertEqual((first['cleaned'], first['pending'], first['skipped']), (32, 0, 0))
        self.assertEqual(len(set(reported)), 32)
        self.assertIn(profiles[0], reported)
        self.assertEqual(len(self.manager.deleted_profiles), 40)
        for revision, profile in enumerate(reported, 42):
            self.delete(action='forget_deleted', profile_id=profile, revision=revision)
        remaining, _ = self.delete(action='cleanup_status', profile_id='default', revision=74)
        self.assertEqual((remaining['cleaned'], remaining['pending'], remaining['skipped']), (8, 0, 0))
        self.assertEqual({item['profile_id'] for item in remaining['results']}, set(profiles) - set(reported))
        for revision, item in enumerate(remaining['results'], 75):
            self.delete(action='forget_deleted', profile_id=item['profile_id'], revision=revision)
        empty, _ = self.delete(action='cleanup_status', profile_id='default', revision=83)
        self.assertEqual((empty['cleaned'], empty['pending'], empty['skipped']), (0, 0, 0))
        self.assertEqual(empty['results'], [])
        self.assertFalse(self.manager.deleted_profiles)
        self.assertFalse(self.manager.revisions)

    def test_partial_filesystem_failure_is_retryable_without_touching_siblings(self):
        unlink = runtime.erasure.os.unlink
        calls = 0
        def fail_after_progress(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError('fixture failure')
            return unlink(*args, **kwargs)
        with patch.object(runtime.erasure.os, 'unlink', side_effect=fail_after_progress):
            with self.assertRaisesRegex(runtime.ManagerError, 'profile_data_permission_denied'):
                self.delete()
        self.assertTrue(self.home.exists())
        self.assert_preserved()
        self.assertTrue(self.delete(revision=3)[0]['browser_data_deleted'])
        self.assertFalse(self.home.exists())
        self.assert_preserved()

    def test_missing_target_retry_requires_durable_parent_removal(self):
        fsync = runtime.erasure.os.fsync
        def fail_after_removal(fd):
            if not self.home.exists():
                raise OSError('fixture parent fsync failure')
            return fsync(fd)
        with patch.object(runtime.erasure.os, 'fsync', side_effect=fail_after_removal):
            for revision in (2, 3):
                with self.assertRaisesRegex(runtime.ManagerError, 'profile_data_delete_failed'):
                    self.delete(revision=revision)
                self.assertFalse(self.home.exists())
        self.assertTrue(self.delete(revision=4)[0]['browser_data_deleted'])
        self.assert_preserved()

    def test_missing_profiles_directory_requires_data_parent_fsync(self):
        (self.data/'profiles').rename(self.root/'retained-fixture')
        with patch.object(runtime.erasure.os, 'fsync', side_effect=OSError('fixture fsync failure')):
            with self.assertRaisesRegex(runtime.ManagerError, 'profile_data_delete_failed'):
                self.delete()
        self.assertTrue(self.delete(revision=3)[0]['browser_data_deleted'])
        self.assertTrue((self.root/'retained-fixture'/self.profile/'config'/'extension').exists())

    def test_default_and_invalid_ids_rejected(self):
        for profile in ('default', '../data', str(uuid.uuid4()).upper()):
            with self.assertRaises(runtime.ManagerError):
                self.delete(profile_id=profile)
        self.assertTrue(self.home.exists())
        self.assert_preserved()

    def test_unknown_startup_live_record_and_stale_revision_rejected(self):
        for field in ('startup_blocked', 'startup_unaccounted', 'stopping'):
            setattr(self.manager, field, True)
            with self.assertRaises(runtime.ManagerError):
                self.delete()
            setattr(self.manager, field, False)
        self.manager.startup_cleanup_done = False
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.manager.startup_cleanup_done = True
        self.manager.records[self.profile] = object()
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.manager.records.clear()
        self.manager.revisions[self.profile] = 3
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.assertTrue(self.home.exists())

    def test_uncertain_runtime_files_and_nonpristine_absence_rejected(self):
        self.manager.startup_pristine = False
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.manager.startup_pristine = True
        run = self.root/'run'/self.profile
        run.mkdir(parents=True, mode=0o700)
        (run/'unknown').write_text('fixture')
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.assertTrue(self.home.exists())

    def test_confirmed_stopped_epoch_allows_erasure(self):
        self.manager.startup_pristine = False
        self.manager.stopped_epochs[self.profile] = 'a'*32
        self.assertTrue(self.delete()[0]['browser_data_deleted'])

    def test_target_symlink_rejected(self):
        moved = self.root/'original'
        self.home.rename(moved)
        self.home.symlink_to(self.other, target_is_directory=True)
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.assertTrue((moved/'config'/'extension').exists())
        self.assert_preserved()

    def test_ancestor_symlinks_rejected(self):
        original = self.root/'original'
        self.data.rename(original)
        self.data.symlink_to(original, target_is_directory=True)
        with self.assertRaises(runtime.ManagerError):
            self.delete()
        self.assertTrue((self.home/'config'/'extension').exists())

    def test_replaced_directory_during_traversal_fails_closed(self):
        original_open = runtime.erasure.os.open
        moved = self.root/'moved'
        def replace(name, flags, *args, **kwargs):
            if name == 'chromium':
                (self.home/'chromium').rename(moved)
                (self.home/'chromium').symlink_to(self.other, target_is_directory=True)
            return original_open(name, flags, *args, **kwargs)
        with patch.object(runtime.erasure.os, 'open', side_effect=replace):
            with self.assertRaises(runtime.ManagerError):
                self.delete()
        self.assertTrue((moved/'nested'/'cookie').exists())
        self.assert_preserved()

    def test_admission_lock_held_through_erasure(self):
        erase = runtime.erasure.erase
        def checked(*args):
            self.assertFalse(self.manager.lock.acquire(blocking=False))
            return erase(*args)
        with patch.object(runtime.erasure, 'erase', side_effect=checked):
            self.delete()


if __name__ == '__main__':
    unittest.main()
