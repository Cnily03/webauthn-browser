"""Private profile lifecycle with real disposable Python peers, never Chromium."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('profile_manager_tests', ROOT/'runtime/profile_manager.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)

FIXTURE = r'''
import json,os,pathlib,secrets,socket,sys
sys.path.insert(0,sys.argv[1])
import profile_wire as wire
control=socket.socket(fileno=int(os.environ['AUTH_BROWSER_PROFILE_WORKER_FD']))
try:start,rights=wire.receive(control)
except wire.ProtocolError:sys.exit(70)  # No services started; fixture cleanup complete.
wire.close_rights(rights)
assert start['action']=='start'
assert 'AUTH_BROWSER_PROFILE_CONTROL_TOKEN' not in os.environ
path=pathlib.Path(os.environ['AUTH_BROWSER_PROFILE_RUNTIME_DIR'])
(path/'fixture.json').write_text(json.dumps({key:os.environ[key] for key in (
 'HOME','DISPLAY','XDG_RUNTIME_DIR','XDG_CACHE_HOME','XDG_CONFIG_HOME',
 'AUTH_BROWSER_PROXY_SOCKET','DBUS_SYSTEM_BUS_ADDRESS','DBUS_SESSION_BUS_ADDRESS')}))
epoch=os.environ['AUTH_BROWSER_PROFILE_EPOCH']
a=b=None
def offer():
 global a,b
 if a is not None:a.close();b.close()
 a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
 wire.send(control,dict(ok=True,runtime_epoch=epoch,fido_gateway_epoch=secrets.token_hex(16)),a.fileno())
offer()
while True:
 message,rights=wire.receive(control);wire.close_rights(rights)
 if message['action']=='stop':
  wire.send(control,dict(ok=True,stopped=True));break
 if message['action']=='gateway':offer()
 if message['action']=='gateway_lost':
  if a is not None:a.shutdown(socket.SHUT_RDWR)
  wire.send(control,dict(ok=True))
'''


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = self.root/'peer.py'
        self.fixture.write_text(FIXTURE)
        real_popen = subprocess.Popen
        def factory(paths, token, **kwargs):
            def launch(_command, **options):
                return real_popen([sys.executable,str(self.fixture),str(ROOT/'runtime')],**options)
            with patch.object(runtime.subprocess,'Popen',side_effect=launch):
                return runtime.Worker(paths,token,**kwargs)
        self.manager = runtime.ProfileManager(worker_factory=factory, roots=dict(
            data=self.root/'data',run=self.root/'run',cache=self.root/'cache'))
        self.rights = []
    def tearDown(self):
        runtime.wire.close_rights(self.rights)
        self.manager.shutdown()
        self.temp.cleanup()
    def request(self, profile='default', revision=1, action='ensure', **fields):
        return dict(version=1,token=self.manager.token,request_id=str(uuid.uuid4()),
                    action=action,profile_id=profile,revision=revision,**fields)
    def handle(self, message):
        value,rights=self.manager.handle(message);self.rights.extend(rights)
        return value,rights
    def test_delete_data_requires_confirmed_stop_and_removes_only_selected_home(self):
        profile = str(uuid.uuid4())
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = True
        self.handle(self.request())
        self.handle(self.request(profile))
        record = self.manager.records[profile]
        (record.paths.profile/'cookie').write_text('fixture')
        with self.assertRaises(runtime.ManagerError):
            self.handle(self.request(profile, 2, 'delete_data'))
        self.handle(self.request(profile, 2, 'stop'))
        reply, rights = self.handle(self.request(profile, 3, 'delete_data'))
        self.assertTrue(reply['browser_data_deleted'])
        self.assertEqual(rights, [])
        self.assertFalse(record.paths.home.exists())
        self.assertTrue(self.manager.records['default'].paths.home.exists())
        self.assertIsNone(self.manager.records['default'].worker.process.poll())

    def test_two_stacks_get_distinct_processes_paths_displays_and_fido_capabilities(self):
        first, fds=self.handle(self.request())
        second, other=self.handle(self.request(str(uuid.uuid4())))
        self.assertEqual(len(fds),1);self.assertEqual(len(other),1)
        for key in ('display','vnc_port','runtime_dir','control_path','proxy_path','clipboard_path','ble_path','status_path','runtime_epoch','fido_gateway_epoch'):
            self.assertNotEqual(first[key],second[key],key)
        processes=[r.worker.process.pid for r in self.manager.records.values()]
        self.assertEqual(len(set(processes)),2)
        a=json.loads((Path(first['runtime_dir'])/'fixture.json').read_text())
        b=json.loads((Path(second['runtime_dir'])/'fixture.json').read_text())
        for key in a:self.assertNotEqual(a[key],b[key],key)
        self.assertEqual(a['HOME'],str(self.root/'data'))
        self.assertFalse(first['engine_ready'])
    def test_repeat_ensure_does_not_replace_live_capability_or_process(self):
        first,_=self.handle(self.request());pid=self.manager.records['default'].worker.process.pid
        second,rights=self.handle(self.request())
        self.assertEqual(first['runtime_epoch'],second['runtime_epoch']);self.assertEqual(rights,[])
        self.assertNotIn('fido_gateway_epoch',second)
        self.assertEqual(pid,self.manager.records['default'].worker.process.pid)
    def test_explicit_attach_recovers_discarded_initial_offer_without_restarting(self):
        first, rights = self.handle(self.request(attach_gateway=True))
        record = self.manager.records['default']
        worker = record.worker
        token = record.bound_token
        # An HTTP context abandoned this late offer before installing its proxy.
        # Close only the received copy, as the cancelled Rust future would do.
        for fd in rights:
            self.rights.remove(fd)
            os.close(fd)
        with patch.object(worker, 'exchange', wraps=worker.exchange) as exchange:
            for fields in ({}, {'attach_gateway': False}):
                cached, offered = self.handle(self.request(revision=2, **fields))
                self.assertEqual(offered, [])
                self.assertNotIn('fido_gateway_epoch', cached)
            exchange.assert_not_called()
            recovered, offered = self.handle(self.request(revision=3, attach_gateway=True))
            exchange.assert_called_once_with({'action': 'gateway', 'token': token})
        self.assertEqual(len(offered), 1)
        self.assertNotEqual(first['fido_gateway_epoch'], recovered['fido_gateway_epoch'])
        self.assertEqual(first['runtime_epoch'], recovered['runtime_epoch'])
        self.assertIs(self.manager.records['default'], record)
        self.assertIs(record.worker, worker)
        self.assertIsNone(worker.process.poll())
        self.assertEqual(record.bound_token, token)
        self.assertEqual(self.manager.slots, {0: 'default'})

    def test_attach_gateway_is_a_strict_boolean_only_for_ensure(self):
        for value in (None, 0, 1, 'true', [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(runtime.ManagerError, 'invalid_request'):
                self.handle(self.request(attach_gateway=value))
        for action in ('stop', 'delete_data', 'forget_deleted', 'health', 'cleanup', 'cleanup_status', 'cleanup_startup'):
            for value in (True, False):
                with self.subTest(action=action, value=value), self.assertRaisesRegex(runtime.ManagerError, 'invalid_request'):
                    self.handle(self.request(action=action, attach_gateway=value))
        self.assertFalse(self.manager.records)
        self.assertFalse(self.manager.revisions)

    def test_disable_preserves_data_and_reenable_has_a_new_runtime_epoch(self):
        first,_=self.handle(self.request());record=self.manager.records['default']
        marker=record.paths.profile/'saved-tabs';marker.write_text('synthetic fixture only')
        stopped,_=self.handle(self.request(revision=2,action='stop',runtime_epoch=first['runtime_epoch']))
        self.assertTrue(stopped['stopped']);self.assertEqual(record.worker.process.poll(),0)
        self.assertTrue(marker.exists());self.assertFalse(self.manager.records)
        second,_=self.handle(self.request(revision=3));self.assertNotEqual(first['runtime_epoch'],second['runtime_epoch'])
        with self.assertRaisesRegex(runtime.ManagerError,'stale_runtime'):
            self.handle(self.request(revision=4,action='stop',runtime_epoch=first['runtime_epoch']))
        self.assertEqual(marker.read_text(),'synthetic fixture only')
    def test_lost_confirmed_stop_reply_can_retry_exact_epoch_without_stopping_replacement(self):
        first,_=self.handle(self.request());epoch=first['runtime_epoch']
        record=self.manager.records['default']
        # Exercise the production stream handler, then lose its successful stop
        # reply. The worker uses only an anonymous socketpair and disposable peer.
        client,server=socket.socketpair();self.manager.inflight.acquire()
        runtime.wire.send(client,self.request(revision=2,action='stop',runtime_epoch=epoch))
        client.close()
        thread=threading.Thread(target=self.manager.connection,args=(server,));thread.start();thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(record.worker.process.poll(),0)
        self.assertNotIn('default',self.manager.records);self.assertFalse(self.manager.slots)
        for revision in (2,3):
            stopped,rights=self.handle(self.request(revision=revision,action='stop',runtime_epoch=epoch))
            self.assertTrue(stopped['stopped']);self.assertEqual(rights,[])
        with self.assertRaisesRegex(runtime.ManagerError,'stale_runtime'):
            self.handle(self.request(revision=4,action='stop',runtime_epoch='0'*32))
        replacement,_=self.handle(self.request(revision=4))
        self.assertNotEqual(epoch,replacement['runtime_epoch'])
        for revision in (5,6):
            with self.assertRaisesRegex(runtime.ManagerError,'stale_runtime'):
                self.handle(self.request(revision=revision,action='stop',runtime_epoch=epoch))
        self.assertIsNone(self.manager.records['default'].worker.process.poll())
        self.assertEqual(self.manager.slots,{0:'default'})

    def test_stale_stop_and_same_revision_stop_cannot_affect_live_owner(self):
        first,_=self.handle(self.request(revision=3))
        for rev in (2,3):
            with self.assertRaisesRegex(runtime.ManagerError,'stale_revision'):
                self.handle(self.request(revision=rev,action='stop'))
        self.assertIsNone(self.manager.records['default'].worker.process.poll())
    def test_stopped_tombstone_rejects_equal_revision_ensure(self):
        self.handle(self.request(revision=1,action='stop'))
        with self.assertRaisesRegex(runtime.ManagerError,'stale_revision'):self.handle(self.request())
        self.handle(self.request(revision=2))
    def test_completed_epoch_history_is_bounded_and_new_gateway_cannot_reuse_old_completion(self):
        first,_=self.handle(self.request())
        self.handle(self.request(revision=2,action='stop',runtime_epoch=first['runtime_epoch']))
        self.assertEqual(self.manager.stopped_epochs,{'default':first['runtime_epoch']})
        with patch.object(runtime,'MAX_HISTORY',1):
            with self.assertRaisesRegex(runtime.ManagerError,'revision_capacity'):
                self.handle(self.request(str(uuid.uuid4())))
        self.manager.gateway_lost()
        self.assertEqual(self.manager.stopped_epochs,{})
        with self.assertRaisesRegex(runtime.ManagerError,'stale_runtime'):
            self.handle(self.request(revision=1,action='stop',runtime_epoch=first['runtime_epoch']))
        stopped,_=self.handle(self.request(revision=1,action='stop'))
        self.assertTrue(stopped['stopped'])

    def test_invalid_input_never_spawns(self):
        for change in ({'token':'0'*64},{'token':'你'},{'profile_id':'../other'},
                       {'version':True},{'revision':True},{'revision':0},{'command':'exec'}, {'action':'delete'},
                       {'runtime_epoch':'a'*32}):
            value=self.request();value.update(change)
            with self.assertRaises(runtime.ManagerError):self.handle(value)
        self.assertFalse(self.manager.records)
    def test_health_never_allocates_a_profile_or_advances_revision(self):
        response,rights=self.handle(self.request(action='health'))
        self.assertTrue(response['manager_ready']);self.assertEqual(rights,[])
        self.assertTrue(response['profiles_alive'])
        self.assertFalse(self.manager.records);self.assertFalse(self.manager.revisions)
        self.handle(self.request(revision=8))
        self.handle(self.request(action='health'))
        self.assertEqual(self.manager.revisions['default'],8)
    def test_abrupt_worker_exit_requires_actual_generation_absence_before_freeing_slot(self):
        first,_=self.handle(self.request());record=self.manager.records['default']
        record.worker.process.kill();record.worker.process.wait(timeout=2)
        health,_=self.handle(self.request(action='health'))
        self.assertFalse(health['profiles_alive']);self.assertTrue(health['manager_ready'])
        # The worker's exit code alone is never proof. A failed inventory keeps
        # the generation and slot, and the automatic pass is consumed once.
        with patch.object(runtime.resources,'reconcile',return_value=False) as reconcile:
            with self.assertRaisesRegex(runtime.ManagerError,'cleanup_unconfirmed'):
                self.handle(self.request(revision=2,action='stop'))
            with self.assertRaisesRegex(runtime.ManagerError,'cleanup_unconfirmed'):
                self.handle(self.request(revision=3))
            reconcile.assert_called_once()
        self.assertIs(self.manager.records['default'],record)
        self.assertEqual(self.manager.slots[0],'default')
        # Manual cleanup performs the real /proc generation check and may
        # reclaim only after the disposable peer and all its services are gone.
        result,_=self.handle(self.request(action='cleanup'))
        self.assertEqual(result['cleaned'],1);self.assertEqual(result['pending'],0)
        self.assertEqual(result['results'][0]['runtime_epoch'],first['runtime_epoch'])
        self.assertNotIn('default',self.manager.records);self.assertFalse(self.manager.slots)
    def test_shutdown_rejects_new_start_without_reserving_a_slot(self):
        self.manager.stopping=True
        with self.assertRaisesRegex(runtime.ManagerError,'runtime_unavailable'):
            self.handle(self.request())
        self.assertFalse(self.manager.records);self.assertFalse(self.manager.slots)
    def test_failed_start_write_receives_one_automatic_reconciliation(self):
        send=runtime.wire.send
        def reject_start(channel,message,*args):
            if message.get('action')=='start':raise OSError('fixture send failure')
            return send(channel,message,*args)
        with patch.object(runtime.wire,'send',side_effect=reject_start):
            with self.assertRaisesRegex(runtime.ManagerError,'profile_start_failed') as caught:
                self.handle(self.request())
        self.assertTrue(caught.exception.cleanup_receipt['cleanup_confirmed'])
        self.assertFalse(self.manager.records);self.assertFalse(self.manager.slots)
        self.assertIn('default',self.manager.stopped_epochs)
    def test_partial_success_write_never_appends_a_second_response(self):
        a,b=socket.socketpair();self.manager.inflight.acquire()
        runtime.wire.send(a,self.request(action='health'))
        sent=[]
        def fail_send(channel,message,*args):
            sent.append(message);raise OSError('fixture partial send')
        with patch.object(runtime.wire,'send',side_effect=fail_send):
            self.manager.connection(b)
        a.close();self.assertEqual(len(sent),1);self.assertTrue(sent[0]['ok'])
    def test_gateway_restart_retires_old_report_leg_without_restarting_profile(self):
        first,rights=self.handle(self.request());old_token=self.manager.token
        pid=self.manager.records['default'].worker.process.pid
        self.manager.gateway_lost()
        with self.assertRaisesRegex(runtime.ManagerError,'unauthorized'):
            self.handle(dict(self.request(revision=2),token=old_token))
        second,new=self.handle(self.request())
        self.assertEqual(first['runtime_epoch'],second['runtime_epoch'])
        self.assertNotEqual(first['fido_gateway_epoch'],second['fido_gateway_epoch'])
        self.assertEqual(pid,self.manager.records['default'].worker.process.pid)
        endpoint=socket.socket(fileno=os.dup(rights[0]));endpoint.settimeout(1)
        try:self.assertEqual(endpoint.recv(1),b'')
        finally:endpoint.close()
        self.assertEqual(len(new),1)
    def test_newer_stop_cancels_a_start_reply_before_its_capability_is_published(self):
        started=threading.Event();release=threading.Event();outcome=[]
        factory=self.manager.worker_factory
        def delayed(*args,**kwargs):
            worker=factory(*args,**kwargs);receive=worker.receive;first=[True]
            def wait():
                if first[0]:
                    first[0]=False;started.set();release.wait(2)
                return receive()
            worker.receive=wait
            return worker
        self.manager.worker_factory=delayed
        def call(request):
            try:outcome.append(self.handle(request)[0])
            except runtime.ManagerError as error:outcome.append(str(error))
        ensure=threading.Thread(target=call,args=(self.request(),));ensure.start();self.assertTrue(started.wait(2))
        stop=threading.Thread(target=call,args=(self.request(revision=2,action='stop'),));stop.start()
        deadline=time.monotonic()+2
        while self.manager.revisions.get('default')!=2 and time.monotonic()<deadline:time.sleep(.001)
        self.assertEqual(self.manager.revisions['default'],2)
        release.set();ensure.join(3);stop.join(3)
        self.assertFalse(ensure.is_alive());self.assertFalse(stop.is_alive())
        self.assertIn('stale_revision',outcome)
        self.assertTrue(any(isinstance(v,dict) and v.get('stopped') for v in outcome))
        self.assertFalse(self.manager.records);self.assertFalse(self.rights)
    def test_newer_stop_cancels_explicit_attachment_before_publishing_rights(self):
        self.handle(self.request())
        record = self.manager.records['default']
        started = threading.Event()
        release = threading.Event()
        outcome = []
        offered = []
        exchange = record.worker.exchange
        def delayed(message):
            reply, rights = exchange(message)
            if message['action'] == 'gateway':
                offered.extend(rights)
                started.set()
                if not release.wait(3):
                    runtime.wire.close_rights(rights)
                    raise AssertionError('fixture attachment release timed out')
            return reply, rights
        record.worker.exchange = delayed
        def call(request):
            try:
                outcome.append(self.handle(request)[0])
            except runtime.ManagerError as error:
                outcome.append(str(error))
        attach = threading.Thread(target=call, args=(self.request(revision=2, attach_gateway=True),))
        stop = threading.Thread(target=call, args=(self.request(revision=3, action='stop'),))
        attach.start()
        try:
            self.assertTrue(started.wait(2))
            stop.start()
            deadline = time.monotonic() + 2
            while self.manager.revisions.get('default') != 3 and time.monotonic() < deadline:
                time.sleep(.001)
            self.assertEqual(self.manager.revisions['default'], 3)
        finally:
            release.set()
            attach.join(3)
            if stop.ident is not None:
                stop.join(3)
        self.assertFalse(attach.is_alive())
        self.assertFalse(stop.is_alive())
        self.assertIn('stale_revision', outcome)
        self.assertTrue(any(isinstance(value, dict) and value.get('stopped') for value in outcome))
        self.assertEqual(len(offered), 1)
        with self.assertRaises(OSError):
            os.fstat(offered[0])
        self.assertFalse(self.manager.records)
        self.assertFalse(self.manager.slots)

    def test_uncertain_reply_is_not_retransferred_and_explicit_stop_can_retire_it(self):
        a,b=socket.socketpair();self.manager.inflight.acquire()
        runtime.wire.send(a,self.request());a.close()
        thread=threading.Thread(target=self.manager.connection,args=(b,));thread.start();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertIn('default',self.manager.records)
        response,rights=self.handle(self.request(revision=2))
        self.assertEqual(rights,[]);self.assertNotIn('fido_gateway_epoch',response)
        stopped,_=self.handle(self.request(revision=3,action='stop'))
        self.assertTrue(stopped['stopped'])

    def test_explicit_cleanup_forces_resistant_owned_worker_and_preserves_other_profile(self):
        resistant = FIXTURE.replace('import json,os,pathlib,secrets,socket,sys',
            'import json,os,pathlib,secrets,signal,socket,sys\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)')
        resistant = resistant.replace("wire.send(control,dict(ok=True,stopped=True));break", "continue")
        self.fixture.write_text(resistant)
        profile = str(uuid.uuid4())
        first, _ = self.handle(self.request(profile))
        record = self.manager.records[profile]
        marker = record.paths.profile/'saved-tabs'
        marker.write_text('preserve saved browser state')
        self.fixture.write_text(FIXTURE)
        self.handle(self.request())
        healthy = self.manager.records['default']
        started = time.monotonic()
        result, _ = self.handle(self.request(action='cleanup', cleanup_profiles=[profile],
            cleanup_stop_profiles=[dict(profile_id=profile, runtime_epoch=first['runtime_epoch'])]))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(result['cleaned'], 1)
        self.assertEqual(result['pending'], 0)
        self.assertEqual(record.worker.process.returncode, -runtime.signal.SIGKILL)
        self.assertNotIn(profile, self.manager.records)
        self.assertFalse((record.paths.runtime/runtime.resources.MANIFEST).exists())
        self.assertEqual(marker.read_text(), 'preserve saved browser state')
        self.assertIs(self.manager.records['default'], healthy)
        self.assertIsNone(healthy.worker.process.poll())

    def test_explicit_stop_retries_force_after_automatic_cleanup_was_consumed(self):
        resistant = FIXTURE.replace('import json,os,pathlib,secrets,socket,sys',
            'import json,os,pathlib,secrets,signal,socket,sys\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)')
        resistant = resistant.replace("wire.send(control,dict(ok=True,stopped=True));break", "continue")
        self.fixture.write_text(resistant)
        first, _ = self.handle(self.request())
        record = self.manager.records['default']
        record.state = 'cleanup_unconfirmed'
        record.cleanup_attempted = True
        started = time.monotonic()
        result, _ = self.handle(self.request(revision=2, action='stop', runtime_epoch=first['runtime_epoch']))
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(result['stopped'])
        self.assertEqual(record.worker.process.returncode, -runtime.signal.SIGKILL)
        self.assertFalse(self.manager.records)
        self.assertFalse(self.manager.slots)

    def test_delete_data_reports_stable_failure_categories(self):
        profile = str(uuid.uuid4())
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = True
        for error, code in ((PermissionError('fixture'), 'profile_data_permission_denied'),
                            (ValueError('fixture unsafe path'), 'profile_data_unsafe_path'),
                            (OSError('fixture IO'), 'profile_data_delete_failed')):
            with self.subTest(code=code), patch.object(runtime.erasure, 'erase', side_effect=error):
                with self.assertRaisesRegex(runtime.ManagerError, '^' + code + '$'):
                    self.handle(self.request(profile, action='delete_data'))

    def test_cleanup_accepts_already_missing_manifest_only_after_generation_absence(self):
        self.handle(self.request())
        record = self.manager.records['default']
        (record.paths.runtime/runtime.resources.MANIFEST).unlink()
        # Losing a file is not permission to kill a still-running process.
        with patch.object(runtime.resources, 'reconcile') as reconcile:
            record.state = 'cleanup_unconfirmed'
            result, _ = self.handle(self.request(action='cleanup'))
        reconcile.assert_not_called()
        self.assertEqual(result['results'][0]['error'], 'ownership_unconfirmed')
        self.assertIsNone(record.worker.process.poll())
        record.worker.process.kill()
        record.worker.process.wait(timeout=2)
        result, _ = self.handle(self.request(action='cleanup'))
        self.assertEqual(result['cleaned'], 1)
        self.assertEqual(result['pending'], 0)
        self.assertFalse(self.manager.records)
        self.assertFalse(self.manager.slots)

    def test_cleanup_reports_permission_failure_and_keeps_owned_record(self):
        first, _ = self.handle(self.request())
        record = self.manager.records['default']
        with patch.object(self.manager, 'stop_worker', return_value=False), \
                patch.object(runtime.resources, 'reconcile', side_effect=PermissionError('fixture denial')) as reconcile:
            result, _ = self.handle(self.request(action='cleanup', cleanup_profiles=['default'],
                cleanup_stop_profiles=[dict(profile_id='default', runtime_epoch=first['runtime_epoch'])]))
        self.assertTrue(reconcile.call_args.kwargs['force'])
        self.assertEqual(result['results'][0]['error'], 'permission_denied')
        self.assertFalse(result['results'][0]['stopped'])
        self.assertIs(self.manager.records['default'], record)
        self.assertIsNone(record.worker.process.poll())
        self.assertTrue((record.paths.runtime/runtime.resources.MANIFEST).exists())

    def test_cleanup_refuses_changed_manifest_before_any_stop_or_signal(self):
        first, _ = self.handle(self.request())
        record = self.manager.records['default']
        with patch.object(runtime.resources, 'read', return_value=dict(record.manifest, generation='0'*64)), \
                patch.object(self.manager, 'stop_worker') as stop, \
                patch.object(runtime.resources, 'reconcile') as reconcile:
            result, _ = self.handle(self.request(action='cleanup', cleanup_profiles=['default'],
                cleanup_stop_profiles=[dict(profile_id='default', runtime_epoch=first['runtime_epoch'])]))
        stop.assert_not_called()
        reconcile.assert_not_called()
        self.assertEqual(result['results'][0]['error'], 'resource_generation_changed')
        self.assertFalse(result['results'][0]['stopped'])
        self.assertIs(self.manager.records['default'], record)

    def test_cleanup_skips_unrelated_startup_while_ensure_is_busy(self):
        started = threading.Event()
        release = threading.Event()
        outcome = []
        factory = self.manager.worker_factory
        def delayed(*args, **kwargs):
            worker = factory(*args, **kwargs)
            receive = worker.receive
            def wait():
                started.set()
                if not release.wait(3):
                    raise AssertionError('fixture startup release timed out')
                return receive()
            worker.receive = wait
            return worker
        self.manager.worker_factory = delayed
        def ensure():
            try:
                outcome.append(self.handle(self.request())[0])
            except BaseException as error:
                outcome.append(error)
        thread = threading.Thread(target=ensure)
        thread.start()
        try:
            self.assertTrue(started.wait(2))
            result, _ = self.handle(self.request(action='cleanup'))
            self.assertEqual((result['cleaned'], result['pending'], result['skipped']), (0, 0, 1))
            self.assertEqual(result['results'], [])
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], dict)
        self.assertEqual(self.manager.records['default'].epoch, outcome[0]['runtime_epoch'])
        self.assertIsNone(self.manager.records['default'].worker.process.poll())

    def test_cleanup_rechecks_newly_healthy_generation_after_acquiring_operation(self):
        first, _ = self.handle(self.request())
        record = self.manager.records['default']
        original = record.operation
        class FinishStartupOnAcquire:
            def acquire(self, **kwargs):
                record.state = 'running'
                return original.acquire(**kwargs)
            def release(self):
                original.release()
        record.state = 'starting'
        record.operation = FinishStartupOnAcquire()
        try:
            with patch.object(self.manager, 'reconcile_record') as reconcile:
                result, _ = self.handle(self.request(action='cleanup'))
                reconcile.assert_not_called()
            self.assertEqual((result['cleaned'], result['pending'], result['skipped']), (0, 0, 1))
            self.assertEqual(result['results'], [])
            self.assertEqual(record.epoch, first['runtime_epoch'])
            self.assertIsNone(record.worker.process.poll())
        finally:
            record.operation = original

    def test_cleanup_keeps_receipt_when_startup_fails_before_operation_acquisition(self):
        self.handle(self.request())
        record = self.manager.records['default']
        original = record.operation
        class FailStartupOnAcquire:
            def acquire(self, **kwargs):
                record.state = 'cleanup_unconfirmed'
                return original.acquire(**kwargs)
            def release(self):
                original.release()
        record.operation = FailStartupOnAcquire()
        try:
            for confirmed in (False, True):
                record.state = 'starting'
                with patch.object(self.manager, 'reconcile_record', return_value=confirmed) as reconcile:
                    result, _ = self.handle(self.request(action='cleanup'))
                    reconcile.assert_called_once()
                self.assertEqual(result['results'], [dict(profile_id='default',
                                 runtime_epoch=record.epoch, stopped=confirmed)])
                self.assertEqual(result['skipped'], 0)
        finally:
            record.operation = original

    def test_cleanup_does_not_count_a_concurrently_completed_record_as_skipped(self):
        first, _ = self.handle(self.request())
        record = self.manager.records['default']
        original = record.operation
        manager = self.manager
        class FinishStopOnAcquire:
            def acquire(self, **kwargs):
                with original:
                    if not manager.reconcile_record(record, time.monotonic() + 3):
                        raise AssertionError('fixture stop did not finish')
                return original.acquire(**kwargs)
            def release(self):
                original.release()
        record.state = 'cleanup_unconfirmed'
        record.operation = FinishStopOnAcquire()
        try:
            result, _ = self.handle(self.request(action='cleanup'))
        finally:
            record.operation = original
        self.assertEqual((result['cleaned'], result['pending'], result['skipped']), (0, 0, 0))
        self.assertEqual(result['results'], [])
        self.assertFalse(self.manager.records)
        self.assertEqual(self.manager.stopped_epochs, {'default': first['runtime_epoch']})

    def test_inventory_scan_discards_outcome_after_concurrent_admission(self):
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = True
        def scan(*args, **kwargs):
            self.handle(self.request())
            return False
        with patch.object(runtime.resources, 'pristine_start', side_effect=scan):
            self.manager.refresh_startup_inventory(time.monotonic() + 5)
        self.assertFalse(self.manager.startup_unaccounted)
        self.assertTrue(self.manager.startup_pristine)
        self.assertIsNone(self.manager.records['default'].worker.process.poll())
        # A stale successful scan cannot grant admission either.
        self.manager.startup_pristine = False
        self.manager.startup_unaccounted = True
        record = self.manager.records['default']
        def changed(*args, **kwargs):
            record.manifest = dict(record.manifest, generation='a' * 64)
            return True
        manifest = record.manifest
        try:
            with patch.object(runtime.resources, 'pristine_start', side_effect=changed):
                self.manager.refresh_startup_inventory(time.monotonic() + 5)
            self.assertTrue(self.manager.startup_unaccounted)
            self.assertFalse(self.manager.startup_pristine)
        finally:
            record.manifest = manifest

    def test_manual_cleanup_preserves_healthy_stack_even_for_uncertain_caller(self):
        first,_=self.handle(self.request())
        record=self.manager.records['default'];pid=record.worker.process.pid
        with patch.object(record.worker,'exchange',wraps=record.worker.exchange) as exchange:
            result,_=self.handle(self.request(action='cleanup'))
            self.assertEqual((result['cleaned'],result['pending'],result['skipped']),(0,0,1))
            result,_=self.handle(self.request(action='cleanup',cleanup_profiles=['default']))
            self.assertEqual((result['cleaned'],result['pending'],result['skipped']),(0,1,0))
            exchange.assert_not_called()
        self.assertEqual(record.epoch,first['runtime_epoch']);self.assertEqual(record.worker.process.pid,pid)
        self.assertIsNone(record.worker.process.poll())

    def test_persisted_stop_selector_is_exact_and_general_uncertainty_is_not_authority(self):
        first,_=self.handle(self.request())
        stale='0'*32
        result,_=self.handle(self.request(action='cleanup',cleanup_profiles=['default'],
                           cleanup_stop_profiles=[dict(profile_id='default',runtime_epoch=stale)]))
        self.assertEqual(result['pending'],1);self.assertIsNone(self.manager.records['default'].worker.process.poll())
        result,_=self.handle(self.request(action='cleanup',cleanup_profiles=['default'],
                           cleanup_stop_profiles=[dict(profile_id='default',runtime_epoch=first['runtime_epoch'])]))
        self.assertEqual(result['cleaned'],1);self.assertFalse(self.manager.records)
        replacement,_=self.handle(self.request(revision=2))
        result,_=self.handle(self.request(action='cleanup',cleanup_profiles=['default'],
                           cleanup_stop_profiles=[dict(profile_id='default',runtime_epoch=first['runtime_epoch'])]))
        self.assertEqual(result['pending'],1)
        self.assertEqual(self.manager.records['default'].epoch,replacement['runtime_epoch'])
        for change in (dict(action='cleanup_status'),dict(cleanup_profiles=[])):
            request=self.request(action='cleanup',cleanup_profiles=['default'],
                                 cleanup_stop_profiles=[dict(profile_id='default',runtime_epoch=None)])
            request.update(change)
            with self.assertRaisesRegex(runtime.ManagerError,'invalid_request'):
                self.handle(request)

    def test_startup_durable_intent_runs_once_and_never_retries_generic_failure(self):
        first,_=self.handle(self.request());record=self.manager.records['default']
        request=self.request(action='cleanup_startup',cleanup_profiles=['default'],
                             cleanup_stop_profiles=[dict(profile_id='default',runtime_epoch=first['runtime_epoch'])])
        with patch.object(self.manager,'reconcile_record',return_value=False) as reconcile:
            for _ in range(2):
                result,_=self.handle(request)
                self.assertEqual(result['pending'],1)
            reconcile.assert_called_once()
        self.assertTrue(record.cleanup_attempted)
        with patch.object(self.manager,'reconcile_record') as reconcile:
            result,_=self.handle(self.request(action='cleanup_startup'))
            self.assertEqual(result['pending'],1);reconcile.assert_not_called()

    def test_full_budget_known_failure_preserves_prior_inventory_and_healthy_ensure(self):
        healthy,_=self.handle(self.request())
        failed_id=str(uuid.uuid4());self.handle(self.request(failed_id))
        failed=self.manager.records[failed_id];failed.state='cleanup_unconfirmed'
        self.manager.startup_cleanup_done=True
        self.manager.startup_pristine=True
        self.manager.startup_unaccounted=False
        clock=[0.0]
        def expire(record,deadline):
            self.assertIs(record,failed);clock[0]=deadline+1;return False
        with patch.object(runtime.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(self.manager,'reconcile_record',side_effect=expire), \
                patch.object(runtime.resources,'pristine_start') as scan:
            result,_=self.handle(self.request(action='cleanup'))
            scan.assert_not_called()
        self.assertEqual((result['pending'],result['skipped']),(1,1))
        self.assertFalse(self.manager.startup_unaccounted)
        again,_=self.handle(self.request(revision=2))
        self.assertEqual(healthy['runtime_epoch'],again['runtime_epoch'])

    def test_unaccounted_external_generation_blocks_new_slots_without_blocking_known_live_ensure(self):
        healthy,_=self.handle(self.request())
        self.manager.startup_unaccounted=True
        again,_=self.handle(self.request(revision=2))
        self.assertEqual(healthy['runtime_epoch'],again['runtime_epoch'])
        with patch.object(self.manager,'worker_factory') as launch:
            with self.assertRaisesRegex(runtime.ManagerError,'cleanup_unconfirmed'):
                self.handle(self.request(str(uuid.uuid4())))
            launch.assert_not_called()
        self.assertEqual(self.manager.slots,{0:'default'})

    def test_read_only_cleanup_status_never_retries_failed_generation(self):
        first,_=self.handle(self.request());record=self.manager.records['default']
        record.state='cleanup_unconfirmed';record.cleanup_attempted=True
        with patch.object(self.manager,'reconcile_record') as reconcile:
            result,_=self.handle(self.request(action='cleanup_status'))
            self.assertEqual(result['pending'],1);reconcile.assert_not_called()
        self.assertEqual(record.epoch,first['runtime_epoch'])
        self.assertTrue(record.cleanup_attempted)

    def test_cleanup_status_replays_exact_receipt_but_not_absence_or_replacement(self):
        first,_=self.handle(self.request())
        self.handle(self.request(revision=2,action='stop',runtime_epoch=first['runtime_epoch']))
        result,_=self.handle(self.request(action='cleanup_status',cleanup_profiles=['default']))
        self.assertEqual(result['results'],[dict(profile_id='default',runtime_epoch=first['runtime_epoch'],stopped=True)])
        unknown=str(uuid.uuid4())
        result,_=self.handle(self.request(action='cleanup_status',cleanup_profiles=[unknown]))
        self.assertFalse(result['results'][0]['stopped'])
        replacement,_=self.handle(self.request(revision=3))
        result,_=self.handle(self.request(action='cleanup',cleanup_profiles=['default']))
        self.assertEqual(result['results'],[dict(profile_id='default',runtime_epoch=replacement['runtime_epoch'],stopped=False)])
        self.assertIsNone(self.manager.records['default'].worker.process.poll())

    def test_no_record_stop_does_not_poison_pristine_cleanup_proof(self):
        profile = str(uuid.uuid4())
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = True
        # A disabled profile can receive several stops before ever being opened.
        # Its ordering tombstone must not leave durable cleanup pending forever.
        for revision in (1, 2):
            stopped, _ = self.handle(self.request(profile, revision, 'stop'))
            self.assertTrue(stopped['stopped'])
        with patch.object(self.manager, 'refresh_startup_inventory'):
            for action in ('cleanup_status', 'cleanup_startup', 'cleanup'):
                result, _ = self.handle(self.request(action=action, cleanup_profiles=[profile]))
                self.assertEqual((result['cleaned'], result['pending']), (1, 0))
                self.assertEqual(result['results'], [dict(profile_id=profile, runtime_epoch=None, stopped=True)])
        with self.assertRaisesRegex(runtime.ManagerError, 'stale_revision'):
            self.handle(self.request(profile, 2))
        self.handle(self.request(profile, 3))
        result, _ = self.handle(self.request(action='cleanup_status', cleanup_profiles=[profile]))
        self.assertEqual((result['cleaned'], result['pending']), (0, 1))
        self.assertIsNone(self.manager.records[profile].worker.process.poll())

    def test_recovered_inventory_proves_dormant_profile_while_other_profile_lives(self):
        healthy, _ = self.handle(self.request())
        profile = str(uuid.uuid4())
        self.handle(self.request(profile, 1, 'stop'))
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = False
        self.manager.startup_unaccounted = True
        with patch.object(runtime.resources, 'pristine_start', return_value=True) as scan:
            result, _ = self.handle(self.request(action='cleanup', cleanup_profiles=[profile]))
        self.assertEqual((result['cleaned'], result['pending'], result['skipped']), (1, 0, 1))
        self.assertTrue(self.manager.startup_pristine)
        self.assertFalse(self.manager.startup_unaccounted)
        self.assertEqual(scan.call_args.kwargs['allowed_slots'], {0})
        self.assertIn(self.manager.records['default'].manifest['generation'],
                      scan.call_args.kwargs['allowed_generations'])
        self.assertEqual(self.manager.records['default'].epoch, healthy['runtime_epoch'])
        self.assertIsNone(self.manager.records['default'].worker.process.poll())

    def test_never_opened_profile_can_delete_while_other_profile_stays_live(self):
        healthy, _ = self.handle(self.request())
        profile = str(uuid.uuid4())
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = False
        self.manager.startup_unaccounted = True
        # The dormant profile never acquired a worker or persistent directory.
        stopped, _ = self.handle(self.request(profile, 1, 'stop'))
        self.assertTrue(stopped['stopped'])
        self.assertFalse((self.root / 'data' / 'profiles' / profile).exists())
        with patch.object(runtime.resources, 'pristine_start', return_value=True):
            result, _ = self.handle(self.request(action='cleanup', cleanup_profiles=[profile]))
        self.assertEqual((result['cleaned'], result['pending']), (1, 0))
        deleted, _ = self.handle(self.request(profile, 2, 'delete_data'))
        self.assertTrue(deleted['browser_data_deleted'])
        forgotten, _ = self.handle(self.request(profile, 3, 'forget_deleted'))
        self.assertTrue(forgotten['forgotten'])
        with patch.object(runtime.resources, 'pristine_start', return_value=True):
            result, _ = self.handle(self.request(action='cleanup'))
        self.assertEqual((result['cleaned'], result['pending'], result['skipped']), (0, 0, 1))
        again, _ = self.handle(self.request(revision=2))
        self.assertEqual(again['runtime_epoch'], healthy['runtime_epoch'])

    def test_lost_delete_and_ack_replies_preserve_proof_until_durable_completion(self):
        healthy, _ = self.handle(self.request())
        profile = str(uuid.uuid4())
        opened, _ = self.handle(self.request(profile, 2))
        record = self.manager.records[profile]
        self.manager.startup_cleanup_done = True
        self.manager.startup_pristine = False
        self.handle(self.request(profile, 3, 'stop', runtime_epoch=opened['runtime_epoch']))
        # An unowned diagnostic file is deliberately preserved by teardown.
        # Completed erasure proof must survive it, including gateway replacement.
        self.assertTrue((record.paths.runtime / 'fixture.json').exists())
        self.handle(self.request(profile, 4, 'delete_data'))
        self.manager.gateway_lost()
        with patch.object(self.manager, 'refresh_startup_inventory'):
            for _ in range(2):
                receipt, _ = self.handle(self.request(action='cleanup'))
                self.assertEqual(receipt['results'], [dict(profile_id=profile,
                    runtime_epoch=opened['runtime_epoch'], stopped=True)])
                self.assertEqual((receipt['cleaned'], receipt['pending'], receipt['skipped']), (1, 0, 1))
        # The gateway replays its durable job if the successful erase reply or
        # journal write was lost, then acknowledges only after that commit.
        self.assertTrue(self.handle(self.request(profile, 1, 'delete_data'))[0]['browser_data_deleted'])
        for _ in range(2):
            self.assertTrue(self.handle(self.request(profile, 2, 'forget_deleted'))[0]['forgotten'])
        with patch.object(self.manager, 'refresh_startup_inventory'):
            for _ in range(3):
                receipt, _ = self.handle(self.request(action='cleanup'))
                self.assertEqual((receipt['cleaned'], receipt['pending'], receipt['skipped']), (0, 0, 1))
                self.assertEqual(receipt['results'], [])
        self.assertNotIn(profile, self.manager.revisions)
        self.assertNotIn(profile, self.manager.stopped_epochs)
        self.assertNotIn(profile, self.manager.deleted_profiles)
        self.assertFalse(record.paths.home.exists())
        self.assertTrue((record.paths.runtime / 'fixture.json').exists())
        self.assertEqual(self.manager.records['default'].epoch, healthy['runtime_epoch'])
        self.assertIsNone(self.manager.records['default'].worker.process.poll())
        for revision in (1, 2):
            with self.assertRaisesRegex(runtime.ManagerError, 'stale_revision'):
                self.handle(self.request(profile, revision))
        replacement = str(uuid.uuid4())
        started, _ = self.handle(self.request(replacement, 3))
        self.assertEqual(self.manager.records[replacement].epoch, started['runtime_epoch'])

    def test_no_record_stop_never_proves_unknown_runtime_ownership(self):
        profile = str(uuid.uuid4())
        self.manager.startup_pristine = True
        self.handle(self.request(profile, 1, 'stop'))
        path = self.root / 'run' / profile
        path.mkdir(parents=True, mode=0o700)
        marker = path / 'unknown.sock'
        marker.write_text('unowned fixture')
        result, _ = self.handle(self.request(action='cleanup_status', cleanup_profiles=[profile]))
        self.assertEqual((result['cleaned'], result['pending']), (0, 1))
        self.assertEqual(marker.read_text(), 'unowned fixture')
        marker.unlink()
        path.rmdir()
        target = self.root / 'foreign'
        target.mkdir(mode=0o700)
        path.symlink_to(target, target_is_directory=True)
        result, _ = self.handle(self.request(action='cleanup_status', cleanup_profiles=[profile]))
        self.assertEqual(result['pending'], 1)
        path.unlink()
        self.manager.startup_pristine = False
        result, _ = self.handle(self.request(action='cleanup_status', cleanup_profiles=[profile]))
        self.assertEqual(result['pending'], 1)
        self.manager.startup_pristine = True
        self.manager.startup_unaccounted = True
        with self.assertRaisesRegex(runtime.ManagerError, 'cleanup_unconfirmed'):
            self.handle(self.request(action='cleanup_status', cleanup_profiles=[profile]))

    def test_dead_cached_ensure_emits_exact_auto_cleanup_receipt_once(self):
        first,_=self.handle(self.request());record=self.manager.records['default']
        record.worker.process.kill();record.worker.process.wait(timeout=2)
        with self.assertRaisesRegex(runtime.ManagerError,'profile_exited') as caught:
            self.handle(self.request(revision=2))
        self.assertEqual(caught.exception.cleanup_receipt,dict(cleanup_confirmed=True,
                         runtime_epoch=first['runtime_epoch'],revision=2))
        self.assertFalse(self.manager.records)

    def test_authenticated_stream_reply_transfers_exactly_one_cloexec_fd(self):
        a,b=socket.socketpair();self.manager.inflight.acquire()
        thread=threading.Thread(target=self.manager.connection,args=(b,));thread.start()
        runtime.wire.send(a,self.request())
        value,rights=runtime.wire.receive(a,allow_rights=True);self.rights.extend(rights)
        self.assertTrue(value['ok']);self.assertEqual(len(rights),1)
        self.assertFalse(os.get_inheritable(rights[0]));a.close();thread.join(2)
        self.assertFalse(thread.is_alive())
    def test_invalid_capability_has_a_bounded_error_response(self):
        a,b=socket.socketpair();self.manager.inflight.acquire()
        thread=threading.Thread(target=self.manager.connection,args=(b,));thread.start()
        runtime.wire.send(a,dict(self.request(),token='0'*64))
        value,rights=runtime.wire.receive(a);self.assertEqual(rights,[])
        self.assertEqual(value['error'],'unauthorized');self.assertFalse(self.manager.records)
        a.close();thread.join(2)


class SharedGatewayContractTests(unittest.TestCase):
    """The Rust suite reads the same wire literals using its production codec."""
    def test_shared_gateway_requests_and_replies(self):
        fixture=json.loads((ROOT/'tests/fixtures/profile_manager_protocol.json').read_text())
        timing=fixture['timing_seconds']
        self.assertEqual(timing['worker_reply'],runtime.WORKER_REPLY_TIMEOUT)
        self.assertEqual(timing['worker_exit'],runtime.WORKER_EXIT_TIMEOUT)
        self.assertEqual(timing['manager_send'],runtime.CONTROL_IO_TIMEOUT)
        self.assertGreater(timing['stop'],runtime.WORKER_REPLY_TIMEOUT+runtime.WORKER_EXIT_TIMEOUT+runtime.CONTROL_IO_TIMEOUT)
        class Process:
            returncode=None
            def poll(self):return self.returncode
        class Worker:
            def __init__(self,*args,**kwargs):self.process=Process()
            def receive(self):return dict(ok=True,runtime_epoch=fixture['runtime_epoch']),[]
            def exchange(self,message):
                if message=={'action':'stop'}:
                    self.process.returncode=0
                    return dict(ok=True,stopped=True),[]
                raise AssertionError('Unexpected contract worker operation')
            def stopped(self,timeout=0):return self.process.returncode==0
        for case in fixture['cases'] + fixture.get('cleanup_cases', []):
            with self.subTest(case=case['name']):
                manager=runtime.ProfileManager(worker_factory=Worker)
                manager.token=fixture['token']
                if case['setup']!='absent':
                    initial=fixture['cases'][0]['request']
                    manager.handle(initial)
                if case['setup']=='dead':
                    manager.records['default'].worker.process.returncode=-9
                if case['setup']=='stopped':
                    manager.handle(dict(fixture['cases'][0]['request'],action='stop',revision=2,
                                        runtime_epoch=fixture['runtime_epoch']))
                if 'error' in case:
                    with self.assertRaisesRegex(runtime.ManagerError,'^'+case['error']+'$'):
                        manager.handle(case['request'])
                else:
                    response,rights=manager.handle(case['request'])
                    self.assertEqual(response,case['reply'])
                    self.assertEqual(len(rights),case['fd_count'])
                    self.assertEqual(rights,[])
                if case['name']=='cached_ensure':
                    self.assertEqual(response['runtime_epoch'],fixture['runtime_epoch'])
                    self.assertNotEqual(response,fixture['stale_cached_reply'])
                    self.assertNotIn('fido_gateway_epoch',response)
                if case['name']=='uncertain_cleanup_stop':
                    self.assertEqual(manager.slots,{0:'default'})


if __name__=='__main__':unittest.main()
