"""Profile-local launch, resize and sibling FIDO isolation without real services."""
import importlib.util
import json
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
import tempfile
from unittest.mock import Mock, patch

from profile_display_test import RandRModel

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('profile_supervisor_tests',ROOT/'runtime/supervisor.py')
runtime=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(runtime)


class ProfileSupervisorTests(unittest.TestCase):
    def model(self):
        with patch.object(runtime._fido_control.FidoController,'from_environment',return_value=None):
            model=runtime.Supervisor()
        model.children=[('Chromium',Mock(poll=Mock(return_value=None)))]
        model.check_children=Mock();model.browser_windows=Mock(return_value=['0x4000007'])
        model.display_ready=Mock(return_value=True);model.vnc_ready=Mock(return_value=True)
        return model
    def message(self, model, **values):
        return dict(command='ensure',request_id='11111111-1111-4111-8111-111111111111',
                    expected_epoch=model.browser_epoch,remaining_ms=1000,**values)
    def test_resize_requires_current_epoch_and_explicit_valid_dimensions(self):
        model=self.model();display=runtime._profile_modules['display_size']
        with patch.object(display,'resize',return_value={'width':1920,'height':1080}) as resize:
            stale=self.message(model,viewport={'width':1920,'height':1080});stale['expected_epoch']='old'
            with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(stale)
            resize.assert_not_called()
            model.browser_control(self.message(model,viewport={'width':1920,'height':1080}))
            self.assertEqual(resize.call_args.args,(runtime.DISPLAY,1920,1080))
            self.assertIs(resize.call_args.kwargs['env'],os.environ)
            self.assertTrue(callable(resize.call_args.kwargs['check']))
    def test_viewport_is_absent_for_observation_and_never_implicit(self):
        model=self.model();display=runtime._profile_modules['display_size']
        with patch.object(display,'resize') as resize:
            model.browser_control(self.message(model))
            for viewport in ({'width':True,'height':900},{'width':0,'height':900},{'width':1900}, {'width':1,'height':1,'command':'x'}):
                self.assertTrue(model.browser_control(self.message(model,viewport=viewport))['ok'])
            value=self.message(model,viewport={'width':1900,'height':1000});value['command']='inspect'
            reply=model.browser_control(value)
            self.assertTrue(reply['ok'])
            self.assertNotIn('display_width',reply)
            for viewport in ({'width':True,'height':900},{'width':0,'height':900},
                             {'width':16385,'height':900},{'width':1900},
                             {'width':1900,'height':1000,'secret':'ignored?'},'1920x1080'):
                value['viewport']=viewport
                self.assertTrue(model.browser_control(value)['ok'])
            resize.assert_not_called()
            model.check_children.assert_called()
    def test_cancel_during_resizing_cannot_continue_to_browser_close(self):
        model=self.model();live=[True];pipe=Mock();model.browser_pipe=pipe
        model.browser_pipe_process=model.children[0][1]
        def resize(*args,**kwargs):live[0]=False
        value=self.message(model,viewport={'width':1920,'height':1080});value['command']='restart'
        with patch.object(runtime._profile_modules['display_size'],'resize',side_effect=resize):
            with self.assertRaisesRegex(runtime.BrowserUnavailable,'canceled'):
                model.browser_control(value,lambda:live[0])
        pipe.close_browser.assert_not_called()
    def test_resize_failure_cannot_swallow_concurrent_owner_revocation(self):
        model=self.restart_model();live=[True]
        display=runtime._profile_modules['display_size']
        def resize(*args,**kwargs):
            live[0]=False
            raise display.DisplaySizeError('partial resize', 'resize_query_failed')
        value=self.message(model,viewport={'width':1920,'height':1080});value['command']='restart'
        with patch.object(display,'resize',side_effect=resize):
            with self.assertRaisesRegex(runtime.BrowserUnavailable,'canceled'):
                model.browser_control(value,lambda:live[0])
        model.browser_pipe.close_browser.assert_not_called();model.start_browser.assert_not_called()

    def restart_model(self):
        model=self.model();old=model.children[0][1];old.wait.return_value=0
        windows=['0x4000007'];model.browser_windows=lambda:list(windows)
        def close(**kwargs):model.browser_pipe_process.poll.return_value=0;windows.clear()
        model.browser_pipe=Mock(close_browser=Mock(side_effect=close));model.browser_pipe_process=old
        def start(**kwargs):
            model.browser_epoch=f'{model.start_browser.call_count:032x}';windows[:]=['0x4000008']
            browser=Mock(poll=Mock(return_value=None),wait=Mock(return_value=0))
            model.children=[('Chromium',browser)];model.browser_pipe_process=browser
        model.start_browser=Mock(side_effect=start);model.wait_ready=Mock();model.release_browser_pipe=Mock()
        model.restore_browser=Mock();model.proxy_ready=Mock(return_value=True);model.write_status=Mock()
        return model

    def test_repeated_owner_lifecycle_matches_current_viewport_in_both_directions(self):
        sizes = [(1920, 1080), (2560, 1440), (800, 600), (1920, 700),
                 (800, 1200), (1920, 1080), (800, 600)]
        display = runtime._profile_modules['display_size']
        # A live Ensure workflow reaches Maximize after its read-only phases.
        # An absent-browser Ensure and manual Restart can also carry geometry.
        for command in ('ensure', 'maximize', 'restart'):
            with self.subTest(command=command):
                model = self.restart_model()
                desktop = RandRModel({runtime.DISPLAY: [1440, 900]})
                with patch.object(display.subprocess, 'run', side_effect=desktop.run):
                    for index, (width, height) in enumerate(sizes, 1):
                        request = self.message(model, viewport={'width': width, 'height': height})
                        request.update(command=command,
                                       request_id=f'11111111-1111-4111-8111-{index:012x}')
                        reply = model.browser_control(request)
                        self.assertEqual((reply['display_width'], reply['display_height']),
                                         (width, height))
                        self.assertEqual(desktop.displays[runtime.DISPLAY], [width, height])
                        self.assertEqual(desktop.maximum[runtime.DISPLAY], (3840, 2160))
                        if command == 'restart':
                            request.update(command='maximize', expected_epoch=model.browser_epoch)
                            final = model.browser_control(request)
                            self.assertEqual((final['display_width'], final['display_height']),
                                             (width, height))
                restart_count = len(sizes) if command == 'restart' else 0
                self.assertEqual(model.browser_pipe.close_browser.call_count, restart_count)
                self.assertEqual(model.start_browser.call_count, restart_count)
                self.assertEqual(sum(call[0][3] == '--output' for call in desktop.calls), len(sizes))

    def test_failed_shrink_is_optional_and_next_request_can_resize_again(self):
        display = runtime._profile_modules['display_size']
        for command in ('ensure', 'maximize', 'restart'):
            with self.subTest(command=command):
                model = self.restart_model()
                desktop = RandRModel({runtime.DISPLAY: [1920, 1080]})

                def fail_after_apply(arguments, **options):
                    result = desktop.run(arguments, **options)
                    if arguments[3] == '--output':
                        desktop.fail_action = '--query'
                    return result

                request = self.message(model, viewport={'width': 800, 'height': 600})
                request['command'] = command
                with patch.object(display.subprocess, 'run', side_effect=fail_after_apply), \
                        patch('sys.stderr', new_callable=io.StringIO):
                    reply = model.browser_control(request)
                    self.assertTrue(reply['ok'])
                    self.assertNotIn('display_width', reply)
                    self.assertEqual(desktop.displays[runtime.DISPLAY], [800, 600])
                    before = len(desktop.calls)
                    request.update(command='maximize', expected_epoch=model.browser_epoch)
                    self.assertNotIn('display_width', model.browser_control(request))
                    self.assertEqual(len(desktop.calls), before)

                request.update(request_id='22222222-2222-4222-8222-222222222222',
                               viewport={'width': 1600, 'height': 900})
                with patch.object(display.subprocess, 'run', side_effect=desktop.run):
                    reply = model.browser_control(request)
                self.assertEqual((reply['display_width'], reply['display_height']), (1600, 900))
                restart_count = int(command == 'restart')
                self.assertEqual(model.browser_pipe.close_browser.call_count, restart_count)
                self.assertEqual(model.start_browser.call_count, restart_count)

    def test_resize_failure_cannot_swallow_expired_deadline_before_browser_close(self):
        model = self.restart_model()
        display = runtime._profile_modules['display_size']
        clock = [0.0]

        def resize(*args, **kwargs):
            clock[0] = 2.0
            raise display.DisplaySizeError('partial resize', 'resize_query_failed')

        request = self.message(model, viewport={'width': 800, 'height': 600})
        request['command'] = 'restart'
        with patch.object(runtime.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(display, 'resize', side_effect=resize), \
                patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaisesRegex(runtime.BrowserUnavailable, 'timed out'):
                model.browser_control(request)
        model.browser_pipe.close_browser.assert_not_called()
        model.start_browser.assert_not_called()
    def test_invalid_optional_viewport_does_not_block_exactly_one_restart(self):
        for viewport in ({'width':0,'height':900},{'width':True,'height':900},'bad',{'secret':'PRIVATE'}):
            model=self.restart_model();value=self.message(model,viewport=viewport);value['command']='restart'
            with patch.object(runtime._profile_modules['display_size'],'resize') as resize,patch('sys.stderr',new_callable=io.StringIO) as log:
                reply=model.browser_control(value)
                self.assertTrue(reply['ok']);self.assertTrue(reply['restarted'])
                self.assertNotIn('display_width',reply);resize.assert_not_called()
                self.assertIn('invalid_viewport',log.getvalue());self.assertNotIn('PRIVATE',log.getvalue())
            model.browser_pipe.close_browser.assert_called_once();model.start_browser.assert_called_once()
    def test_partial_resize_failure_continues_restart_without_replay_or_geometry_claim(self):
        model=self.restart_model();display=runtime._profile_modules['display_size']
        error=display.DisplaySizeError('PRIVATE URL / token', 'resize_query_failed')
        value=self.message(model,viewport={'width':1920,'height':1080});value['command']='restart'
        with patch.object(display,'resize',side_effect=error) as resize,patch('sys.stderr',new_callable=io.StringIO) as log:
            reply=model.browser_control(value)
            self.assertTrue(reply['restarted']);self.assertNotIn('display_width',reply)
            value.update(command='maximize',expected_epoch=model.browser_epoch)
            final=model.browser_control(value)
            self.assertTrue(final['ok']);self.assertNotIn('display_width',final)
            resize.assert_called_once();self.assertIn('resize_query_failed',log.getvalue());self.assertNotIn('PRIVATE',log.getvalue())
        model.browser_pipe.close_browser.assert_called_once();model.start_browser.assert_called_once()
    def test_inspect_maximize_diagnostics_are_fixed_and_correlated(self):
        for command,method,reason in [('inspect','browser_windows','inspect_failed'),('maximize','restore_browser','maximize_failed')]:
            model=self.restart_model();setattr(model,method,Mock(side_effect=OSError('PRIVATE https://secret/')))
            request=self.message(model);request['command']=command
            with self.assertRaises(OSError) as caught:model.browser_control(request)
            with patch('sys.stderr',new_callable=io.StringIO) as log:
                response=runtime.control_failure(request,caught.exception)
            self.assertEqual(response['command'],command);self.assertEqual(response['request_id'],request['request_id'])
            self.assertEqual(response['stage'],command);self.assertEqual(response['reason'],reason)
            self.assertNotIn('PRIVATE',json.dumps(response)+log.getvalue())
    def test_status_timestamp_changes_only_when_status_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'runtime.json';model=self.model()
            with patch.object(runtime,'STATUS_PATH',path),patch.object(runtime.time,'time_ns',side_effect=[1000000,9000000]):
                model.write_status('failed','old');first=json.loads(path.read_text())
                self.assertEqual(first['updated_at_unix_ms'],1)
                model.write_status('ready','current');self.assertEqual(json.loads(path.read_text())['updated_at_unix_ms'],9)
    def test_optional_initial_resize_failure_still_starts_desktop_services(self):
        model=self.model();model.spawn=Mock();model.wait_ready=Mock();model.start_browser=Mock()
        display=runtime._profile_modules['display_size']
        with patch.object(runtime,'PROFILE_ID','default'),patch.object(runtime,'prepare_x_socket_dir'),patch.object(display,'initialize',side_effect=display.DisplaySizeError('PRIVATE')),patch('sys.stderr',new_callable=io.StringIO) as log:
            model.start_desktop(wait_engine=False)
        names=[call.args[0] for call in model.spawn.call_args_list]
        self.assertIn('Openbox',names);self.assertIn('x11vnc',names);model.start_browser.assert_called_once()
        self.assertNotIn('PRIVATE',log.getvalue())

    def test_profile_stop_preserves_live_auxiliary_browser_until_ownership_is_confirmed(self):
        for primary_exit in (None,0):
            model=self.model();model.children[0][1].poll.return_value=primary_exit
            launcher=Mock(poll=Mock(return_value=None))
            model.children.append(('Chromium window launcher',launcher))
            model.browser_pipe=Mock();model.browser_pipe_process=model.children[0][1]
            with patch.object(runtime.os,'killpg') as signal:
                with self.assertRaisesRegex(runtime.BrowserUnavailable,'launcher is still active'):
                    model.stop_profile()
                signal.assert_not_called()
            model.browser_pipe.close_browser.assert_not_called()
            self.assertFalse(model.stopping)
            self.assertIn(('Chromium window launcher',launcher),model.children)

    def test_profile_stop_ack_requires_graceful_close_before_desktop_teardown(self):
        wire=runtime._profile_modules['profile_wire']
        for closed in (False,True):
            model=self.restart_model();model.profile_control=Mock();model.shutdown=Mock()
            if not closed:model.browser_pipe.close_browser.side_effect=None
            with patch.object(wire,'receive',return_value=({'action':'stop'},[])),patch.object(wire,'send') as send,patch.object(runtime.time,'monotonic',side_effect=[0,9]),patch.object(runtime.os,'killpg') as signal:
                model.serve_profile_control()
                reply=send.call_args.args[1]
                self.assertEqual(reply['ok'],closed)
                self.assertEqual(reply.get('stopped',False),closed)
                signal.assert_not_called()
            model.browser_pipe.close_browser.assert_called_once()
            if closed:model.shutdown.assert_called_once_with(desktop_only=True)
            else:model.shutdown.assert_not_called()
            self.assertEqual(model.stopping,closed)

    def test_promoted_launcher_without_private_pipe_remains_uncertain(self):
        model=self.model();old=model.children[0][1];old.poll.return_value=0
        launcher=Mock(poll=Mock(return_value=None));model.children.append(('Chromium window launcher',launcher))
        pipe=Mock();model.browser_pipe=pipe;model.browser_pipe_process=old
        model.reap_window_launcher()
        self.assertIsNone(model.browser_pipe)
        with patch.object(runtime.os,'killpg') as signal:
            with self.assertRaisesRegex(runtime.BrowserUnavailable,'Owned browser close is unavailable'):
                model.stop_profile()
            signal.assert_not_called()
        self.assertFalse(model.stopping);self.assertIn(('Chromium',launcher),model.children)

    def test_worker_child_environment_does_not_leak_manager_authority(self):
        model=self.model()
        with patch.object(runtime,'PROFILE_ID','default'),patch.dict(os.environ,{
            'AUTH_BROWSER_PROFILE_CONTROL_TOKEN':'a'*64,'AUTH_BROWSER_PROFILE_CONTROL_PATH':'/private/control',
            'AUTH_BROWSER_PROFILE_WORKER_FD':'77','AUTH_BROWSER_PROXY_SOCKET':'/profile/webauthn.sock',
            'DISPLAY':':105'}),patch.object(runtime.subprocess,'Popen') as launch:
            model.spawn('Openbox',['openbox'])
            env=launch.call_args.kwargs['env']
            self.assertEqual(env['DISPLAY'],':105')
            self.assertEqual(env['AUTH_BROWSER_PROXY_SOCKET'],'/profile/webauthn.sock')
            for key in ('AUTH_BROWSER_PROFILE_CONTROL_TOKEN','AUTH_BROWSER_PROFILE_CONTROL_PATH','AUTH_BROWSER_PROFILE_WORKER_FD'):
                self.assertNotIn(key,env)
    def test_profile_environment_selects_all_module_paths_in_a_fresh_process(self):
        profile='12345678-1234-4234-8234-123456789abc'
        paths=runtime._profile_modules['profile_context'].ProfilePaths(profile,7)
        script='''import importlib.util,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('probe',p/'supervisor.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
s._fido_control.FidoController.from_environment=lambda:None
model=s.Supervisor()
print(json.dumps(dict(profile=str(s.PROFILE_PATH),run=str(s.RUN_PATH),cache=str(s.CACHE_PATH),display=s.DISPLAY,port=s.VNC_PORT,command=model.browser_command())))
'''
        result=subprocess.run([sys.executable,'-c',script,str(ROOT/'runtime')],env=paths.environment(os.environ),capture_output=True,text=True,check=True,timeout=5)
        value=json.loads(result.stdout)
        self.assertEqual(value['run'],str(paths.runtime));self.assertEqual(value['profile'],str(paths.profile))
        self.assertEqual(value['cache'],str(paths.cache));self.assertEqual(value['display'],':106')
        self.assertEqual(value['port'],5907)
        self.assertIn(f'--user-data-dir={paths.profile}',value['command'])
        self.assertIn(f'--disk-cache-dir={paths.cache}/chromium',value['command'])
    def test_stack_uses_reserved_backing_size_then_initializes_before_clients(self):
        model=self.model();model.spawn=Mock();model.wait_ready=Mock();model.start_browser=Mock()
        events=[]
        model.spawn.side_effect=lambda name,command:events.append((name,command))
        with patch.object(runtime,'PROFILE_ID','default'),patch.object(runtime,'DISPLAY',':104'),patch.object(runtime,'VNC_PORT',5905),patch.object(runtime,'prepare_x_socket_dir'),patch.object(runtime._profile_modules['display_size'],'initialize',side_effect=lambda *a,**k:events.append(('initialize',[]))):
            model.start_desktop(wait_engine=False)
        names=[name for name,_ in events]
        self.assertLess(names.index('Xvfb'),names.index('initialize'))
        self.assertLess(names.index('initialize'),names.index('Openbox'))
        xvfb=dict(events)['Xvfb'];vnc=dict(events)['x11vnc']
        self.assertIn('3840x2160x24',xvfb);self.assertIn('-noreset',xvfb)
        self.assertIn(':104',vnc);self.assertIn('5905',vnc);self.assertIn('-xrandr',vnc)
        self.assertEqual(model.wait_ready.call_args.args[1],model.browser_ready)
    def test_readiness_uses_exact_profile_private_token_and_retains_upgrade_recovery(self):
        model=self.model();model.profile_gateway_token='a'*64
        model.request_extension_upgrade=Mock();model.extension_upgrade_readiness=Mock(return_value=False)
        response=io.StringIO(json.dumps({'engine_connected':False,'control_connected':True,
                                        'native_qr_mode':False,'mode_error':'extension_upgrade_required'}))
        model.opener.open=Mock(return_value=response)
        with patch.object(runtime,'PROFILE_ID','default'):
            self.assertFalse(model.proxy_ready())
        request=model.opener.open.call_args.args[0]
        self.assertEqual(request.full_url,'http://127.0.0.1:8080/api/runtime/profiles/default/engine')
        self.assertEqual(request.get_header('X-profile-control-token'),'a'*64)
        model.request_extension_upgrade.assert_called_once()
        model.extension_upgrade_readiness.assert_called_once_with(False)
    def test_missing_gateway_capability_does_not_fall_back_to_global_status(self):
        model=self.model();model.opener.open=Mock()
        with patch.object(runtime,'PROFILE_ID','default'):
            self.assertFalse(model.proxy_ready())
        model.opener.open.assert_not_called()

    def test_lazy_start_becomes_ready_only_after_profile_engine_ack(self):
        model=self.model();model.profile_engine_pending=True
        model.proxy_ready=Mock(side_effect=[False,True,True]);model.write_status=Mock()
        for expected_calls in (0,1,1):
            model.browser_probe_at=0;model.maintain_browser()
            self.assertEqual(model.write_status.call_count,expected_calls)
        self.assertFalse(model.profile_engine_pending)
        self.assertEqual(model.write_status.call_args.args[0],'ready')

    def test_idle_healthcheck_has_no_fixed_slot_vnc_probe(self):
        source=(ROOT/'runtime/healthcheck.py').read_text()
        self.assertIn('/readyz',source);self.assertNotIn('5900',source)
        self.assertNotIn('socket.create_connection',source)


class SiblingFidoTests(unittest.TestCase):
    def test_two_profile_control_scopes_do_not_cross_and_one_revoke_leaves_other_ready(self):
        fido=runtime._fido_control
        controllers=[];ends=[]
        try:
            for _ in range(2):
                ctrl=fido.FidoController(allow_simulation=True);controllers.append(ctrl)
                _,gateway=ctrl.prepare_child('gateway');ends.append(gateway)
                ctrl.channel_started('gateway')
                _,browser=ctrl.prepare_child('browser');ends.append(browser)
                ctrl.child_started('browser',Mock(poll=Mock(return_value=None)))
                gateway.settimeout(1);browser.settimeout(1)
                hello,fd=fido.receive_frame(browser,True);self.assertIsNone(fd)
                other,fd=fido.receive_frame(gateway,True);self.assertEqual(hello,other);self.assertIsNone(fd)
                ready=fido.replace(hello,op=fido.Op.READY,flags=129)
                fido.send_frame(browser,ready,allow_simulation=True);ctrl.tick()
                received,_=fido.receive_frame(gateway,True);self.assertEqual(received,ready)
            self.assertNotEqual(controllers[0].scope,controllers[1].scope)
            controllers[0].retire('gateway')
            self.assertFalse(controllers[0].ready);self.assertTrue(controllers[1].ready)
            replacement,endpoint=controllers[0].prepare_child('gateway');ends.append(endpoint)
            controllers[0].channel_started('gateway')
            self.assertNotEqual(controllers[0].scope,controllers[1].scope)
        finally:
            for ctrl in controllers:ctrl.close()
            for endpoint in ends:endpoint.close()


if __name__=='__main__':unittest.main()
