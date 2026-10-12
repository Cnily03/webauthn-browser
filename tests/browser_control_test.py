"""Fixed browser lifecycle protocol; owned Python CDP peers, never Chromium/X."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('lifecycle_supervisor',ROOT/'runtime/supervisor.py')
runtime=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(runtime)
REQUEST='12345678-1234-4321-8765-123456789abc'

class BrowserControlTests(unittest.TestCase):
    def model(self, running=True, windows=None):
        with patch.object(runtime._fido_control.FidoController,'from_environment',return_value=None):
            model=runtime.Supervisor()
        child=Mock(poll=Mock(return_value=None if running else 0))
        model.children=[('Chromium',child)]
        model.check_children=Mock()
        model.display_ready=Mock(return_value=True);model.vnc_ready=Mock(return_value=True)
        model.browser_windows=Mock(return_value=['0x4000007'] if windows is None else windows)
        model.restore_browser=Mock();model.write_status=Mock();model.proxy_ready=Mock(return_value=True)
        model.start_browser=Mock();model.wait_ready=Mock()
        return model,child
    def message(self, model, command, **extra):
        return dict(command=command,request_id=REQUEST,expected_epoch=model.browser_epoch,remaining_ms=1000,**extra)
    def test_request_liveness_is_nonblocking_and_rejects_hup_or_extra_data(self):
        reader,writer=os.pipe()
        connection=Mock(fileno=Mock(return_value=reader))
        try:
            started=time.monotonic()
            self.assertTrue(runtime.control_request_live(connection))
            self.assertLess(time.monotonic()-started,.1)
            os.write(writer,b'unexpected')
            self.assertFalse(runtime.control_request_live(connection))
            os.read(reader,10);os.close(writer);writer=None
            self.assertFalse(runtime.control_request_live(connection))
        finally:
            os.close(reader)
            if writer is not None:os.close(writer)

    def test_inspect_is_read_only(self):
        model,child=self.model();result=model.browser_control(self.message(model,'inspect'))
        self.assertEqual(result['window_count'],1);self.assertTrue(result['process_running'])
        model.start_browser.assert_not_called();model.restore_browser.assert_not_called();model.proxy_ready.assert_not_called()
    def test_ensure_keeps_live_browser_even_when_window_not_yet_created(self):
        for windows in ([],['0x4000007']):
            model,_=self.model(windows=windows);result=model.browser_control(self.message(model,'ensure'))
            self.assertFalse(result['restarted']);model.start_browser.assert_not_called()
    def test_ensure_closed_starts_same_profile_session_only_once(self):
        model,_=self.model(running=False,windows=[])
        def start(**kwargs):
            model.children=[('Chromium',Mock(poll=Mock(return_value=None)))];model.browser_windows.return_value=['0x4000007']
        model.start_browser.side_effect=start
        self.assertTrue(model.browser_control(self.message(model,'ensure'))['restarted'])
        self.assertFalse(model.browser_control(self.message(model,'ensure'))['restarted'])
        model.start_browser.assert_called_once_with(restore_session=True)
    def test_stale_epoch_and_expired_budget_never_mutate(self):
        model,_=self.model();message=self.message(model,'restart');message['expected_epoch']='stale'
        with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(message)
        model.check_children.assert_not_called()
        model.browser_windows.side_effect=lambda:(time.sleep(.01) or ['0x4000007'])
        message=self.message(model,'restart');message['remaining_ms']=1
        with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(message)
        model.start_browser.assert_not_called()
    def test_restart_unowned_or_multiple_window_owner_never_closes(self):
        for count,owned in ((1,False),(2,True)):
            model,child=self.model(windows=['0x4000007']*count);pipe=Mock();model.browser_pipe=pipe
            model.browser_pipe_process=child if owned else Mock()
            with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(self.message(model,'restart'))
            pipe.close_browser.assert_not_called();model.start_browser.assert_not_called()
    def test_restart_rejects_live_auxiliary_launcher_before_close_or_cap_retirement(self):
        model,child=self.model();pipe=Mock();model.browser_pipe=pipe;model.browser_pipe_process=child
        model.fido_control=Mock();model.children.append(('Chromium window launcher',Mock(poll=Mock(return_value=None))))
        with self.assertRaisesRegex(runtime.BrowserUnavailable,'launcher'):
            model.browser_control(self.message(model,'restart'))
        pipe.close_browser.assert_not_called();model.fido_control.retire.assert_not_called();model.start_browser.assert_not_called()
        self.assertEqual(model.browser_operations,{})
    def test_ensure_still_preserves_browser_with_live_auxiliary_launcher(self):
        model,child=self.model();model.children.append(('Chromium window launcher',Mock(poll=Mock(return_value=None))))
        result=model.browser_control(self.message(model,'ensure'))
        self.assertTrue(result['ok']);self.assertEqual(result['window_count'],1);model.start_browser.assert_not_called()

    def test_close_timeout_is_bounded_retains_owner_and_never_retries_same_action(self):
        model,child=self.model();pipe=Mock(close_browser=Mock(side_effect=runtime._browser_cdp.BrowserPipeError('timed out')))
        model.browser_pipe=pipe;model.browser_pipe_process=child
        message=self.message(model,'restart');message['remaining_ms']=100
        with patch.object(runtime.os,'killpg') as kill:
            started=time.monotonic()
            with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(message)
            self.assertLess(time.monotonic()-started,.5)
            with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(message)
            kill.assert_not_called()
        pipe.close_browser.assert_called_once();pipe.dispose_after_exit.assert_not_called();model.start_browser.assert_not_called()
    def test_unclean_exit_during_close_is_not_a_successful_restart(self):
        model,child=self.model();child.wait.return_value=-11
        def close(**kwargs):child.poll.return_value=-11
        pipe=Mock(close_browser=Mock(side_effect=close));model.browser_pipe=pipe;model.browser_pipe_process=child
        with self.assertRaisesRegex(runtime.BrowserUnavailable,'not clean'):
            model.browser_control(self.message(model,'restart'))
        model.start_browser.assert_not_called();pipe.dispose_after_exit.assert_called_once()

    def test_owner_disconnect_during_close_prevents_replacement_launch(self):
        model,child=self.model();live=[True]
        def close(**kwargs):
            live[0]=False
            child.poll.return_value=0
        pipe=Mock(close_browser=Mock(side_effect=close));model.browser_pipe=pipe;model.browser_pipe_process=child
        with patch.object(runtime.os,'killpg') as kill:
            with self.assertRaisesRegex(runtime.BrowserUnavailable,'canceled'):
                model.browser_control(self.message(model,'restart'),lambda:live[0])
            kill.assert_not_called()
        pipe.close_browser.assert_called_once();model.start_browser.assert_not_called()

    def test_maximize_rechecks_single_window_and_reports_engine_separately(self):
        for ready in (False,True):
            model,_=self.model();model.proxy_ready.return_value=ready
            result=model.browser_control(self.message(model,'maximize'))
            self.assertEqual(result['engine_ready'],ready);model.restore_browser.assert_called_once()
            self.assertEqual(model.write_status.call_args.args[0],'ready' if ready else 'recovering')
        model,_=self.model();model.browser_windows.side_effect=[['0x1'],['0x1','0x2']]
        with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(self.message(model,'maximize'))
    def test_maximize_checks_request_liveness_between_window_mutations(self):
        model,_=self.model();model.restore_browser=runtime.Supervisor.restore_browser.__get__(model)
        live=[True];mutations=[]
        def run(command,**kwargs):
            mutations.append(command);live[0]=False;return Mock()
        with patch.object(runtime.subprocess,'run',side_effect=run):
            with self.assertRaisesRegex(runtime.BrowserUnavailable,'canceled'):
                model.browser_control(self.message(model,'maximize'),lambda:live[0])
        self.assertEqual(len(mutations),1)
        self.assertEqual(mutations[0][-1],'remove,fullscreen')

    def test_protocol_rejects_arbitrary_methods_and_extra_payload(self):
        model,_=self.model()
        for changes in ({'command':'Browser.close'},{'url':'https://example.test/'},{'request_id':'bad'},{'remaining_ms':0},{'remaining_ms':True},{'remaining_ms':25001}):
            message=self.message(model,'restart');message.update(changes)
            with self.assertRaises(ValueError):model.browser_control(message)
        model.start_browser.assert_not_called()
    def test_real_owned_pipe_close_exit_then_fresh_generation_preserves_simulated_tabs(self):
        peer=r'''import os,json,sys,pathlib
path=pathlib.Path(sys.argv[1]);buffer=b''
while True:
 data=os.read(3,4096)
 if not data:break
 buffer+=data
 while b'\0' in buffer:
  packet,buffer=buffer.split(b'\0',1);request=json.loads(packet)
  os.write(4,json.dumps({'id':request['id'],'result':{}}).encode()+b'\0')
  if request['method']=='Browser.close':
   state=json.loads(path.read_text());state['windows']=0;state['saved']=state['tabs'];path.write_text(json.dumps(state));sys.exit(0)
'''
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json';state.write_text(json.dumps({'windows':1,'tabs':['one','two']}))
            command=[sys.executable,'-c',peer,str(state)]
            old,pipe=runtime._browser_cdp.spawn(command,os.environ.copy())
            processes=[(old,pipe)];model,_=self.model();model.children=[('Chromium',old)]
            model.browser_pipe=pipe;model.browser_pipe_process=old
            model.browser_windows=lambda:['0x4000007']*json.loads(state.read_text())['windows']
            fido=Mock();model.fido_control=fido
            initial_epoch=model.browser_epoch
            def start(**kwargs):
                self.assertIsNotNone(old.poll());self.assertEqual(kwargs,{'restore_session':True})
                fido.retire.assert_called_with('browser')
                saved=json.loads(state.read_text());self.assertEqual(saved['saved'],['one','two']);saved['windows']=1;state.write_text(json.dumps(saved))
                child,new_pipe=runtime._browser_cdp.spawn(command,os.environ.copy());processes.append((child,new_pipe))
                model.children=[('Chromium',child)];model.browser_pipe=new_pipe;model.browser_pipe_process=child;model.browser_epoch='fresh_epoch'
            model.start_browser.side_effect=start
            try:
                with patch.object(runtime.os,'killpg') as kill:
                    result=model.browser_control(self.message(model,'restart'))
                    self.assertTrue(result['restarted']);self.assertNotEqual(result['browser_epoch'],initial_epoch)
                    self.assertNotEqual(old.pid,model.children[0][1].pid);self.assertEqual(result['window_count'],1)
                    self.assertEqual(json.loads(state.read_text())['tabs'],['one','two']);kill.assert_not_called()
                stale=self.message(model,'restart');stale['expected_epoch']=initial_epoch
                with self.assertRaises(runtime.BrowserUnavailable):model.browser_control(stale)
                model.start_browser.assert_called_once()
            finally:
                for child,controller in processes:
                    if child.poll() is None:child.terminate();child.wait(timeout=3)
                    controller.dispose_after_exit()

if __name__=='__main__':unittest.main()
