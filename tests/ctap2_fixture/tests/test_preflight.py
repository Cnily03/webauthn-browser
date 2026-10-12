"""All environment/runtime probes are mocked; no Chromium or real monitor retry."""
import errno
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import preflight
from runner_resources import Resources
import future_browser_acceptance as runner

def image(path,kind=3,machine=62,execute=True):
    header=bytearray(64);header[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI',header,16,kind,machine,1)
    extra=b''
    if kind==2:
        interpreter=b'/lib64/ld-linux-x86-64.so.2\0'
        struct.pack_into('<Q',header,32,64);struct.pack_into('<HH',header,54,56,1)
        program=struct.pack('<IIQQQQQQ',3,4,120,0,0,len(interpreter),len(interpreter),1)
        extra=program+interpreter
    path.write_bytes(header+extra);path.chmod(0o755 if execute else 0o644)
    return path

class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fixture-preflight-test-')
        self.root=pathlib.Path(self.temp.name)
        self.browser=image(self.root/'browser',kind=2)
        self.hook=image(self.root/'hook.so')
        self.monitor=mock.Mock();self.loader=mock.Mock()
        self.platform=mock.patch.multiple(preflight.platform,system=lambda:'Linux',machine=lambda:'x86_64')
        self.platform.start()
        self.env=mock.patch.dict(os.environ,{},clear=True);self.env.start()
    def tearDown(self):
        self.env.stop();self.platform.stop();self.temp.cleanup()
    def check(self,browser=None,hook=None,exports=None):
        return preflight.preflight(browser or self.browser,hook or self.hook,
            exports_check=lambda _:preflight.REQUIRED_EXPORTS if exports is None else exports,
            monitor_check=self.monitor,load_check=self.loader)
    def test_valid_files_complete_all_preflight_checks(self):
        self.assertEqual(self.check(),(self.browser,self.hook))
        self.monitor.assert_called_once_with();self.loader.assert_called_once_with(self.hook)
    def test_missing_invalid_nonregular_symlink_unreadable_files_fail_before_probes(self):
        cases=[]
        bad=self.root/'text';bad.write_text('not ELF');bad.chmod(0o755);cases.append((bad,self.hook))
        cases.append((self.root/'missing',self.hook));cases.append((self.browser,self.root/'missing-hook'))
        directory=self.root/'directory';directory.mkdir();cases.append((directory,self.hook))
        link=self.root/'link';link.symlink_to(self.hook);cases.append((self.browser,link))
        fifo=self.root/'fifo';os.mkfifo(fifo);cases.append((self.browser,fifo))
        noexec=image(self.root/'not-executable',execute=False);cases.append((noexec,self.hook))
        wrong_arch=image(self.root/'arm-hook',machine=183);cases.append((self.browser,wrong_arch))
        executable_hook=image(self.root/'exec-hook',kind=2);cases.append((self.browser,executable_hook))
        for browser,hook in cases:
            with self.subTest(browser=browser.name,hook=hook.name):
                with self.assertRaises(preflight.PreflightError):self.check(browser,hook)
        with mock.patch.object(preflight.os,'open',side_effect=PermissionError(errno.EACCES,'denied')):
            with self.assertRaises(preflight.PreflightError):self.check()
        self.monitor.assert_not_called();self.loader.assert_not_called()
    def test_missing_hook_abi_and_unsupported_platform_fail_closed(self):
        with self.assertRaisesRegex(preflight.PreflightError,'exported ABI'):self.check(exports={'open'})
        self.monitor.assert_not_called()
        with mock.patch.object(preflight.platform,'machine',return_value='aarch64'):
            with self.assertRaisesRegex(preflight.PreflightError,'Linux x86-64'):self.check()
        with mock.patch.dict(os.environ,{'LD_PRELOAD':'unrelated.so'}):
            with self.assertRaisesRegex(preflight.PreflightError,'inherited'):self.check()
        self.loader.assert_not_called()
    def test_denied_monitor_and_failed_loader_never_continue(self):
        self.monitor.side_effect=preflight.PreflightError('errno=1 EPERM')
        with self.assertRaisesRegex(preflight.PreflightError,'EPERM'):self.check()
        self.loader.assert_not_called()
        self.monitor.side_effect=None
        self.loader.side_effect=preflight.PreflightError('missing dependency')
        with self.assertRaisesRegex(preflight.PreflightError,'dependency'):self.check()
    def test_static_or_privileged_browser_cannot_silently_ignore_preload(self):
        static=image(self.root/'static-browser',kind=3)
        with self.assertRaisesRegex(preflight.PreflightError,'program-header'):self.check(browser=static)
        self.browser.chmod(0o4755)
        with self.assertRaisesRegex(preflight.PreflightError,'Privileged'):self.check()
        self.browser.chmod(0o755)
        with mock.patch.object(preflight.os,'getxattr',return_value=b'capability'):
            with self.assertRaisesRegex(preflight.PreflightError,'capabilities'):self.check()
        self.monitor.assert_not_called();self.loader.assert_not_called()
    def test_dynamic_exports_parse_only_defined_public_functions(self):
        output='''Symbol table '.dynsym' contains 5 entries:
 1: 000000001 10 FUNC GLOBAL DEFAULT 15 open
 2: 000000002 10 FUNC WEAK DEFAULT 15 read@@ABI_1
 3: 000000000 0 FUNC GLOBAL DEFAULT UND write
 4: 000000004 10 FUNC GLOBAL HIDDEN 15 close
 5: 000000005 10 OBJECT GLOBAL DEFAULT 15 ioctl
'''
        with mock.patch.object(preflight.shutil,'which',return_value='/usr/bin/readelf'),mock.patch.object(preflight.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,'')):
            self.assertEqual(preflight.dynamic_exports(self.hook),{'open','read'})
        with mock.patch.object(preflight.shutil,'which',return_value=None):
            with self.assertRaises(preflight.PreflightError):preflight.dynamic_exports(self.hook)
    def test_hook_loader_probe_isolated_and_failure_is_not_ignored(self):
        with mock.patch.object(preflight.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'hook-load-ok\n','')) as execute:
            preflight.probe_hook_load(self.hook)
            args=execute.call_args
            self.assertEqual(args.args[0][1],'-I');self.assertNotIn('LD_PRELOAD',args.kwargs['env'])
            self.assertNotIn('UHF_ENABLE',args.kwargs['env']);self.assertEqual(args.kwargs['timeout'],5)
            self.assertNotIn(str(self.browser),args.args[0])
        with mock.patch.object(preflight.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','missing dependency')):
            with self.assertRaisesRegex(preflight.PreflightError,'could not load'):preflight.probe_hook_load(self.hook)
    def test_runner_preflight_failure_allocates_nothing(self):
        # Only mocked preflight/error branch is invoked, never the prepared runtime.
        with mock.patch.object(sys,'argv',['runner','--run-in-authorized-environment']),mock.patch.object(runner,'preflight',side_effect=preflight.PreflightError('mock monitor EPERM')),mock.patch.object(runner.http.server,'HTTPServer') as server,mock.patch.object(runner.socket,'socketpair') as pair,mock.patch.object(runner.subprocess,'Popen') as launch:
            with self.assertRaises(SystemExit) as ended:runner.main()
            self.assertEqual(ended.exception.code,2)
            server.assert_not_called();pair.assert_not_called();launch.assert_not_called()
    def test_real_monitor_api_denial_is_mocked_and_context_is_freed(self):
        library=mock.Mock()
        library.udev_new.return_value=123
        library.udev_monitor_new_from_netlink.return_value=None
        with mock.patch.object(preflight.ctypes,'CDLL',return_value=library),mock.patch.object(preflight.ctypes,'get_errno',return_value=errno.EPERM):
            with self.assertRaisesRegex(preflight.PreflightError,'errno=1'):preflight.probe_udev_monitor()
        library.udev_unref.assert_called_once_with(123)
        library.udev_monitor_unref.assert_not_called()
    def test_real_monitor_enable_denial_is_mocked_and_monitor_is_freed(self):
        library=mock.Mock()
        library.udev_new.return_value=123
        library.udev_monitor_new_from_netlink.return_value=456
        library.udev_monitor_enable_receiving.return_value=-1
        with mock.patch.object(preflight.ctypes,'CDLL',return_value=library):
            with self.assertRaises(preflight.PreflightError):preflight.probe_udev_monitor()
        library.udev_monitor_unref.assert_called_once_with(456)
        library.udev_unref.assert_called_once_with(123)

class ResourceCleanupTests(unittest.TestCase):
    def test_failure_before_popen_closes_packet_fd_server_and_unstarted_threads(self):
        resources=Resources()
        resources.server=mock.Mock()
        resources.http_thread=mock.Mock();resources.http_thread.is_alive.return_value=False
        resources.fixture_thread=mock.Mock();resources.fixture_thread.is_alive.return_value=False
        resources.host,resources.peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        resources.relay=os.dup(resources.host.fileno());saved=resources.relay
        try:raise OSError('simulated failure before Popen')
        except OSError:errors=resources.close()
        self.assertEqual(errors,[])
        with self.assertRaises(OSError):os.fstat(saved)
        self.assertEqual(resources.host.fileno(),-1);self.assertEqual(resources.peer.fileno(),-1)
        resources.server.server_close.assert_called_once_with();resources.server.shutdown.assert_not_called()
        resources.http_thread.join.assert_not_called();resources.fixture_thread.join.assert_not_called()
    def test_early_partial_setup_and_cleanup_error_do_not_leak_other_resources(self):
        resources=Resources();resources.server=mock.Mock()
        resources.server.server_close.side_effect=OSError('mock close error')
        resources.host,resources.peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        resources.relay=os.dup(resources.host.fileno());saved=resources.relay
        self.assertEqual(resources.close(),['OSError'])
        with self.assertRaises(OSError):os.fstat(saved)
        self.assertEqual(resources.host.fileno(),-1);self.assertEqual(resources.peer.fileno(),-1)

if __name__=='__main__':unittest.main(verbosity=2)
