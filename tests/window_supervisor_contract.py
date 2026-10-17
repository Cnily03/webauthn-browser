"""Pipe fixture for the Rust workflow's actual supervisor wire protocol.

Only browser/display services are simulated. Supervisor.browser_control retains
its production schema, epoch, lifecycle and viewport validation. No sockets,
Chromium, X server, manager, network or hardware service is opened.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('window_supervisor_contract', ROOT / 'runtime/supervisor.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
OLD = '0123456789abcdef0123456789abcdef'
NEW = 'abcdef0123456789abcdef0123456789'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--absent', action='store_true')
    parser.add_argument('--viewport', nargs=2, type=int)
    parser.add_argument('--resize-failure', action='store_true')
    parser.add_argument('--control-failure', choices=('inspect', 'maximize'))
    options = parser.parse_args()
    expected = None if options.viewport is None else dict(zip(('width', 'height'), options.viewport))
    with patch.object(runtime._fido_control.FidoController, 'from_environment', return_value=None):
        model = runtime.Supervisor()
    model.browser_epoch = OLD
    windows = [] if options.absent else ['0x4000007']
    browser = Mock(poll=Mock(return_value=None), wait=Mock(return_value=0))
    model.children = [] if options.absent else [('Chromium', browser)]
    model.check_children = Mock()
    model.browser_windows = lambda: list(windows)
    model.display_ready = Mock(return_value=True)
    model.vnc_ready = Mock(return_value=True)
    model.proxy_ready = Mock(return_value=True)
    model.restore_browser = Mock()
    model.write_status = Mock()
    model.wait_ready = Mock()
    model.release_browser_pipe = Mock()
    model.browser_pipe_process = browser

    def close_browser(**_):
        browser.poll.return_value = 0
        windows.clear()

    model.browser_pipe = Mock(close_browser=Mock(side_effect=close_browser))

    def start_browser(**_):
        model.browser_epoch = NEW
        model.children = [('Chromium', Mock(poll=Mock(return_value=None)))]
        windows[:] = ['0x4000008']

    model.start_browser = Mock(side_effect=start_browser)
    if options.control_failure == 'inspect':
        model.browser_windows = Mock(side_effect=OSError('PRIVATE https://secret.invalid/token'))
    elif options.control_failure == 'maximize':
        model.restore_browser = Mock(side_effect=OSError('PRIVATE https://secret.invalid/token'))

    def resize(_, width, height, *, env, check):
        check()
        if options.resize_failure:
            raise runtime._profile_modules['display_size'].DisplaySizeError('synthetic partial resize', 'resize_unconfirmed')
        return {'width': width, 'height': height}

    with patch.object(runtime._profile_modules['display_size'], 'resize', side_effect=resize) as resizing:
        for line in sys.stdin:
            request = json.loads(line)
            before = resizing.call_count
            # This is the production validator and state machine, not a copied
            # list of permitted fields. The old Inspect+viewport bug fails here.
            try:
                reply = model.browser_control(request)
            except Exception as error:
                if options.control_failure is None:
                    raise
                print(json.dumps(runtime.control_failure(request, error)), flush=True)
                continue
            if request['command'] == 'inspect':
                assert 'viewport' not in request
                assert resizing.call_count == before
            else:
                assert request.get('viewport') == expected
                attempted = expected is not None and not (options.resize_failure and before > 0)
                assert resizing.call_count == before + int(attempted)
                if options.resize_failure:
                    assert 'display_width' not in reply and 'display_height' not in reply
                elif expected is not None:
                    assert reply['display_width'] == expected['width']
                    assert reply['display_height'] == expected['height']
            print(json.dumps(reply), flush=True)


if __name__ == '__main__':
    main()
