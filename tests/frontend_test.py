"""Real Chromium tests of the bundled React/MUI UI with a synthetic backend.
Run pnpm --dir web install --frozen-lockfile && pnpm --dir web run build first, then this script.
This does not exercise the production native broker or real noVNC transport.
"""
import json
import mimetypes
import re
import secrets
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parent.parent / "web" / "dist"
state = {"vnc_authenticated": True, "settings_authenticated": True,
         "vnc_password_enabled": False, "settings_password_enabled": False, "csrf_token": "test-csrf"}
keys = []
requests = []
passwords = {}
pending_requests = []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, data, content_type='application/json', status=200):
        nonce = secrets.token_urlsafe(24)
        if content_type == 'text/html': data = data.replace('__CSP_NONCE__', nonce)
        payload = json.dumps(data).encode() if content_type == 'application/json' else data.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-" + nonce +
            "'; style-src-elem 'self' 'nonce-" + nonce + "'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == '/api/status': return self.respond(state)
        if self.path == '/api/requests/events':
            if not state['vnc_authenticated']:
                return self.respond({'error': '请解锁浏览器'}, status=401)
            assert self.headers.get('X-CSRF-Token') == 'test-csrf'
            assert self.headers.get('Accept') == 'text/event-stream'
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            sequence = 0
            previous = None
            try:
                while state['vnc_authenticated']:
                    snapshot = json.dumps(list(pending_requests), ensure_ascii=False)
                    if snapshot != previous:
                        sequence += 1
                        cursor = f'test:{sequence}'
                        data = json.dumps({'requests': json.loads(snapshot), 'connected': True,
                                           'cursor': cursor, 'events': []}, ensure_ascii=False)
                        self.wfile.write(f'id: {cursor}\nevent: snapshot\ndata: {data}\n\n'.encode())
                        self.wfile.flush()
                        previous = snapshot
                    else:
                        self.wfile.write(b': heartbeat\n\n')
                        self.wfile.flush()
                    time.sleep(0.05)
                self.wfile.write(b'event: locked\ndata: {}\n\n')
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if self.path == '/api/browser/mode':
            return self.respond({'mode': 'software', 'state': 'software', 'generation': 1, 'active': False,
                                 'owned': False, 'control_connected': True, 'remaining_ms': 0, 'mode_error': None})
        if self.path == '/api/requests':
            return self.respond({'requests': pending_requests, 'connected': True, 'cursor': 'test:1'}) if state['vnc_authenticated'] else self.respond({'error': '请解锁浏览器'}, status=401)
        if self.path.startswith('/api/') and not state['settings_authenticated']:
            return self.respond({'error': '请解锁设置'}, status=401)
        if self.path == '/api/security': return self.respond({k: v for k, v in state.items() if 'password_enabled' in k})
        if self.path == '/api/runtime': return self.respond({'state': 'ready', 'sandbox_enabled': False})
        if self.path == '/api/keys': return self.respond({'keys': keys})
        if self.path == '/api/backup':
            assert self.headers.get('X-CSRF-Token') == 'test-csrf'
            return self.respond({'version': 1, 'keys': keys})
        if self.path == '/api/targets': return self.respond({'targets': [{'id': 'target-1', 'title': '示例网站', 'url': 'https://example.com', 'selected': True}]})
        if self.path == '/novnc/core/rfb.js':
            return self.respond('export default class RFB extends EventTarget {constructor(el,url){super();window.testWebSocketURL=url;el.append(document.createElement("canvas"));setTimeout(()=>this.dispatchEvent(new Event("connect")),20)} disconnect(){this.dispatchEvent(new Event("disconnect"))}}', 'text/javascript')
        path = urlsplit(self.path).path
        filename = 'index.html' if path in ('/', '/settings', '/settings/') else path.lstrip('/')
        target = (ROOT / filename).resolve()
        if not target.is_relative_to(ROOT.resolve()) or not target.is_file():
            return self.respond({}, status=404)
        content_type = 'text/javascript' if target.suffix == '.js' else mimetypes.guess_type(target.name)[0] or 'application/octet-stream'
        return self.respond(target.read_text(), content_type)

    def mutation(self):
        assert self.headers.get('X-CSRF-Token') == 'test-csrf'
        assert self.headers.get('Content-Type') == 'application/json'
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        requests.append((self.command, self.path, body))
        if self.path.startswith('/api/requests/') and self.path.endswith('/decision'):
            item = next((item for item in pending_requests if item['id'] == self.path.split('/')[3]), None)
            action = body['action']
            if action in ('deny', 'touch'):
                pending_requests[:] = [p for p in pending_requests if p is not item]
            elif item:
                if action == 'select':
                    item.update(selected_key_id=body['key_id'], selected_credential_id=body.get('credential_id'))
                item['stage'] = {'select': 'setup_password', 'setup_password': 'verify_password', 'verify_password': 'touch'}[action]
        elif self.path == '/api/restore/preview':
            return self.respond({'token': 'restore-token', 'key_count': 0, 'credential_count': 0,
                                 'current_key_count': len(keys), 'current_credential_count': 0,
                                 'counters_preserved': 0, 'warnings': []})
        elif self.path == '/api/restore/backup':
            return self.respond({'version': 1, 'keys': keys})
        elif self.path == '/api/restore/confirm':
            assert body['token'] == 'restore-token'
            keys[:] = json.loads(body['backup'])['keys']
        elif self.path == '/api/login':
            scope = body['scope']
            if body['password'] != passwords.get(scope): return self.respond({'error': '密码不正确'}, status=401)
            state[scope + '_authenticated'] = True
        elif self.path == '/api/logout': state[body['scope'] + '_authenticated'] = False
        elif self.path == '/api/security':
            scope = body['scope']
            passwords[scope] = body['password']
            state[scope + '_password_enabled'] = body['password'] is not None
            state[scope + '_authenticated'] = body['password'] is None
        elif self.path == '/api/keys' and self.command == 'POST':
            key = dict(body, id='key-1', credentials=[])
            keys.append(key)
            return self.respond({'key': key})
        elif self.path.startswith('/api/keys/'):
            key_id = self.path.split('/')[3]
            key = next((value for value in keys if value['id'] == key_id), None)
            if self.command == 'PATCH' and key: key.update(body)
            elif self.command == 'DELETE' and self.path.endswith('/credentials') and key:
                key['credentials'] = [c for c in key['credentials'] if c['credential_id'] != body['credential_id']]
            elif self.command == 'DELETE': keys[:] = [value for value in keys if value['id'] != key_id]
        return self.respond({'ok': True})

    do_POST = mutation
    do_PUT = mutation
    do_PATCH = mutation
    do_DELETE = mutation


def select_material(page, label, option):
    page.get_by_role('combobox', name=label, exact=True).click()
    page.get_by_role('option', name=re.compile(option)).click()


def assert_responsive(page, widths=(320, 390, 768, 1440)):
    for width in widths:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'Horizontal overflow at {width}'


def assert_navigation_alignment(page, base):
    for width in (320, 390, 599, 600, 768, 1440):
        page.set_viewport_size({'width': width, 'height': 1000})
        page.goto(base + '/')
        page.get_by_role('button', name='收起导航', exact=True).wait_for()
        before = [page.get_by_role('link', name=name, exact=True).bounding_box()['x'] for name in ('浏览器', '设置')]
        slot = page.locator('.navigation-toggle').bounding_box()
        page.get_by_role('link', name='设置', exact=True).click()
        page.get_by_role('heading', name='安全设置', exact=True).wait_for()
        after = [page.get_by_role('link', name=name, exact=True).bounding_box()['x'] for name in ('浏览器', '设置')]
        assert all(abs(a - b) < .5 for a, b in zip(before, after)), f'Navigation shifted at {width}: {before} -> {after}'
        placeholder = page.locator('.navigation-toggle')
        geometry = placeholder.evaluate('(el) => ({ width: el.getBoundingClientRect().width, visibility: getComputedStyle(el).visibility, display: getComputedStyle(el).display })')
        assert abs(geometry['width'] - slot['width']) < .5
        assert geometry['visibility'] == 'hidden' and geometry['display'] != 'none'
        assert placeholder.is_disabled() and placeholder.get_attribute('tabindex') == '-1'
        assert placeholder.get_attribute('aria-expanded') is None
        assert placeholder.get_attribute('aria-controls') is None
        assert page.locator('#navigation-group').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.get_by_role('link', name='浏览器', exact=True).click()
        page.get_by_role('button', name='收起导航', exact=True).wait_for()
        returned = [page.get_by_role('link', name=name, exact=True).bounding_box()['x'] for name in ('浏览器', '设置')]
        assert all(abs(a - b) < .5 for a, b in zip(before, returned))
    page.set_viewport_size({'width': 1440, 'height': 1000})


def main():
    if not (ROOT / 'index.html').is_file() or not (ROOT / 'assets').is_dir():
        raise RuntimeError('Build the frontend first: pnpm --dir web install --frozen-lockfile && pnpm --dir web run build')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, executable_path=shutil.which('chromium'), chromium_sandbox=True)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.add_init_script("window.cspViolations=[]; document.addEventListener('securitypolicyviolation', e=>window.cspViolations.push(e.violatedDirective));")
            assert_navigation_alignment(page, base)
            page.goto(base + '/settings')
            page.get_by_role('heading', name='安全设置', exact=True).wait_for()
            assert page.locator('.MuiButton-root').count() > 0
            assert page.get_by_text('未设置', exact=True).count() == 2
            assert not page.get_by_role('heading', name='还没有验证器').is_visible()
            page.get_by_role('link', name='验证器管理', exact=True).click()
            assert page.url.endswith('#authenticator')
            assert page.locator('#authenticator').is_visible()
            page.get_by_role('heading', name='还没有验证器', exact=True).wait_for()
            page.go_back()
            page.get_by_role('heading', name='安全设置', exact=True).wait_for()
            page.go_forward()
            page.get_by_role('heading', name='还没有验证器', exact=True).wait_for()

            add = page.locator('.section-heading').get_by_role('button', name='添加验证器', exact=True)
            add.click(); add.click()
            assert page.locator('.key-form').count() == 1
            assert page.evaluate("[...document.querySelectorAll('.form-fieldset .MuiOutlinedInput-notchedOutline > legend')].every(el => getComputedStyle(el).float === 'none' && getComputedStyle(el).width !== getComputedStyle(el.closest('.form-fieldset')).width)")
            assert page.get_by_role('textbox', name=re.compile('^Provider')).get_attribute('placeholder') is None
            assert page.get_by_role('textbox', name=re.compile('^Provider')).input_value() == ''
            assert page.get_by_role('textbox', name=re.compile('^昵称')).get_attribute('placeholder') == '日常登录'
            assert page.get_by_role('textbox', name=re.compile(r'^AAGUID\s*\*?$')).evaluate("el => getComputedStyle(el).fontFamily") == 'monospace'
            assert page.get_by_text('模拟与兼容性', exact=True).count() == 0
            page.get_by_role('button', name='随机生成 AAGUID').click()
            assert re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', page.get_by_role('textbox', name=re.compile('^AAGUID')).input_value())
            page.get_by_role('button', name='重置为全零 AAGUID').click()
            assert page.get_by_role('textbox', name=re.compile('^AAGUID')).input_value() == '00000000-0000-0000-0000-000000000000'
            select_material(page, '证明方式', '证书证明')
            assert page.get_by_role('textbox', name='组织单位（OU）', exact=True).is_disabled()
            assert page.get_by_role('textbox', name='组织单位（OU）', exact=True).input_value() == 'Authenticator Attestation'
            select_material(page, '证书来源', '导入证书')
            page.get_by_role('textbox', name=re.compile('^签名私钥')).fill('discard on cancel')
            page.evaluate("window.oldSecret=document.querySelector('textarea[name=attestation-private-key]')")
            assert_responsive(page)
            page.get_by_role('button', name='取消', exact=True).click()
            assert page.evaluate('window.oldSecret.value') == ''
            assert page.locator('.key-form').count() == 0
            assert add.evaluate('(el)=>el===document.activeElement')

            add.click()
            name = '<img src=x onerror=alert(1)> 测试密钥'
            page.get_by_role('textbox', name=re.compile('^昵称')).fill(name)
            page.get_by_role('textbox', name=re.compile('^Provider')).fill('个人密钥')
            page.get_by_role('textbox', name=re.compile('^AAGUID')).fill(' 0123456789ABCDEF0123456789ABCDEF ')
            page.locator('.key-form').get_by_role('button', name='添加验证器', exact=True).click()
            page.get_by_role('heading', name=name, exact=True).wait_for()
            assert page.locator('.keys-list [aria-pressed=true]').count() == 1
            assert page.locator('.key-card').count() == 1
            assert page.locator('img').count() == 0
            assert page.locator('.key-card .key-name svg').count() == 1
            assert page.locator('.key-card .key-badges .MuiChip-root').count() == 2
            assert page.locator('.key-card .key-badges svg').count() == 0
            for width in (320, 390, 599, 600, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 900})
                header = page.locator('.key-card .key-header').bounding_box()
                badges = page.locator('.key-card .key-badges').bounding_box()
                assert header and badges
                assert abs(header['x'] + header['width'] - badges['x'] - badges['width']) < 2
                assert badges['x'] >= header['x'] - 1
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.get_by_role('button', name='验证器身份', exact=True).click()
            assert page.locator('.identity-grid dt').first.evaluate('el => getComputedStyle(el).fontWeight') == '700'
            assert page.locator('.identity-grid dd').first.evaluate('el => getComputedStyle(el).fontWeight') == '400'
            assert keys[0]['model_aaguid'] == '01234567-89ab-cdef-0123-456789abcdef'
            assert keys[0]['automatic_presence'] is False and keys[0]['simulated_uv'] is False
            assert keys[0]['attestation_mode'] == 'none'
            page.get_by_role('button', name='编辑设置', exact=True).click()
            page.get_by_role('textbox', name=re.compile('^Provider')).fill('已更新本地标签')
            page.get_by_role('spinbutton', name=re.compile('^确认时限')).fill('30')
            page.get_by_role('button', name='保存验证器设置', exact=True).click()
            page.get_by_text('验证器设置已更新。', exact=True).wait_for()
            patch = [body for method, _, body in requests if method == 'PATCH'][-1]
            assert patch == {'name': name, 'provider_label': '已更新本地标签', 'presence_timeout_seconds': 30}

            keys.append({'id': 'key-2', 'name': 'Backup key', 'enabled': True,
                         'attachment': 'cross-platform', 'credentials': [{'credential_id': 'c3ludGhldGlj', 'rp_id': 'example.test', 'user_name': 'misaka'}], 'attestation_mode': 'basic',
                         'attestation_certificate': {'subject': 'Synthetic test certificate', 'registration_usable': False,
                         'warning': '证书编码不兼容；保留旧密钥可继续登录已有凭据。'}})
            page.reload()
            page.get_by_role('button', name=re.compile('Backup key')).click()
            page.get_by_role('heading', name='Backup key', exact=True).wait_for()
            assert page.get_by_text('证书编码不兼容；保留旧密钥可继续登录已有凭据。', exact=True).is_visible()
            assert page.get_by_role('button', name='证明证书', exact=True).get_attribute('aria-expanded') == 'false'
            credential_summary = page.get_by_role('button', name='RP ID：example.test，用户名：misaka', exact=True)
            assert '用户名' not in credential_summary.inner_text()
            rp = credential_summary.get_by_text('example.test', exact=True)
            username = credential_summary.get_by_text('misaka', exact=True)
            assert rp.evaluate('el => getComputedStyle(el).fontWeight') == '700'
            assert username.evaluate('el => getComputedStyle(el).fontWeight') == '400'
            assert rp.evaluate('el => parseFloat(getComputedStyle(el).fontSize)') > username.evaluate('el => parseFloat(getComputedStyle(el).fontSize)')
            credential_summary.click()
            credential_region = page.get_by_role('region', name='RP ID：example.test，用户名：misaka', exact=True)
            assert credential_region.get_by_role('region', name='凭据信息').is_visible()
            assert credential_region.locator('.MuiAccordionActions-root').is_visible()
            for width in (320, 390, 599, 600, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            credential_summary.click()
            page.get_by_role('button', name='编辑设置', exact=True).click()
            page.get_by_role('textbox', name=re.compile('^昵称')).fill('Unsaved')
            add.click()
            discard = page.get_by_role('dialog', name='放弃尚未保存的更改？')
            discard.get_by_role('button', name='取消', exact=True).click()
            assert page.get_by_role('textbox', name=re.compile('^昵称')).input_value() == 'Unsaved'
            page.get_by_role('link', name='安全设置', exact=True).click()
            page.get_by_role('dialog').get_by_role('button', name='放弃更改', exact=True).click()
            page.go_back()
            page.get_by_role('heading', name='Backup key', exact=True).wait_for()
            assert page.locator('.key-form').count() == 0
            assert_responsive(page)

            page.get_by_role('link', name='安全设置', exact=True).click()
            page.get_by_role('button', name='设置密码', exact=True).nth(1).click()
            dialog = page.get_by_role('dialog')
            password = ' 空白🔑密码𠮷 '
            dialog.get_by_label('新密码', exact=True).fill(password)
            dialog.get_by_label('再次输入', exact=True).fill(password)
            dialog.get_by_role('button', name='保存密码', exact=True).click()
            page.get_by_role('heading', name='解锁设置').wait_for()
            assert passwords['settings'] == password
            page.get_by_label('密码', exact=True).fill('wrong')
            page.get_by_role('button', name='解锁', exact=True).click()
            page.get_by_text('密码不正确', exact=True).wait_for()
            page.get_by_label('密码', exact=True).fill(password)
            page.get_by_role('button', name='解锁', exact=True).click()
            page.get_by_role('heading', name='安全设置', exact=True).wait_for()
            page.get_by_role('button', name='更改密码', exact=True).click()
            page.get_by_role('dialog').get_by_role('button', name='保存密码', exact=True).click()
            page.get_by_role('heading', name='解锁设置').wait_for()
            assert passwords['settings'] == ''
            page.get_by_role('button', name='解锁', exact=True).click()
            page.get_by_role('heading', name='安全设置', exact=True).wait_for()

            page.get_by_role('link', name='验证器管理', exact=True).click()
            assert page.url.endswith('#authenticator')
            assert page.locator('#authenticator').is_visible()
            with page.expect_download() as backup:
                page.get_by_role('button', name='下载备份', exact=True).click()
            assert backup.value.suggested_filename == 'webauthn-browser-backup.json'
            page.screenshot(path='/tmp/webauthn-browser-material-settings.png', full_page=True)
            page.goto(base + '/')
            page.get_by_text('浏览器已连接', exact=True).wait_for()
            assert page.evaluate('window.testWebSocketURL').endswith('/ws')
            page.locator('#browser-controls #request-connection[data-state=connected]').wait_for()
            assert page.locator('.request-status #request-connection').count() == 0
            assert page.locator('.topbar .brand').count() == 0
            assert page.locator('.topbar-toolbar > :first-child').get_attribute('aria-expanded') == 'true'
            assert page.locator('.topbar [role=status]').count() == 0
            assert page.locator('#browser-controls [role=status]').count() == 1
            page.get_by_role('button', name='收起导航', exact=True).click()
            assert page.locator('#navigation-group').is_hidden()
            assert page.locator('#browser-controls').is_visible()
            page.get_by_role('button', name='展开导航', exact=True).click()
            assert page.locator('#browser-controls #request-connection').is_visible()
            page.get_by_role('button', name='收起控制栏', exact=True).click()
            assert page.locator('#browser-control-content').is_hidden()
            assert page.locator('#navigation-group').is_visible()
            page.get_by_role('button', name='展开控制栏', exact=True).click()
            assert page.get_by_role('combobox', name='模式', exact=True).is_visible()
            assert page.get_by_role('button', name='收起导航', exact=True).inner_text() == ''
            assert_responsive(page, (320, 390, 500, 768, 1440))
            page.get_by_role('button', name='重新连接', exact=True).click()
            page.get_by_text('浏览器已连接', exact=True).wait_for()
            pending_requests.append({'id': 'request-one', 'stage': 'select_key', 'kind': 'create', 'origin': 'https://example.com', 'rp_id': 'example.com', 'uv': 'required', 'remaining_ms': 60000, 'candidates': [
                {'key_id': 'a', 'key_name': 'Device A', 'attachment': 'platform', 'user_name': 'misaka', 'provider_label': 'Local label', 'model_aaguid': '11111111-2222-3333-4444-555555555555', 'pin_setup': True, 'pin_required': True},
                {'key_id': 'b', 'key_name': 'USB B', 'attachment': 'cross-platform', 'pin_required': True}]})
            dialog = page.get_by_role('dialog')
            dialog.wait_for()
            assert page.locator('#root .MuiDialog-root').count() == 0
            assert dialog.get_by_role('button', name='继续').is_disabled()
            select_material(page, '选择验证器和账户', 'Device A')
            dialog.get_by_role('button', name='继续').click()
            dialog.get_by_role('heading', name='设置验证器密码').wait_for()
            dialog.get_by_label(re.compile('^新验证器密码')).fill('pass123')
            dialog.get_by_label(re.compile('^再次输入验证器密码')).fill('pass123')
            dialog.get_by_role('button', name='保存密码').click()
            dialog.get_by_role('heading', name='输入验证器密码').wait_for()
            assert dialog.get_by_label(re.compile('^验证器密码')).input_value() == ''
            dialog.get_by_label(re.compile('^验证器密码')).fill('pass123')
            dialog.get_by_role('button', name='验证密码').click()
            dialog.get_by_role('heading', name='触摸确认').wait_for()
            details = dialog.get_by_label('当前验证器详情')
            assert details.get_by_text('当前验证器', exact=True).evaluate('el => el.parentElement.textContent') == '当前验证器：Device A'
            assert details.get_by_text('用户名', exact=True).evaluate('el => el.parentElement.textContent') == '用户名：misaka'
            assert details.get_by_text('设备验证器', exact=True).evaluate("el => !!el.closest('.MuiChip-root')")
            for label in ('当前验证器', '用户名', 'Provider', 'AAGUID'):
                field = details.get_by_text(label, exact=True)
                assert field.evaluate('el => getComputedStyle(el).fontWeight') == '700'
                assert field.evaluate('el => getComputedStyle(el.parentElement).fontWeight') == '400'
            assert dialog.get_by_text('RP ID', exact=True).is_visible()
            assert dialog.get_by_text(re.compile('软件模拟验证器|无物理设备或可信厂商证明|网站（RP ID）')).count() == 0
            dialog.get_by_role('button', name='触摸并允许').click()
            dialog.wait_for(state='hidden')
            assert [body['action'] for _, path, body in requests if path.endswith('/decision')][-4:] == ['select', 'setup_password', 'verify_password', 'touch']
            assert page.evaluate("[...document.querySelectorAll('style[data-emotion]')].every(el=>el.nonce===document.querySelector('meta[name=csp-nonce]').content)")
            assert page.evaluate('window.cspViolations') == []
            assert not errors, errors
            page.screenshot(path='/tmp/webauthn-browser-material-toolbar.png', full_page=True)
            browser.close()
    finally:
        server.shutdown()
    print('PASS: real bundled React/MUI browser mock-backend suite: CSP, forms, navigation, passwords, backup, responsive layout, noVNC mock and staged authentication')


if __name__ == '__main__':
    main()
