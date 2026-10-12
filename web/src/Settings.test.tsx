import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Settings from './Settings';
import { setCsrfToken } from './api';
import type { AppStatus, VirtualKey } from './types';
import { renderMaterial } from './test-render';

type Call = { path: string; method: string; body: Record<string, unknown> };
let calls: Call[];
let keys: VirtualKey[];
let status: AppStatus;
let heldPatch: Promise<void> | undefined;
const notify = vi.fn();
const unauthorized = vi.fn();
const refresh = vi.fn(async () => ({ ...status }));
const makeKey = (id: string, name: string): VirtualKey => ({ id, name, provider_label: 'Local provider', enabled: true, attachment: 'platform', presence_timeout_seconds: 120, model_aaguid: '01234567-89ab-cdef-0123-456789abcdef', resident_key_supported: true, attestation_mode: 'none', credentials: [] });

beforeEach(() => {
  calls = [];
  heldPatch = undefined;
  keys = [makeKey('key-a', '<img src=x> Daily'), { ...makeKey('key-b', 'Backup key'), attachment: 'cross-platform' }];
  status = { csrf_token: 'test-csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: false, settings_password_enabled: false };
  setCsrfToken(status.csrf_token);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const method = init?.method || 'GET';
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ path, method, body });
    expect(init?.credentials).toBe('same-origin');
    expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe('test-csrf');
    if (method !== 'GET') expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json');
    let data: unknown = { ok: true };
    if (path === '/api/security' && method === 'GET') data = { vnc_password_enabled: status.vnc_password_enabled, settings_password_enabled: status.settings_password_enabled };
    else if (path === '/api/keys' && method === 'GET') data = { keys: structuredClone(keys) };
    else if (path === '/api/keys' && method === 'POST') {
      const key = { ...body, id: 'new-key', credentials: [] } as VirtualKey;
      keys.push(key); data = { key };
    } else if (path.startsWith('/api/keys/') && method === 'PATCH') {
      if (heldPatch) await heldPatch;
      Object.assign(keys.find(key => key.id === decodeURIComponent(path.split('/')[3]))!, body);
    } else if (path.endsWith('/credentials') && method === 'DELETE') {
      const key = keys.find(key => key.id === decodeURIComponent(path.split('/')[3]))!;
      key.credentials = key.credentials.filter(credential => credential.credential_id !== body.credential_id);
    } else if (path.startsWith('/api/keys/') && method === 'DELETE') keys = keys.filter(key => key.id !== decodeURIComponent(path.split('/')[3]));
    else if (path === '/api/security' && method === 'PUT') {
      status[`${body.scope as 'settings' | 'vnc'}_password_enabled`] = body.password !== null;
    }
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
  }));
});
async function mount(section = 'authenticator') {
  window.history.replaceState({}, '', `/settings#${section}`);
  const rendered = renderMaterial(<Settings status={status} refreshStatus={refresh} onUnauthorized={unauthorized} notify={notify} />);
  await waitFor(() => expect(screen.queryByText('正在读取设置…')).not.toBeInTheDocument());
  return rendered;
}
async function select(label: string, option: RegExp) {
  await userEvent.click(screen.getByRole('combobox', { name: label }));
  await userEvent.click(await screen.findByRole('option', { name: option }));
}
const chosen = () => document.querySelectorAll('.keys-list [aria-pressed="true"]');

describe('Material UI settings integration', () => {
  it.each([
    {control_connected: true, native_qr_mode: true, mode_switching: false},
    {control_connected: false, native_qr_mode: true, mode_switching: false},
    {control_connected: true, native_qr_mode: false, mode_switching: false},
    {control_connected: true, native_qr_mode: true, mode_switching: true},
  ])('keeps global engine and desktop status out of authenticator settings: %j', async engineStatus => {
    Object.assign(status, {engine_connected: false, engine_message: 'backend status detail', ...engineStatus});
    await mount();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/原生验证模式|验证模式切换中|验证引擎连接已断开|虚拟验证器未就绪|桌面运行状态/)).not.toBeInTheDocument();
    expect(screen.queryByText('backend status detail')).not.toBeInTheDocument();
    expect(calls.some(call => call.path === '/api/runtime')).toBe(false);
    expect(screen.getByRole('button', { name: '编辑设置' })).toBeEnabled();
    expect(screen.getByRole('switch', { name: '启用验证器' })).toBeChecked();
  });

  it('omits the security information panel while preserving password controls and disable confirmation', async () => {
    Object.assign(status, {vnc_password_enabled: true, settings_password_enabled: true});
    const { container } = await mount('security');
    expect(container.querySelector('.security-footnote')).toBeNull();
    expect(screen.queryByText(/关闭密码时，能访问页面/)).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    const cards = container.querySelectorAll('.security-card');
    expect(cards).toHaveLength(2);
    expect(within(cards[0] as HTMLElement).getByRole('heading', { name: '浏览器访问密码' })).toBeVisible();
    expect(within(cards[1] as HTMLElement).getByRole('heading', { name: '设置管理密码' })).toBeVisible();
    for (const card of cards) expect(within(card as HTMLElement).getByRole('button', { name: '更改密码' })).toBeEnabled();
    const browserCard = within(cards[0] as HTMLElement);
    await userEvent.click(browserCard.getByRole('button', { name: '停用密码' }));
    let dialog = await screen.findByRole('dialog', { name: '停用浏览器访问密码？' });
    expect(dialog).toHaveTextContent('可以访问此服务的人将无需该密码即可进入。此操作只影响对应范围。');
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
    await userEvent.click(browserCard.getByRole('button', { name: '停用密码' }));
    dialog = await screen.findByRole('dialog', { name: '停用浏览器访问密码？' });
    await userEvent.click(within(dialog).getByRole('button', { name: '停用密码' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(calls.filter(call => call.method !== 'GET')).toEqual([{ path: '/api/security', method: 'PUT', body: {scope: 'vnc', password: null} }]);
    expect(refresh).toHaveBeenCalledOnce();
    expect(browserCard.getByText('未设置')).toBeVisible();
    expect(within(cards[1] as HTMLElement).getByText('已启用')).toBeVisible();
  });

  it.each(['authenticator', 'keys'])('opens the authenticator section from #%s and emits only the canonical link', async hash => {
    await mount(hash);
    const link = screen.getByRole('link', { name: '验证器管理' });
    expect(link).toHaveAttribute('href', '#authenticator');
    expect(link).toHaveAttribute('aria-current', 'page');
    expect(document.getElementById('authenticator')).toBeVisible();
    expect(document.getElementById('keys')).toBeNull();
    await userEvent.click(screen.getByRole('link', { name: '安全设置' }));
    expect(window.location.hash).toBe('#security');
    await userEvent.click(link);
    expect(window.location.hash).toBe('#authenticator');
    expect(document.getElementById('authenticator')).toBeVisible();
  });

  it('uses security for an unknown anchor and handles a legacy history entry without mutations', async () => {
    await mount('unknown');
    expect(screen.getByRole('heading', { name: '安全设置' })).toBeVisible();
    await act(async () => { window.location.hash = '#keys'; window.dispatchEvent(new HashChangeEvent('hashchange')); });
    expect(document.getElementById('authenticator')).toBeVisible();
    expect(screen.getByRole('link', { name: '验证器管理' })).toHaveAttribute('aria-current', 'page');
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
  });

  it('places type icons beside names and text-only badges at the right in both headers', async () => {
    const { container } = await mount();
    for (const header of container.querySelectorAll('.key-header')) {
      const name = header.querySelector('.key-name') as HTMLElement;
      const badges = header.querySelector('.key-badges') as HTMLElement;
      expect(name.querySelector('svg')).not.toBeNull();
      expect(name.querySelector('svg')?.nextElementSibling?.textContent).toMatch(/Daily|Backup key/);
      expect(badges.querySelectorAll('.MuiChip-root')).toHaveLength(2);
      expect(badges.querySelector('svg')).toBeNull();
      expect(badges).toHaveStyle({ marginLeft: 'auto', justifyContent: 'flex-end', flexWrap: 'wrap' });
      expect(header).toHaveStyle({ flexWrap: 'wrap', alignItems: 'flex-start' });
    }
    await userEvent.click(screen.getByRole('button', { name: /Backup key/ }));
    const article = screen.getByRole('article');
    expect(within(article).getByTitle('USB 验证器').closest('.key-name')).not.toBeNull();
    expect(within(article).getByText('USB 密钥').closest('.MuiChip-root')?.querySelector('svg')).toBeNull();
    await userEvent.click(within(article).getByRole('switch'));
    await waitFor(() => expect(within(article).getByText('已停用')).toBeVisible());
    expect(screen.getAllByText('已停用')).toHaveLength(2);
  });

  it('uses bold keys and regular values in identity, edit identity and passkey details', async () => {
    keys[0].credentials = [{ credential_id: 'opaque-id', rp_id: 'example.com', user_name: 'Alice' }];
    const { container } = await mount();
    await userEvent.click(screen.getByRole('button', { name: '验证器身份' }));
    await userEvent.click(screen.getByRole('button', { name: 'RP ID：example.com，用户名：Alice' }));
    const assertWeights = (selector: string) => {
      const grid = container.querySelector(selector)!;
      expect(grid.querySelectorAll('dt').length).toBeGreaterThan(0);
      for (const label of grid.querySelectorAll('dt')) {
        expect(label).toHaveStyle({ display: 'inline', fontWeight: '700' });
        expect(label.textContent).toMatch(/：$/);
      }
      for (const value of grid.querySelectorAll('dd')) expect(value).toHaveStyle({ display: 'inline', fontWeight: '400' });
    };
    assertWeights('.identity-grid');
    assertWeights('.credential-grid');
    await userEvent.click(screen.getByRole('button', { name: '编辑设置' }));
    await userEvent.click(screen.getByRole('button', { name: '验证器身份' }));
    assertWeights('.identity-grid');
  });

  it('uses standard Material accordion surfaces, spacing and named regions for admin details', async () => {
    keys[0].credentials = [{ credential_id: 'first-id', rp_id: 'first.example.com', user_name: 'alice' }, { credential_id: 'second-id', rp_id: 'second.example.com', user_name: 'bob' }];
    keys[0].attestation_certificate = { subject: 'CN=Test Certificate', not_before: '', not_after: '2030-01-01', sha256: 'hash', chain_length: 1, currently_valid: true, registration_usable: true };
    await mount();
    const summaries = ['验证器身份', '证明证书', 'RP ID：first.example.com，用户名：alice', 'RP ID：second.example.com，用户名：bob'].map(name => screen.getByRole('button', { name, expanded: false }));
    for (const summary of summaries) {
      const accordion = summary.closest('.MuiAccordion-root')!;
      expect(accordion).toHaveClass('MuiPaper-elevation1', 'MuiAccordion-gutters');
      expect(summary).toHaveClass('MuiAccordionSummary-gutters');
      expect(summary).toHaveStyle({ minHeight: '48px' });
      const region = document.getElementById(summary.getAttribute('aria-controls')!);
      expect(region).toHaveAttribute('role', 'region');
      expect(region).toHaveAttribute('aria-labelledby', summary.id);
      expect(region).not.toBeVisible();
      expect(region!.querySelector('.MuiAccordionDetails-root')).toBeInTheDocument();
      await userEvent.click(summary);
      expect(summary).toHaveAttribute('aria-expanded', 'true');
      expect(region).toBeVisible();
    }
    const certificate = screen.getByRole('region', { name: '证明证书' });
    expect(within(certificate).getByText('证书主题：')).toHaveStyle({ fontWeight: '700' });
    expect(within(certificate).getByText('CN=Test Certificate')).toHaveStyle({ fontWeight: '400' });
    const first = screen.getByRole('region', { name: 'RP ID：first.example.com，用户名：alice' });
    expect(within(first).getByRole('region', { name: '凭据信息' })).toBeVisible();
    expect(within(first).getByRole('region', { name: '注册记录' })).toBeVisible();
    expect(within(first).getByRole('button', { name: '删除此通行密钥' }).closest('.MuiAccordionActions-root')).not.toBeNull();
    summaries[2].focus();
    await userEvent.keyboard('{Enter}');
    expect(summaries[2]).toHaveAttribute('aria-expanded', 'false');
    expect(summaries[3]).toHaveAttribute('aria-expanded', 'true');
    await userEvent.keyboard(' ');
    expect(summaries[2]).toHaveAttribute('aria-expanded', 'true');
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
  });

  it('renders one selected detail, escapes key names, and edits mutable provider only', async () => {
    const { container } = await mount();
    expect(chosen()).toHaveLength(1);
    expect(container.querySelectorAll('.key-card')).toHaveLength(1);
    expect(screen.getByRole('heading', { name: '<img src=x> Daily' })).toBeVisible();
    expect(container.querySelector('img')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '编辑设置' }));
    const provider = screen.getByRole('textbox', { name: /^Provider/ });
    await userEvent.clear(provider); await userEvent.type(provider, 'New local label');
    expect(screen.queryByRole('textbox', { name: /^AAGUID/ })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '保存验证器设置' }));
    await waitFor(() => expect(screen.queryByRole('textbox', { name: /^Provider/ })).toBeNull());
    expect(calls.find(call => call.method === 'PATCH')?.body).toEqual({ name: '<img src=x> Daily', provider_label: 'New local label', presence_timeout_seconds: 120 });
    expect(screen.getByRole('button', { name: '编辑设置' })).toHaveFocus();
    expect(screen.queryByText(/已显式关闭 Chromium 沙箱/)).not.toBeInTheDocument();
    expect(screen.queryByText('模拟与兼容性')).not.toBeInTheDocument();
  });

  it('shows legacy certificate warnings without opening details', async () => {
    keys[1].attestation_certificate = { subject: 'Synthetic certificate', not_before: '', not_after: '2030-01-01', sha256: 'hash', chain_length: 1, currently_valid: true, registration_usable: false, warning: '证书编码不兼容；已有凭据仍可登录。' };
    await mount();
    await userEvent.click(screen.getByRole('button', { name: /Backup key/ }));
    expect(chosen()).toHaveLength(1);
    expect(screen.getByText('证书编码不兼容；已有凭据仍可登录。')).toBeVisible();
    expect(screen.getByRole('button', { name: '证明证书', expanded: false })).toBeInTheDocument();
  });

  it('guards dirty navigation, keeps one editor, and discards secrets on confirmed section changes', async () => {
    await mount();
    const add = screen.getByRole('button', { name: '添加验证器' });
    await userEvent.click(add); await userEvent.click(add);
    expect(document.querySelectorAll('.key-form')).toHaveLength(1);
    await select('证明方式', /证书证明/); await select('证书来源', /导入证书/);
    const secret = screen.getByRole('textbox', { name: /^签名私钥/ });
    await userEvent.type(secret, 'never keep detached secrets');
    await userEvent.click(screen.getByRole('link', { name: '安全设置' }));
    let dialog = await screen.findByRole('dialog', { name: '放弃尚未保存的更改？' });
    await userEvent.click(within(dialog).getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(secret).toHaveValue('never keep detached secrets');
    await userEvent.click(screen.getByRole('link', { name: '安全设置' }));
    dialog = await screen.findByRole('dialog', { name: '放弃尚未保存的更改？' });
    await userEvent.click(within(dialog).getByRole('button', { name: '放弃更改' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: '安全设置' })).toBeVisible());
    expect(secret).toHaveValue('');
    expect(document.querySelector('.key-form')).toBeNull();
    await userEvent.click(screen.getByRole('link', { name: '验证器管理' }));
    expect(document.querySelector('.key-form')).toBeNull();
    expect(screen.getByRole('heading', { name: '<img src=x> Daily' })).toBeVisible();
    const freshAdd = screen.getByRole('button', { name: '添加验证器' });
    await userEvent.click(freshAdd);
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(freshAdd).toHaveFocus();
  });

  it('guards real fragment Back/Forward without discarding edits on cancellation or replaying mutations', async () => {
    await mount();
    await userEvent.click(screen.getByRole('link', {name: '安全设置'}));
    await userEvent.click(screen.getByRole('link', {name: '验证器管理'}));
    const originalState = window.history.state;
    const originalLength = window.history.length;
    await userEvent.click(screen.getByRole('button', { name: '编辑设置' }));
    const name = screen.getByRole('textbox', { name: /^昵称/ });
    await userEvent.type(name, ' unsaved');
    const traverse = async (distance: number) => {
      await act(async () => {
        const changed = new Promise<void>(resolve => window.addEventListener('popstate', () => resolve(), {once: true}));
        window.history.go(distance); await changed;
      });
    };
    await traverse(-1);
    await waitFor(() => expect(window.location.hash).toBe('#authenticator'));
    let dialog = await screen.findByRole('dialog', { name: '放弃尚未保存的更改？' });
    await userEvent.click(within(dialog).getByRole('button', {name: '取消'}));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(name).toHaveValue('<img src=x> Daily unsaved');
    expect(window.history.length).toBe(originalLength); expect(window.history.state).toEqual(originalState);
    await traverse(-1);
    await waitFor(() => expect(window.location.hash).toBe('#authenticator'));
    dialog = await screen.findByRole('dialog', { name: '放弃尚未保存的更改？' });
    await userEvent.click(within(dialog).getByRole('button', {name: '放弃更改'}));
    await waitFor(() => expect(window.location.hash).toBe('#security'));
    expect(document.querySelector('.key-form')).toBeNull();
    await traverse(1);
    await waitFor(() => expect(screen.getByRole('heading', { name: '<img src=x> Daily' })).toBeVisible());
    expect(window.history.state).toEqual(originalState); expect(window.history.length).toBe(originalLength);
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
  });

  it('clears a confirmed editor when canonical navigation leaves the legacy alias of the same section', async () => {
    await mount('keys');
    await userEvent.click(screen.getByRole('button', {name: '编辑设置'}));
    const name = screen.getByRole('textbox', {name: /^昵称/});
    await userEvent.type(name, ' unsaved');
    await userEvent.click(screen.getByRole('link', {name: '验证器管理'}));
    const dialog = await screen.findByRole('dialog', {name: '放弃尚未保存的更改？'});
    await userEvent.click(within(dialog).getByRole('button', {name: '放弃更改'}));
    await waitFor(() => expect(window.location.hash).toBe('#authenticator'));
    expect(name).not.toBeInTheDocument();
    expect(document.querySelector('.key-form')).toBeNull();
    expect(calls.filter(call => call.method !== 'GET')).toHaveLength(0);
  });

  it('blocks duplicate toggle and selection changes while a mutation is pending', async () => {
    let finish!: () => void;
    heldPatch = new Promise<void>(resolve => { finish = resolve; });
    await mount();
    const toggle = screen.getByRole('switch', { name: '启用验证器' });
    await userEvent.click(toggle); fireEvent.click(toggle);
    expect(toggle).toBeDisabled();
    expect(document.querySelector('.keys-list [aria-pressed="false"]')).toHaveAttribute('aria-disabled', 'true');
    expect(calls.filter(call => call.method === 'PATCH')).toHaveLength(1);
    await act(async () => { finish(); });
    await waitFor(() => expect(screen.getByRole('switch', { name: '启用验证器' })).not.toBeChecked());
    expect(screen.getByRole('heading', { name: '<img src=x> Daily' })).toBeVisible();
  });

  it('requires dialog confirmation before deleting a credential or key', async () => {
    keys[0].credentials = [{ credential_id: 'abc/+==', rp_id: 'example.com', sign_count: 7, user_handle: '测试用户' }];
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'RP ID：example.com，用户名：未记录' }));
    await userEvent.click(screen.getByRole('button', { name: '删除此通行密钥' }));
    let dialog = await screen.findByRole('dialog', { name: '删除此通行密钥？' });
    expect(calls.filter(call => call.method === 'DELETE')).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole('button', { name: '删除此通行密钥' }));
    await waitFor(() => expect(keys[0].credentials).toHaveLength(0));
    expect(calls.find(call => call.path.endsWith('/credentials'))?.body).toEqual({ credential_id: 'abc/+==' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await userEvent.click(screen.getByRole('button', { name: '删除' }));
    dialog = await screen.findByRole('dialog', { name: /删除“/ });
    await userEvent.click(within(dialog).getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(keys).toHaveLength(2);
    await userEvent.click(screen.getByRole('button', { name: '删除' }));
    dialog = await screen.findByRole('dialog', { name: /删除“/ });
    await userEvent.click(within(dialog).getByRole('button', { name: '删除验证器' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Backup key' })).toBeVisible());
    expect(chosen()).toHaveLength(1);
  });

  it.each([' 空白🔑密码𠮷 ', ''])('preserves arbitrary access password %j and clears submitted fields', async password => {
    await mount('security');
    await userEvent.click(screen.getAllByRole('button', { name: '设置密码' })[1]);
    const dialog = await screen.findByRole('dialog', { name: '设置设置管理密码' });
    const first = within(dialog).getByLabelText('新密码');
    const second = within(dialog).getByLabelText('再次输入');
    if (password) { await userEvent.type(first, password); await userEvent.type(second, password); }
    await userEvent.click(within(dialog).getByRole('button', { name: '保存密码' }));
    await waitFor(() => expect(calls.find(call => call.method === 'PUT')?.body).toEqual({ scope: 'settings', password }));
    expect(first).toHaveValue(''); expect(second).toHaveValue('');
  });

  it('shows each passkey summary as RP and username, with independent expandable metadata and copy controls', async () => {
    const credentialId = 'X'.repeat(768) + '+/==';
    keys[0].credentials = [{ credential_id: credentialId, rp_id: 'accounts.example.com', user_name: 'alice@example.com', user_display_name: 'Alice Example', user_handle: 'AAECAwQF+/==', registered_at: 1767225600000, sign_count: 42, resident: true, registration_aaguid: '01234567-89ab-cdef-0123-456789abcdef', registration_attestation: 'packed-self', registration_requested_attestation: 'direct', registration_identity: { providerLabel: 'Historical provider label', modelAaguid: '01234567-89ab-cdef-0123-456789abcdef', attachment: 'platform' } }];
    const copy = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy } });
    await mount();
    expect(screen.getAllByRole('img', { name: '设备验证器' }).length).toBeGreaterThan(0);
    expect(screen.getByRole('img', { name: 'USB 验证器' })).toBeInTheDocument();
    const summary = screen.getByRole('button', { name: 'RP ID：accounts.example.com，用户名：alice@example.com' });
    const credential = summary.closest('.credential') as HTMLElement;
    expect(summary).toHaveAttribute('aria-expanded', 'false');
    const rp = within(summary).getByText('accounts.example.com');
    const username = within(summary).getByText('alice@example.com');
    expect(rp).toHaveStyle({ fontWeight: '700', fontSize: '16px' });
    expect(rp).toHaveClass('MuiTypography-subtitle1');
    expect(username).toHaveClass('MuiTypography-body2');
    expect(username).toHaveStyle({ fontWeight: '400', fontSize: '14px' });
    expect(username).toBeVisible();
    expect(summary).not.toHaveTextContent('用户名');
    expect(within(credential).getByText('Alice Example')).not.toBeVisible();
    expect(within(summary).queryByText('AAECAwQF+/==')).toBeNull();
    await userEvent.click(summary);
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    for (const value of ['Alice Example', 'AAECAwQF+/==', credentialId, '42', '2026-01-01 00:00:00 UTC', 'Historical provider label']) expect(within(credential).getByText(value)).toBeVisible();
    expect(within(credential).getByText('用户 ID（Base64）：')).toBeVisible();
    const deletion = within(credential).getByRole('button', { name: '删除此通行密钥' });
    expect(summary.contains(deletion)).toBe(false);
    await userEvent.click(within(credential).getByRole('button', { name: '复制凭证 ID（Base64）' }));
    expect(copy).toHaveBeenCalledWith(credentialId);
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    expect(calls.filter(call => call.method === 'DELETE')).toHaveLength(0);
    await userEvent.click(summary);
    await waitFor(() => expect(within(credential).getByText('Alice Example')).not.toBeVisible());
  });

  it('marks missing legacy username, display name and registration time unrecorded instead of inferring from opaque handles', async () => {
    keys[0].credentials = [{ credential_id: 'legacy-id', rp_id: 'legacy.example.com', user_handle: 'YWxpY2U=', sign_count: 7, user_name: null, user_display_name: null, registered_at: null }];
    await mount();
    const summary = screen.getByRole('button', { name: 'RP ID：legacy.example.com，用户名：未记录' });
    expect(within(summary).getByText('未记录')).toBeVisible();
    expect(summary).not.toHaveTextContent('用户名');
    expect(within(summary).queryByText('YWxpY2U=')).toBeNull();
    await userEvent.click(summary);
    const detail = summary.closest('.credential') as HTMLElement;
    expect(within(detail).getByText('YWxpY2U=')).toBeVisible();
    for (const label of ['用户名', '显示名称', '注册时间']) {
      const row = within(detail).getByText(`${label}：`).closest('div');
      expect(row?.querySelector('dd')?.textContent).toBe('未记录');
    }
    expect(within(detail).queryByText('alice')).toBeNull();
  });

  it('keeps legacy configured AAGUID distinct from the actual registration and does not invent a counter', async () => {
    const configuredModel = '87654321-abcd-4321-9876-abcdef123456';
    keys[0].credentials = [{ credential_id: 'partial-legacy-id', rp_id: 'partial.example.com', registration_identity: { modelAaguid: configuredModel } }];
    await mount();
    const summary = screen.getByRole('button', { name: 'RP ID：partial.example.com，用户名：未记录' });
    await userEvent.click(summary);
    const detail = summary.closest('.credential') as HTMLElement;
    for (const label of ['注册时 AAGUID', '签名计数', '注册时间']) {
      const row = within(detail).getByText(`${label}：`).closest('div');
      expect(row?.querySelector('dd')?.textContent).toBe('未记录');
    }
    const configuredRow = within(detail).getByText('注册时配置 AAGUID：').closest('div');
    expect(configuredRow?.querySelector('dd')?.textContent).toBe(configuredModel);
  });

  it.each([
    ['none', '不要求 (none)', 'none', '无证明'],
    ['direct', '直接证明 (direct)', 'packed-self', '凭据自签名'],
    ['indirect', '间接证明 (indirect)', 'packed-basic', '证书证明'],
    ['enterprise', '企业证明 (enterprise)', undefined, '未记录'],
    [undefined, '未记录', undefined, '未记录'],
  ])('distinguishes the website proof request %s from the proof actually provided', async (requestMode, requestLabel, proofMode, proofLabel) => {
    keys[0].credentials = [{ credential_id: 'proof-id', rp_id: 'proof.example.com', user_name: 'Alice', registration_requested_attestation: requestMode, registration_attestation: proofMode }];
    await mount();
    const summary = screen.getByRole('button', { name: 'RP ID：proof.example.com，用户名：Alice' });
    await userEvent.click(summary);
    const record = within(summary.closest('.credential') as HTMLElement).getByRole('region', { name: '注册记录' });
    const requested = within(record).getByText('网站要求的注册证明：');
    const provided = within(record).getByText('注册时提供的证明：');
    expect(requested.nextElementSibling).toHaveTextContent(requestLabel!);
    expect(provided.nextElementSibling).toHaveTextContent(proofLabel!);
    expect(record).not.toHaveTextContent('·');
  });

  it('clears access-password DOM nodes on route unmount', async () => {
    const { unmount } = await mount('security');
    await userEvent.click(screen.getAllByRole('button', { name: '设置密码' })[0]);
    const password = await screen.findByLabelText('新密码');
    await userEvent.type(password, 'clear on lock or navigation');
    unmount();
    expect(password).toHaveValue('');
  });
});
