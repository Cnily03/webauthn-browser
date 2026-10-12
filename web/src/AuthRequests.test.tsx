/// <reference types="node" />
import { StrictMode } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthRequests } from './AuthRequests';
import type { AppStatus } from './types';
import type { PendingRequest, RequestSnapshot } from './requestStream';

class HelperSocket {
  static instances: HelperSocket[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: {data: unknown}) => void) | null = null;
  send = vi.fn(); close = vi.fn();
  constructor(public url: string) { HelperSocket.instances.push(this); }
}
let nextId = 0;
const status: AppStatus = {csrf_token: 'csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: false, settings_password_enabled: false};
const candidate = {key_id: 'key-1', key_name: '日常验证器', attachment: 'platform', credential_id: 'account-1', display_name: 'Alice', attestation_effective: 'none', attestation_aaguid: '11111111-2222-3333-4444-555555555555', remaining_ms: 60000};
const pending = (stage = 'select_key'): PendingRequest => ({id: `request-${++nextId}`, kind: 'create', stage, selected_key_id: candidate.key_id, selected_credential_id: candidate.credential_id, rp_id: 'example.com', origin: 'https://example.com', uv: 'required', candidates: [candidate], remaining_ms: 60000});
const flush = async () => { for (let i = 0; i < 15; i++) await Promise.resolve(); };
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function fixture(initial: PendingRequest, options: {
  decision?: (body: Record<string, unknown>) => Response | Promise<Response>;
  nativeStart?: () => Response | Promise<Response>;
  nativeStatus?: () => Response | Promise<Response>;
  strict?: boolean;
} = {}) {
  HelperSocket.instances = []; vi.stubGlobal('WebSocket', HelperSocket);
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let snapshot: RequestSnapshot = {connected: true, cursor: 'test:1', requests: [initial]};
  const actions: Record<string, unknown>[] = [];
  const starts: unknown[] = []; const finishes: Record<string, unknown>[] = [];
  const notify = vi.fn(); const onUnauthorized = vi.fn();
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/requests/events') return new Response(new ReadableStream<Uint8Array>({start(value) { controller = value; }}), {headers: {'Content-Type': 'text/event-stream'}});
    if (path === '/api/requests') return Response.json(snapshot);
    if (path === '/api/helper/status') return options.nativeStatus ? options.nativeStatus() : Response.json({active: true, session_id: 'session', remaining_ms: 100000, state: 'native'});
    if (path === '/api/helper/refresh') return Response.json({session_id: 'session', token: 'new-pair-token', remaining_ms: 90000});
    if (path === '/api/helper/stop') return Response.json({ok: true});
    if (path === '/api/helper/start') {
      starts.push(JSON.parse(String(init?.body)));
      return options.nativeStart ? options.nativeStart() : Response.json({session_id: 'session', token: 'pair-token', expires_in_ms: 120000, helper_url: 'http://127.0.0.1:10233'});
    }
    if (path.endsWith('/decision')) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      actions.push(body);
      if (options.decision) return options.decision(body);
      snapshot = {...snapshot, requests: []};
      return Response.json({ok: true});
    }
    throw new Error('Unexpected path ' + path);
  });
  vi.stubGlobal('fetch', fetcher);
  const props = {status, refreshStatus: vi.fn(async () => status), onUnauthorized, notify};
  const rendered = render(options.strict ? <StrictMode><AuthRequests {...props} /></StrictMode> : <AuthRequests {...props} />);
  await act(flush);
  const emit = async (next: RequestSnapshot) => {
    snapshot = next;
    await act(async () => { controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: ' + JSON.stringify(next) + '\n\n')); await flush(); });
  };
  await emit(snapshot);
  return {actions, starts, finishes, notify, onUnauthorized, fetcher, rendered, props, emit, controller: () => controller, snapshot: () => snapshot,
    setBackend: (next: RequestSnapshot) => { snapshot = next; }};
}

describe('Material UI authentication ceremony', () => {
  it('requires distinct select, setup, verify and touch actions and clears each password', async () => {
    const item = pending();
    let f: Awaited<ReturnType<typeof fixture>>;
    f = await fixture(item, {decision: body => {
      const stages: Record<string, string> = {select: 'setup_password', setup_password: 'verify_password', verify_password: 'touch'};
      f.setBackend({connected: true, cursor: `test:${f.actions.length + 1}`, requests: body.action === 'touch' ? [] : [{...item, stage: stages[String(body.action)]}]});
      return Response.json({ok: true});
    }});
    expect(screen.getByRole('dialog')).toHaveClass('MuiDialog-paper');
    expect(screen.getByText('RP ID').parentElement).toHaveTextContent('RP ID：example.com');
    expect(screen.getByText('AAGUID').parentElement).toHaveTextContent('AAGUID：11111111');
    fireEvent.click(screen.getByRole('button', {name: '继续'}));
    const setup = await screen.findByLabelText(/新验证器密码/);
    fireEvent.change(setup, {target: {value: '六个不同汉字'}});
    fireEvent.change(screen.getByLabelText(/再次输入验证器密码/), {target: {value: '六个不同汉字'}});
    fireEvent.click(screen.getByRole('button', {name: '保存密码'}));
    expect(setup).toHaveValue('');
    const verify = await screen.findByLabelText(/^验证器密码/);
    expect(verify).toHaveValue('');
    expect(f.actions.map(value => value.action)).toEqual(['select', 'setup_password']);
    fireEvent.change(verify, {target: {value: '六个不同汉字'}});
    fireEvent.click(screen.getByRole('button', {name: '验证密码'}));
    expect(verify).toHaveValue('');
    await screen.findByRole('button', {name: '触摸并允许'});
    expect(f.actions.map(value => value.action)).toEqual(['select', 'setup_password', 'verify_password']);
    fireEvent.click(screen.getByRole('button', {name: '触摸并允许'}));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(f.actions.map(value => value.action)).toEqual(['select', 'setup_password', 'verify_password', 'touch']);
    expect(f.actions[0]).toEqual({action: 'select', key_id: 'key-1', credential_id: 'account-1'});
    expect(f.actions[3]).toEqual({action: 'touch'});
  });
  it.each(['select_key', 'setup_password', 'verify_password', 'touch', 'signing'])('shows labeled selected identity without caveats in %s', async stage => {
    const item = pending(stage);
    await fixture({...item, candidates: [{...candidate, key_name: 'test', user_name: 'misaka', display_name: '御坂', provider_label: 'Local label', model_aaguid: candidate.attestation_aaguid}]});
    const details = screen.getByLabelText('当前验证器详情');
    expect(within(details).getByText('当前验证器').parentElement).toHaveTextContent('当前验证器：test');
    expect(within(details).getByText('设备验证器')).toHaveClass('MuiChip-label');
    for (const [label, value] of [['用户名', 'misaka'], ['显示名', '御坂'], ['Provider', 'Local label'], ['AAGUID', candidate.attestation_aaguid]]) {
      const field = within(details).getByText(label);
      expect(field).toHaveStyle({fontWeight: '700'});
      expect(field.parentElement).toHaveStyle({fontWeight: '400'});
      expect(field.parentElement).toHaveTextContent(`${label}：${value}`);
    }
    expect(screen.getByText('RP ID')).toHaveStyle({fontWeight: '700'});
    expect(screen.queryByText(/软件模拟验证器|无物理设备或可信厂商证明|网站（RP ID）/)).not.toBeInTheDocument();
  });
  it('updates selected details for two accounts on one authenticator and submits only that credential', async () => {
    const item = {...pending(), kind: 'get'};
    const first = {...candidate, user_name: 'first-user', display_name: undefined, provider_label: 'Local label'};
    const second = {...first, credential_id: 'account-2', user_name: 'misaka'};
    const f = await fixture({...item, candidates: [first, second]});
    expect(screen.getByLabelText('当前验证器详情')).toHaveTextContent('first-user');
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', {name: /first-user/}));
    expect(within(screen.getByLabelText('当前验证器详情')).getByText('用户名').parentElement).toHaveTextContent('first-user');
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', {name: /misaka/}));
    expect(within(screen.getByLabelText('当前验证器详情')).getByText('用户名').parentElement).toHaveTextContent('misaka');
    expect(within(screen.getByLabelText('当前验证器详情')).queryByText(/first-user/)).not.toBeInTheDocument();
    expect(screen.queryByText('网站请求证明')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', {name: '继续'}));
    await waitFor(() => expect(f.actions).toEqual([{action: 'select', key_id: candidate.key_id, credential_id: 'account-2'}]));
  });
  it('keeps the exact legacy credential identifiable through touch', async () => {
    await fixture({...pending('touch'), kind: 'get', candidates: [{...candidate, display_name: undefined, user_name: undefined, user_handle: undefined}]});
    expect(screen.getByText('凭证 ID（Base64）').parentElement).toHaveTextContent(`凭证 ID（Base64）：${candidate.credential_id}`);
  });
  it('does not invent a key type or details when the selected credential is unavailable', async () => {
    await fixture({...pending('touch'), selected_credential_id: 'missing'});
    expect(screen.queryByLabelText('当前验证器详情')).not.toBeInTheDocument();
    expect(screen.queryByTestId('UsbOutlinedIcon')).not.toBeInTheDocument();
    expect(screen.getByRole('button', {name: '触摸并允许'})).toBeDisabled();
  });
  it('validates Unicode character count and password confirmation without posting', async () => {
    const f = await fixture(pending('setup_password'));
    fireEvent.change(screen.getByLabelText(/新验证器密码/), {target: {value: '😀😀😀'}});
    fireEvent.change(screen.getByLabelText(/再次输入验证器密码/), {target: {value: '😀😀😀'}});
    fireEvent.click(screen.getByRole('button', {name: '保存密码'}));
    expect(screen.getByText('验证器密码至少 6 个字符，且两次输入必须一致。')).toBeVisible();
    expect(f.actions).toHaveLength(0);
  });
  it('keeps fields for countdown ticks but clears them when candidates or origins change', async () => {
    const item = pending('verify_password'); const f = await fixture(item);
    const field = screen.getByLabelText(/^验证器密码/);
    fireEvent.change(field, {target: {value: 'secret-value'}});
    await f.emit({connected: true, cursor: 'test:2', requests: [{...item, remaining_ms: 59000}]});
    expect(screen.getByLabelText(/^验证器密码/)).toBe(field);
    expect(field).toHaveValue('secret-value');
    await f.emit({connected: true, cursor: 'test:3', requests: [{...item, origin: 'https://changed.example'}]});
    expect(field).toHaveValue('');
    expect(screen.getByLabelText(/^验证器密码/)).toHaveValue('');
  });
  it('clears secrets and ignores stale controls across disconnects and resyncs', async () => {
    const item = pending('verify_password'); const f = await fixture(item);
    const field = screen.getByLabelText(/^验证器密码/);
    const button = screen.getByRole('button', {name: '验证密码'});
    fireEvent.change(field, {target: {value: 'secret-value'}});
    await f.emit({connected: true, cursor: 'test:2', requests: [item], resync: true});
    expect(field).toHaveValue('');
    fireEvent.click(button); expect(f.actions).toHaveLength(0);
    const replacement = screen.getByLabelText(/^验证器密码/);
    fireEvent.change(replacement, {target: {value: 'another-secret'}});
    await act(async () => { f.controller().error(new Error('connection lost')); await flush(); });
    expect(replacement).toHaveValue('');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('clears software approvals and secrets when healthy native mode is active', async () => {
    const item = pending('verify_password'); const f = await fixture(item);
    const field = screen.getByLabelText(/^验证器密码/);
    const button = screen.getByRole('button', {name: '验证密码'});
    fireEvent.change(field, {target: {value: 'secret-value'}});
    await f.emit({connected: false, control_connected: true, native_qr_mode: true, mode_switching: false, cursor: 'test:2', requests: [item]});
    expect(field).toHaveValue('');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    fireEvent.click(button);
    expect(f.actions).toHaveLength(0);
    await f.emit({connected: false, control_connected: true, native_qr_mode: true, mode_switching: false, cursor: 'test:3', requests: [item]});
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(f.actions).toHaveLength(0);
  });
  it('never retries an ambiguous decision or offers its replayed stage', async () => {
    const item = pending('touch'); const f = await fixture(item, {decision: () => Promise.reject(new TypeError('network failed'))});
    const touch = screen.getByRole('button', {name: '触摸并允许'});
    fireEvent.click(touch); fireEvent.click(touch);
    await waitFor(() => expect(f.notify).toHaveBeenCalled());
    expect(f.actions).toEqual([{action: 'touch'}]);
    await f.emit({connected: true, cursor: 'test:2', requests: [item]});
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(f.actions).toHaveLength(1);
  });
  it('disables busy approval while keeping explicit rejection available', async () => {
    const f = await fixture({...pending('touch'), busy: true});
    expect(screen.getByRole('button', {name: '正在处理…'})).toBeDisabled();
    fireEvent.click(screen.getByRole('button', {name: '拒绝请求'}));
    await waitFor(() => expect(f.actions).toEqual([{action: 'deny'}]));
  });
  it('uses Escape to reject once, restores focus, and does not interpret origin as HTML', async () => {
    const opener = document.createElement('button'); opener.textContent = 'opener'; document.body.append(opener); opener.focus();
    const item = {...pending('verify_password'), origin: '<img src=x onerror=alert(1)>'}; const f = await fixture(item);
    const field = screen.getByLabelText(/^验证器密码/); fireEvent.change(field, {target: {value: 'sensitive'}});
    expect(document.querySelector('img')).toBeNull();
    fireEvent.keyDown(screen.getByRole('dialog'), {key: 'Escape'});
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(field).toHaveValue(''); expect(f.actions).toEqual([{action: 'deny'}]);
    await waitFor(() => expect(opener).toHaveFocus()); opener.remove();
  });
  it('expires the request locally and prevents an expired candidate from being selected', async () => {
    vi.useFakeTimers();
    const item = {...pending('touch'), remaining_ms: 500}; const f = await fixture(item);
    await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(f.actions).toHaveLength(0);
  });
  it('clears fields on pagehide and never applies a decision response from the old generation', async () => {
    let resolve!: (value: Response) => void;
    const item = pending('verify_password'); const f = await fixture(item, {decision: () => new Promise(done => { resolve = done; })});
    const field = screen.getByLabelText(/^验证器密码/); fireEvent.change(field, {target: {value: 'sensitive'}});
    fireEvent.click(screen.getByRole('button', {name: '验证密码'}));
    expect(field).toHaveValue('');
    fireEvent(window, new Event('pagehide'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await act(async () => { resolve(Response.json({ok: true})); await flush(); });
    expect(f.fetcher.mock.calls.filter(call => String(call[0]) === '/api/requests')).toHaveLength(0);
  });
  it('closes the current UI and requests reauthentication on a locked event', async () => {
    const f = await fixture(pending('verify_password'));
    const field = screen.getByLabelText(/^验证器密码/); fireEvent.change(field, {target: {value: 'sensitive'}});
    await act(async () => { f.controller().enqueue(new TextEncoder().encode('event: locked\n\n')); await flush(); });
    expect(field).toHaveValue(''); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(f.onUnauthorized).toHaveBeenCalledOnce();
  });
  it('starts a fresh status and snapshot after BFCache pageshow without restoring typed secrets', async () => {
    const f = await fixture(pending('verify_password'));
    const field = screen.getByLabelText(/^验证器密码/);
    fireEvent.change(field, {target: {value: 'sensitive'}});
    fireEvent(window, new Event('pagehide'));
    expect(field).toHaveValue('');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const pageshow = new Event('pageshow'); Object.defineProperty(pageshow, 'persisted', {value: true});
    await act(async () => { window.dispatchEvent(pageshow); await flush(); });
    expect(f.props.refreshStatus).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await f.emit({...f.snapshot(), cursor: 'test:2'});
    expect(screen.getByLabelText(/^验证器密码/)).toHaveValue('');
    expect(f.actions).toHaveLength(0);
  });
  it('shows authenticator types with distinct icons and uses account metadata without decoding user handles', async () => {
    const item = pending();
    await fixture({...item, candidates: [candidate, {...candidate, key_id: 'key-usb', key_name: '外置验证器', attachment: 'cross-platform', display_name: undefined, user_name: undefined, user_handle: 'YWxpY2VAZXhhbXBsZS5jb20=', credential_id: 'another'}]});
    expect(screen.getByRole('button', {name: '继续'})).toBeEnabled();
    fireEvent.mouseDown(screen.getByRole('combobox'));
    expect(screen.getByRole('option', {name: /设备验证器.*Alice/})).toBeVisible();
    expect(screen.getByRole('option', {name: /USB 验证器.*YWxpY2VAZXhhbXBsZS5jb20=/})).toBeVisible();
    expect(screen.getAllByTestId('DevicesOutlinedIcon').length).toBeGreaterThan(0);
    expect(screen.getAllByTestId('UsbOutlinedIcon').length).toBeGreaterThan(0);
    expect(screen.queryByText(/alice@example.com/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', {name: /USB 验证器/}));
    expect(screen.getByRole('button', {name: '继续'})).toBeEnabled();
  });

  it('does not replay a previously submitted select stage after component remount', async () => {
    const item = pending(); const f = await fixture(item);
    fireEvent.click(screen.getByRole('button', {name: '继续'}));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(f.actions.map(action => action.action)).toEqual(['select']);
    f.rendered.unmount();
    const remounted = await fixture(item);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(remounted.actions).toHaveLength(0);
  });
  it('never allows a touch when the selected candidate is missing or already expired', async () => {
    const missing = await fixture({...pending('touch'), candidates: []});
    expect(screen.getByRole('button', {name: '触摸并允许'})).toBeDisabled();
    missing.rendered.unmount();
    const expired = await fixture({...pending('touch'), candidates: [{...candidate, remaining_ms: 0}]});
    expect(screen.getByRole('button', {name: '触摸并允许'})).toBeDisabled();
    expect(expired.actions).toHaveLength(0);
  });

  it.each([
    ['none', '不要求 (none)'], ['direct', '直接证明 (direct)'], ['indirect', '间接证明 (indirect)'], ['enterprise', '企业证明 (enterprise)'],
  ])('shows unambiguous registration attestation labels for %s', async (requested, label) => {
    await fixture({...pending(), attestation_requested: requested});
    const requestedField = screen.getByText('网站要求的注册证明');
    expect(requestedField.parentElement).toHaveTextContent(`网站要求的注册证明：${label}`);
    expect(requestedField).toHaveStyle({fontWeight: '700'});
    expect(requestedField.parentElement).toHaveStyle({fontWeight: '400'});
    expect(screen.getByText('本次提供的注册证明').parentElement).toHaveTextContent('本次提供的注册证明：无');
    expect(screen.queryByText('将发送证明')).not.toBeInTheDocument();
  });

});

describe('global-only native mode', () => {
  it.each(['get', 'create'])('keeps %s requests limited to configured software authenticators', async kind => {
    const f = await fixture({...pending(), kind});
    fireEvent.mouseDown(screen.getByRole('combobox', {name: '选择验证器和账户'}));
    expect(screen.queryByRole('option', {name: /使用设备扫码/})).not.toBeInTheDocument();
    expect(screen.queryByLabelText('辅助程序连接地址')).not.toBeInTheDocument();
    expect(f.starts).toHaveLength(0);
  });
  it.each(['get', 'create'])('never starts a native helper automatically when %s has no software candidates', async kind => {
    const f = await fixture({...pending(), kind, candidates: []});
    expect(screen.getByRole('combobox', {name: '选择验证器和账户'})).toHaveTextContent('没有可用的验证器或账户');
    expect(screen.getByRole('button', {name: '继续'})).toBeDisabled();
    expect(f.starts).toHaveLength(0);
    expect(HelperSocket.instances).toHaveLength(0);
  });
});
