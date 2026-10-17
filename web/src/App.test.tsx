import { StrictMode, useState } from 'react';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { getCsrfToken } from './api';
import type { AppStatus } from './types';
import { renderMaterial } from './test-render';

const clients = vi.hoisted(() => [] as { canvas: HTMLCanvasElement; emit: (event: string) => void; constructedAt: number; disconnect: ReturnType<typeof vi.fn> }[]);
vi.mock('/novnc/core/rfb.js', () => ({ default: class {
  canvas = document.createElement('canvas');
  listeners = new Map<string, () => void>();
  disconnect = vi.fn(() => this.canvas.remove());
  constructedAt: number;
  constructor(host: HTMLElement) { const created = vi.fn(); created(); this.constructedAt = created.mock.invocationCallOrder[0]; host.append(this.canvas); clients.push(this); }
  addEventListener(event: string, callback: () => void) { this.listeners.set(event, callback); }
  emit(event: string) { this.listeners.get(event)?.(); }
  focus() {}
  sendKey() {}
} }));

class HelperSocket {
  static OPEN = 1;
  static instances: HelperSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null; onerror: (() => void) | null = null;
  readyState = 1; bufferedAmount = 0;
  send = vi.fn(); close = vi.fn();
  constructor(public url: string) {HelperSocket.instances.push(this);}
}
let nativeActive: boolean;
let nativeGeneration: number;
let status: AppStatus;
let mode: 'normal' | 'post-error' | 'refresh-error';
let loggedOut: boolean;
let statusResponses: Promise<AppStatus>[];
const operationScope = '55bf3865-8a19-4311-973e-070f41a2ff84';
let operationSequence: bigint;
let metadataResponse: ((init?: RequestInit) => Promise<Response>) | null;
let ensureResponse: ((init?: RequestInit) => Promise<Response>) | null;
let reconnectResponse: ((init?: RequestInit) => Promise<Response>) | null;
let calls: { path: string; method: string; body: unknown; signal?: AbortSignal | null }[];
beforeEach(() => {
  status = { csrf_token: 'test-csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: true, settings_password_enabled: true, engine_connected: true };
  nativeActive = false; nativeGeneration = 1; HelperSocket.instances = [];
  mode = 'normal'; loggedOut = false; calls = []; statusResponses = []; reconnectResponse = null; ensureResponse = null; clients.length = 0;
  operationSequence = 1n; metadataResponse = null;
  vi.stubGlobal('WebSocket', HelperSocket);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input), method = init?.method || 'GET';
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ path, method, body, signal: init?.signal });
    if (path === '/api/browser/reconnect') {
      if (method === 'GET') return metadataResponse ? metadataResponse(init) : browserMetadata();
      if (body.action === 'ensure' && ensureResponse) return ensureResponse(init);
      if (body.action === 'restart' && reconnectResponse) return reconnectResponse(init);
      operationSequence++;
      return browserResult(init);
    }
    if (path === '/api/downloads') return Response.json({files: []});
    if (path === '/api/logout') {
      loggedOut = true;
      if (mode === 'post-error') throw new TypeError('Connection interrupted after sending logout');
      status[`${body.scope as 'settings' | 'vnc'}_authenticated`] = false;
    }
    if (path === '/api/status' && loggedOut && mode === 'refresh-error') throw new TypeError('Status refresh unavailable');
    if (path === '/api/login') {
      if (body.password === 'wrong') return new Response(JSON.stringify({ error: '密码不正确' }), { status: 401 });
      status[`${body.scope as 'settings' | 'vnc'}_authenticated`] = true;
    }
    const nativeMode = () => ({mode: nativeActive ? 'native' : 'software', state: nativeActive ? 'native' : 'software', generation: nativeGeneration, active: nativeActive, owned: nativeActive, control_connected: true});
    if (path === '/api/browser/mode') {
      if (method === 'POST') {nativeActive = body.mode === 'native'; nativeGeneration++;}
      return Response.json({...nativeMode(), ...(nativeActive ? {session_id: `native-${nativeGeneration}`, token: 'memory-only-native-token', expires_in_ms: 120000, helper_url: 'ws://127.0.0.1:10233'} : {})});
    }
    if (path === '/api/helper/status') return Response.json({...nativeMode(), remaining_ms: 120000});
    if (path === '/api/helper/stop') {nativeActive = false; nativeGeneration++; return Response.json({ok: true});}
    if (path === '/api/requests/events') {
      const stream = new ReadableStream<Uint8Array>({ start(controller) {
        controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: ' + JSON.stringify({requests: [], connected: status.engine_connected, control_connected: status.control_connected, native_qr_mode: status.native_qr_mode, mode_switching: status.mode_switching, cursor: 'test:1', events: []}) + '\n\n'));
        init?.signal?.addEventListener('abort', () => { try { controller.close(); } catch {} });
      } });
      return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } });
    }
    const data = path === '/api/status' ? (statusResponses.length ? await statusResponses.shift()! : status) : path === '/api/security' ? status : path === '/api/keys' ? { keys: [] } : path === '/api/runtime' ? { state: 'ready', sandbox_enabled: false } : { ok: true };
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
  }));
});

describe('Material UI shell sessions', () => {
  it.each([
    [{control_connected: true, native_qr_mode: true, mode_switching: false}, '原生验证模式', 'connected'],
    [{control_connected: false, native_qr_mode: true, mode_switching: false}, '验证引擎连接已断开', 'offline'],
    [{control_connected: true, native_qr_mode: false, mode_switching: false}, '虚拟验证器未就绪', 'offline'],
    [{control_connected: true, native_qr_mode: true, mode_switching: true}, '验证模式切换中…', 'connecting'],
  ] as const)('shows engine status %j in the navigation', async (engineStatus, message, state) => {
    Object.assign(status, {engine_connected: false, ...engineStatus});
    renderMaterial(<App />);
    const connection = await screen.findByRole('status', {name: message});
    expect(connection).toHaveAttribute('data-state', state);
    expect(screen.queryByText('验证引擎未连接')).not.toBeInTheDocument();
  });

  it.each([
    ['/settings', 'post-error', '解锁设置'], ['/settings', 'refresh-error', '解锁设置'],
    ['/', 'post-error', '解锁浏览器'], ['/', 'refresh-error', '解锁浏览器'],
  ] as const)('keeps %s locally locked on %s without replaying logout', async (route, failure, heading) => {
    mode = failure;
    window.history.replaceState({}, '', route);
    const { container } = renderMaterial(<App />);
    const logout = await screen.findByRole('button', { name: '锁定会话' });
    if (route === '/settings') await screen.findByRole('heading', { name: '安全设置' }); await act(flush);
    await userEvent.click(logout);
    fireEvent.click(logout);
    expect(await screen.findByRole('heading', { name: heading })).toBeVisible();
    await waitFor(() => expect(calls.filter(call => call.path === '/api/logout')).toHaveLength(1));
    expect(container.querySelector('.settings-page')).toBeNull();
    expect(container.querySelector('.desktop')).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByRole('button', { name: '锁定会话' })).toBeNull();
    const streams = calls.filter(call => call.path === '/api/requests/events').length;
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
    expect(calls.filter(call => call.path === '/api/requests/events')).toHaveLength(streams);
  });

  it('does not let an older authenticated status response overwrite a newer locked status or CSRF token', async () => {
    window.history.replaceState({}, '', '/settings');
    const { container } = renderMaterial(<App />);
    await screen.findByRole('heading', { name: '安全设置' }); await act(flush);
    let older!: (value: AppStatus) => void;
    let newer!: (value: AppStatus) => void;
    statusResponses.push(new Promise(resolve => { older = resolve; }), new Promise(resolve => { newer = resolve; }));
    const authenticatedSnapshot = { ...status, csrf_token: 'stale-csrf' };
    await act(async () => {
      window.dispatchEvent(new PageTransitionEvent('pagehide'));
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    expect(statusResponses).toHaveLength(0);
    Object.assign(status, {settings_authenticated: false, csrf_token: 'new-session-csrf'});
    await act(async () => { newer({...status}); });
    expect(await screen.findByRole('heading', { name: '解锁设置' })).toBeVisible();
    expect(getCsrfToken()).toBe('new-session-csrf');
    await act(async () => { older(authenticatedSnapshot); });
    expect(screen.getByRole('heading', { name: '解锁设置' })).toBeVisible();
    expect(container.querySelector('.settings-page')).toBeNull();
    expect(getCsrfToken()).toBe('new-session-csrf');
  });

  it('finishes Retry after BFCache revalidation failed and the next response is locked', async () => {
    window.history.replaceState({}, '', '/settings');
    const { container } = renderMaterial(<App />);
    await screen.findByRole('heading', { name: '安全设置' }); await act(flush);
    let fail!: (reason: Error) => void;
    statusResponses.push(new Promise((_, reject) => { fail = reject; }));
    await act(async () => {
      window.dispatchEvent(new PageTransitionEvent('pagehide'));
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
      fail(new TypeError('Offline while restoring page'));
    });
    expect(await screen.findByRole('heading', { name: '暂时无法连接服务' })).toBeVisible();
    status.settings_authenticated = false;
    await userEvent.click(screen.getByRole('button', { name: '重试' }));
    expect(await screen.findByRole('heading', { name: '解锁设置' })).toBeVisible();
    expect(container.querySelector('.settings-page')).toBeNull();
    expect(screen.queryByText('正在连接…')).toBeNull();
  });

  it('ignores a wake completion after another pagehide and clears an old error on the next successful wake', async () => {
    window.history.replaceState({}, '', '/settings');
    const { container } = renderMaterial(<App />);
    await screen.findByRole('heading', { name: '安全设置' }); await act(flush);
    let fail!: (reason: Error) => void;
    statusResponses.push(new Promise((_, reject) => { fail = reject; }));
    await act(async () => {
      window.dispatchEvent(new PageTransitionEvent('pagehide'));
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
      fail(new TypeError('Temporary wake failure'));
    });
    expect(await screen.findByRole('heading', { name: '暂时无法连接服务' })).toBeVisible();
    let delayed!: (value: AppStatus) => void;
    statusResponses.push(new Promise(resolve => { delayed = resolve; }));
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pagehide')); delayed({ ...status }); });
    expect(container.querySelector('.settings-page')).toBeNull();
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
    expect(await screen.findByRole('heading', { name: '安全设置' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: '暂时无法连接服务' })).toBeNull();
  });

  it('clears failed login and unmounted input nodes, while accepting an empty password', async () => {
    status.settings_authenticated = false;
    window.history.replaceState({}, '', '/settings');
    const { unmount } = renderMaterial(<App />);
    const input = await screen.findByLabelText('密码');
    await userEvent.type(input, 'wrong');
    await userEvent.click(screen.getByRole('button', { name: '解锁' }));
    expect(await screen.findByText('密码不正确')).toBeVisible();
    expect(input).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: '解锁' }));
    expect(await screen.findByRole('heading', { name: '安全设置' })).toBeVisible();
    expect(calls.filter(call => call.path === '/api/login').map(call => call.body)).toEqual([{ scope: 'settings', password: 'wrong' }, { scope: 'settings', password: '' }]);
    expect(input).toHaveValue('');
    unmount();
  });

  it('clears secrets on pagehide and revalidates a restored page before showing settings', async () => {
    window.history.replaceState({}, '', '/settings');
    const { container } = renderMaterial(<App />);
    await screen.findByRole('heading', { name: '安全设置' }); await act(flush);
    await userEvent.click(screen.getAllByRole('button', { name: '更改密码' })[0]);
    const input = await screen.findByLabelText('新密码');
    await userEvent.type(input, 'erase from back-forward cache');
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pagehide')); });
    expect(input).toHaveValue('');
    expect(container.querySelector('.settings-page')).toBeNull();
    status.settings_authenticated = false;
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
    expect(await screen.findByRole('heading', { name: '解锁设置' })).toBeVisible();
    expect(container.querySelector('.settings-page')).toBeNull();
  });
});

const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve(); };
const reconnectCalls = () => calls.filter(call => call.path === '/api/browser/reconnect' && (call.body as {action?: string})?.action === 'restart');
const ensureCalls = () => calls.filter(call => call.path === '/api/browser/reconnect' && (call.body as {action?: string})?.action === 'ensure');
const metadataCalls = () => calls.filter(call => call.path === '/api/browser/reconnect' && call.method === 'GET');
function browserMetadata(overrides = {}) { return Response.json({operation_scope: operationScope, operation_sequence: operationSequence.toString(), ...overrides}); }
function browserResult(init?: RequestInit, overrides = {}) {
  const body = init?.body ? JSON.parse(String(init.body)) : reconnectCalls().at(-1)!.body as {action: string; request_id: string};
  return Response.json({ok: true, ...body, restarted: body.action === 'restart', engine_ready: true, window_count: 1, ...overrides});
}
const statusCalls = () => calls.filter(call => call.path === '/api/status');
const advance = async (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); await flush(); });
async function mountBrowser(connected = true) {
  vi.useFakeTimers();
  const view = renderMaterial(<App />);
  await act(flush);
  expect(clients).toHaveLength(1);
  if (connected) await act(async () => { clients[0].emit('connect'); await flush(); });
  return { ...view, client: clients[0], desktop: screen.getByRole('region', { name: '浏览器远程桌面' }) };
}
async function reconnectBrowser() {
  fireEvent.click(screen.getByRole('button', { name: '重新连接' }));
  await act(flush);
}

describe('bounded, non-destructive browser recovery', () => {
  it('replaces RFB while retaining the same paired native helper, owner and controls', async () => {
    const {client} = await mountBrowser();
    fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'})); fireEvent.click(screen.getByRole('option', {name: '原生中继'})); await act(flush);
    const helper = HelperSocket.instances.find(socket => String(socket.url).startsWith('ws://127.0.0.1:10233'))!;
    expect(helper).toBeDefined();
    await act(async () => {helper.onopen?.(); helper.onmessage?.({data: JSON.stringify({type: 'status', state: 'paired'})}); await flush();});
    const bar = screen.getByRole('region', {name: '浏览器控制栏'}); const address = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    const reconnect = screen.getByRole('button', {name: '重新连接'});
    act(() => {fireEvent.click(reconnect); fireEvent.click(reconnect);}); await act(flush);
    expect(reconnectCalls()).toHaveLength(1); expect(clients).toHaveLength(2); expect(client.disconnect).toHaveBeenCalledTimes(1);
    expect(document.querySelectorAll('.vnc-screen canvas')).toHaveLength(1);
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBe(bar); expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBe(address);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(helper.close).not.toHaveBeenCalled(); expect(helper.send).toHaveBeenCalledTimes(1); expect(nativeActive).toBe(true);
    expect(calls.filter(call => call.path === '/api/helper/stop')).toHaveLength(0);
    expect(calls.filter(call => call.path === '/api/browser/mode' && call.method === 'POST')).toHaveLength(1);
    await act(async () => {clients[1].emit('connect'); await flush();});
    expect(screen.getByRole('button', {name: 'Ctrl+Alt+Delete'})).toBeEnabled(); expect(helper.close).not.toHaveBeenCalled();
  });

  it('replaces a connected RFB client exactly once after success and awaits the new connection event', async () => {
    const { client, desktop } = await mountBrowser();
    const streams = calls.filter(call => call.path === '/api/requests/events').length;
    reconnectResponse = async init => browserResult(init, {engine_ready: false});
    await reconnectBrowser();
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    const replacement = screen.getByRole('region', { name: '浏览器远程桌面' });
    expect(replacement).not.toBe(desktop); expect(clients).toHaveLength(2);
    expect(client.disconnect).toHaveBeenCalledTimes(1);
    expect(client.disconnect.mock.invocationCallOrder[0]).toBeLessThan(clients[1].constructedAt);
    expect(document.querySelectorAll('.vnc-screen canvas')).toHaveLength(1);
    expect(replacement).toContainElement(clients[1].canvas);
    expect(replacement.querySelector('.vnc-placeholder')).toHaveTextContent('正在连接浏览器…');
    expect(calls.filter(call => call.path === '/api/requests/events')).toHaveLength(streams + 1);
    expect(screen.getByText('浏览器已重启，验证引擎连接中。')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Ctrl+Alt+Delete' })).toBeDisabled();
    const reads = statusCalls().length;
    await act(async () => {client.emit('connect'); client.emit('disconnect'); client.emit('securityfailure'); await flush();});
    expect(statusCalls()).toHaveLength(reads); expect(replacement.querySelector('.vnc-placeholder')).not.toBeNull();
    expect(screen.queryByText('远程桌面连接验证失败，请重新连接或检查服务配置。')).toBeNull();
    await act(async () => {clients[1].emit('connect'); await flush();});
    expect(replacement.querySelector('.vnc-placeholder')).toBeNull();
    expect(screen.getByRole('button', { name: 'Ctrl+Alt+Delete' })).toBeEnabled();
  });

  it('bounds a hanging POST, coalesces repeated clicks, and ignores the old completion after a manual retry', async () => {
    const { client, desktop } = await mountBrowser();
    let completeOld!: (response: Response) => void;
    reconnectResponse = () => new Promise(resolve => { completeOld = resolve; });
    const button = screen.getByRole('button', { name: '重新连接' });
    act(() => { fireEvent.click(button); fireEvent.click(button); fireEvent.click(button); });
    await act(flush);
    expect(reconnectCalls()).toHaveLength(1);
    expect(button).toBeDisabled();
    expect(screen.getByRole('button', { name: '锁定会话' })).toBeEnabled();
    expect(desktop.querySelector('.vnc-placeholder')).toBeNull();
    await advance(59_999);
    expect(button).toBeDisabled();
    await advance(1);
    expect(button).toBeEnabled();
    expect(screen.getByText('重新连接等待超时，请检查服务状态后重试。')).toBeVisible();
    expect(reconnectCalls()[0].signal?.aborted).toBe(true);
    expect(reconnectCalls()).toHaveLength(1);
    expect(client.disconnect).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Ctrl+Alt+Delete' })).toBeEnabled();
    reconnectResponse = null;
    await reconnectBrowser();
    expect(reconnectCalls()).toHaveLength(2);
    const reads = statusCalls().length;
    await act(async () => { completeOld(browserResult(undefined, {engine_ready: false})); await flush(); });
    expect(statusCalls()).toHaveLength(reads);
    expect(screen.queryByText('浏览器已重启，验证引擎连接中。')).toBeNull();
    expect(clients).toHaveLength(2); expect(client.disconnect).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('region', { name: '浏览器远程桌面' })).not.toBe(desktop);
    expect(document.querySelectorAll('.vnc-screen canvas')).toHaveLength(1);
  });

  it('bounds status revalidation too and rejects its late locked snapshot and stale CSRF token', async () => {
    const { client } = await mountBrowser();
    let completeStatus!: (value: AppStatus) => void;
    statusResponses.push(new Promise(resolve => { completeStatus = resolve; }));
    await reconnectBrowser();
    const staleRead = statusCalls().at(-1)!;
    expect(screen.getByRole('button', { name: '重新连接' })).toBeDisabled();
    await advance(60_000);
    expect(staleRead.signal?.aborted).toBe(true);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    await act(async () => { completeStatus({ ...status, vnc_authenticated: false, csrf_token: 'late-csrf' }); await flush(); });
    expect(getCsrfToken()).toBe('test-csrf');
    expect(screen.queryByRole('heading', { name: '解锁浏览器' })).toBeNull();
    expect(client.disconnect).not.toHaveBeenCalled();
    await reconnectBrowser();
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    expect(clients).toHaveLength(2); expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  it('bounds a hanging response body even when its stream ignores fetch cancellation', async () => {
    const { client } = await mountBrowser();
    let body!: ReadableStreamDefaultController<Uint8Array>;
    reconnectResponse = async () => new Response(new ReadableStream<Uint8Array>({ start(controller) {
      body = controller;
      controller.enqueue(new TextEncoder().encode('{"ok":'));
    } }));
    await reconnectBrowser();
    await advance(60_000);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    expect(reconnectCalls()[0].signal?.aborted).toBe(true);
    const reads = statusCalls().length;
    await act(async () => { body.enqueue(new TextEncoder().encode('true}')); body.close(); await flush(); });
    expect(statusCalls()).toHaveLength(reads);
    expect(client.disconnect).not.toHaveBeenCalled();
    expect(clients).toHaveLength(1);
  });

  it.each(['post', 'status', 'body'] as const)('recovers from a %s failure without dropping a live client', async failure => {
    const { client, desktop } = await mountBrowser();
    if (failure === 'post') reconnectResponse = async () => Response.json({ error: '恢复服务暂时不可用' }, { status: 503 });
    if (failure === 'status') statusResponses.push(Promise.reject(new TypeError('会话状态暂时不可用')));
    if (failure === 'body') reconnectResponse = async () => new Response('invalid-json');
    await reconnectBrowser();
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Ctrl+Alt+Delete' })).toBeEnabled();
    expect(desktop.querySelector('.vnc-placeholder')).toBeNull();
    expect(client.disconnect).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toBeVisible();
    reconnectResponse = null;
    await reconnectBrowser();
    expect(reconnectCalls()).toHaveLength(2);
    expect(clients).toHaveLength(2); expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  it('replaces an unavailable transport and also replaces a client that connects while waiting', async () => {
    const { client } = await mountBrowser(false);
    await reconnectBrowser();
    expect(clients).toHaveLength(2);
    expect(client.disconnect).toHaveBeenCalledTimes(1);
    const recovered = clients[1];
    let finish!: (response: Response) => void;
    reconnectResponse = () => new Promise(resolve => { finish = resolve; });
    await reconnectBrowser();
    await act(async () => { recovered.emit('connect'); finish(browserResult()); await flush(); });
    expect(clients).toHaveLength(3);
    expect(recovered.disconnect).toHaveBeenCalledTimes(1);
    expect(document.querySelectorAll('.vnc-screen canvas')).toHaveLength(1);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
  });

  it.each(['post', 'status'] as const)('locks an expired session discovered by the %s and releases the operation', async stage => {
    const { client } = await mountBrowser();
    if (stage === 'post') reconnectResponse = async () => Response.json({ error: '浏览器会话已过期' }, { status: 401 });
    else statusResponses.push(Promise.resolve({ ...status, vnc_authenticated: false, csrf_token: 'locked-csrf' }));
    await reconnectBrowser();
    expect(screen.getByRole('heading', { name: '解锁浏览器' })).toBeVisible();
    expect(client.disconnect).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: '重新连接' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '解锁' }));
    await act(flush);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
  });

  it('lets logout cancel a pending revalidation and ignores its late authenticated response', async () => {
    const { client } = await mountBrowser();
    let finish!: (value: AppStatus) => void;
    const oldSnapshot = { ...status, csrf_token: 'old-session-csrf' };
    statusResponses.push(new Promise(resolve => { finish = resolve; }));
    await reconnectBrowser();
    const reconnectRead = statusCalls().at(-1)!;
    fireEvent.click(screen.getByRole('button', { name: '锁定会话' }));
    await act(flush);
    expect(reconnectRead.signal?.aborted).toBe(true);
    expect(screen.getByRole('heading', { name: '解锁浏览器' })).toBeVisible();
    expect(calls.filter(call => call.path === '/api/logout')).toHaveLength(1);
    await act(async () => { finish(oldSnapshot); await flush(); });
    expect(screen.getByRole('heading', { name: '解锁浏览器' })).toBeVisible();
    expect(getCsrfToken()).toBe('test-csrf');
    expect(client.disconnect).toHaveBeenCalledTimes(1);
    expect(clients).toHaveLength(1);
  });

  it('cancels a hanging recovery immediately when another status check revokes the browser session', async () => {
    const { client } = await mountBrowser();
    reconnectResponse = () => new Promise(() => {});
    await reconnectBrowser();
    status.vnc_authenticated = false;
    await act(async () => { client.emit('disconnect'); await flush(); });
    expect(reconnectCalls()[0].signal?.aborted).toBe(true);
    expect(screen.getByRole('heading', { name: '解锁浏览器' })).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: '解锁' }));
    await act(flush);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
  });

  it.each(['navigation', 'fragment', 'pagehide', 'unmount'] as const)('cancels recovery on %s and never lets its late completion finish a newer wait', async interruption => {
    const view = await mountBrowser();
    let finishOld!: (response: Response) => void;
    reconnectResponse = () => new Promise(resolve => { finishOld = resolve; });
    await reconnectBrowser();
    const oldPost = reconnectCalls()[0];
    if (interruption === 'navigation') fireEvent.click(screen.getByRole('link', { name: '设置' }));
    if (interruption === 'fragment') act(() => {window.history.pushState({}, '', '/#new-location'); window.dispatchEvent(new PopStateEvent('popstate'));});
    if (interruption === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    if (interruption === 'unmount') view.unmount();
    await act(flush);
    expect(oldPost.signal?.aborted).toBe(true);
    const reads = statusCalls().length;
    if (interruption === 'unmount') {
      await act(async () => { finishOld(browserResult()); await flush(); });
      expect(statusCalls()).toHaveLength(reads);
      expect(clients).toHaveLength(1);
      return;
    }
    if (interruption === 'navigation') fireEvent.click(screen.getByRole('link', { name: '浏览器' }));
    else if (interruption === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
    await act(flush);
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
    let finishNew!: (response: Response) => void;
    reconnectResponse = () => new Promise(resolve => { finishNew = resolve; });
    await reconnectBrowser();
    await act(async () => { finishOld(browserResult(undefined, {engine_ready: false})); await flush(); });
    expect(screen.getByRole('button', { name: '重新连接' })).toBeDisabled();
    expect(screen.queryByText('浏览器已重启，验证引擎连接中。')).toBeNull();
    await act(async () => { finishNew(browserResult()); await flush(); });
    expect(screen.getByRole('button', { name: '重新连接' })).toBeEnabled();
  });
});


describe('initial ensure and explicitly correlated restart', () => {
  it.each(['/', '/settings', '/downloads'])('sends one ensure, never restart, when opening authenticated %s under StrictMode', async route => {
    vi.useFakeTimers(); window.history.replaceState({}, '', route);
    renderMaterial(<StrictMode><App /></StrictMode>); await act(flush);
    expect(ensureCalls()).toHaveLength(1); expect(reconnectCalls()).toHaveLength(0);
    expect(ensureCalls()[0].body).toMatchObject({action: 'ensure', request_id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)});
    await advance(10000); expect(ensureCalls()).toHaveLength(1);
  });
  it('does not ensure a locked browser, then ensures once after login without a confirmation or restart', async () => {
    vi.useFakeTimers(); status.vnc_authenticated = false; renderMaterial(<App />); await act(flush);
    expect(ensureCalls()).toHaveLength(0); fireEvent.click(screen.getByRole('button', {name: '解锁'})); await act(flush);
    expect(ensureCalls()).toHaveLength(1); expect(reconnectCalls()).toHaveLength(0); expect(screen.queryByRole('dialog')).toBeNull();
  });
  it('retains the initially connected RFB client on ensure and assigns each manual restart a new ID', async () => {
    const {client} = await mountBrowser(); expect(clients).toHaveLength(1); expect(client.disconnect).not.toHaveBeenCalled();
    await reconnectBrowser(); await reconnectBrowser();
    expect(clients).toHaveLength(3); expect(reconnectCalls()).toHaveLength(2); expect(ensureCalls()).toHaveLength(1);
    const ids = [...ensureCalls(), ...reconnectCalls()].map(call => (call.body as {request_id: string}).request_id);
    expect(new Set(ids).size).toBe(3); expect(document.querySelectorAll('.vnc-screen canvas')).toHaveLength(1);
  });
  it.each([{request_id: 'wrong-id'}, {action: 'ensure'}, {restarted: false}, {window_count: 2}, {engine_ready: undefined},
    {operation_scope: '8115c5c0-38a5-4df5-b26a-1cbe7400687e'}, {operation_sequence: '999'}, {operation_sequence: 2}, {operation_scope: undefined}])('rejects an uncorrelated or incomplete restart result %j without replacing the client', async fields => {
    const {client} = await mountBrowser(); reconnectResponse = async init => browserResult(init, fields); await reconnectBrowser();
    expect(screen.getByText('浏览器操作响应不匹配，请重试。')).toBeVisible(); expect(client.disconnect).not.toHaveBeenCalled(); expect(clients).toHaveLength(1);
  });
  it('does not retry an uncertain ensure automatically and allows a later explicit restart', async () => {
    vi.useFakeTimers(); ensureResponse = () => new Promise(() => {}); renderMaterial(<App />); await act(flush);
    expect(ensureCalls()).toHaveLength(1); expect(screen.getByRole('button', {name: '重新连接'})).toBeDisabled();
    await advance(60000); expect(ensureCalls()[0].signal?.aborted).toBe(true); expect(ensureCalls()).toHaveLength(1);
    await reconnectBrowser(); expect(reconnectCalls()).toHaveLength(1); expect(ensureCalls()).toHaveLength(1);
  });
});

describe('public browser operation admission and ensure races', () => {
  it('reads metadata for each intent and preserves a u64 counter above Number precision exactly', async () => {
    operationSequence = 18446744073709551614n;
    await mountBrowser(); await reconnectBrowser();
    expect(metadataCalls()).toHaveLength(2);
    expect(ensureCalls()[0].body).toMatchObject({operation_scope: operationScope, operation_sequence: '18446744073709551614'});
    expect(reconnectCalls()[0].body).toMatchObject({operation_scope: operationScope, operation_sequence: '18446744073709551615'});
    expect(clients).toHaveLength(2);
    const lifecycleCalls = calls.filter(call => call.path === '/api/browser/reconnect');
    expect(lifecycleCalls.map(call => call.method)).toEqual(['GET', 'POST', 'GET', 'POST']);
    expect(lifecycleCalls[0].signal).toBe(lifecycleCalls[1].signal);
    expect(lifecycleCalls[2].signal).toBe(lifecycleCalls[3].signal);
  });

  it.each([{operation_scope: 'invalid'}, {operation_scope: undefined}, {operation_scope: operationScope + '\n'}, {operation_scope: operationScope + '\r\n'},
    {operation_sequence: '1\n'}, {operation_sequence: '1\r\n'}, {operation_sequence: undefined}, {operation_sequence: 1},
    {operation_sequence: '0'}, {operation_sequence: '01'}, {operation_sequence: '-1'}, {operation_sequence: '1.0'},
    {operation_sequence: '1e3'}, {operation_sequence: ' 1'}, {operation_sequence: '18446744073709551616'}])('rejects malformed admission metadata %j before issuing a mutation', async fields => {
    const {client} = await mountBrowser(); metadataResponse = async () => browserMetadata(fields);
    await reconnectBrowser();
    expect(reconnectCalls()).toHaveLength(0); expect(metadataCalls()).toHaveLength(2);
    expect(screen.getByText('浏览器操作信息无效，请重试。')).toBeVisible();
    expect(client.disconnect).not.toHaveBeenCalled();
    await advance(5000); expect(metadataCalls()).toHaveLength(2);
  });

  it('recovers two simultaneous page ensures from both stale-sequence and busy admission races', async () => {
    vi.useFakeTimers(); window.history.replaceState({}, '', '/downloads');
    let busy = false; let finishFirst!: () => void;
    const admitted: unknown[] = [];
    ensureResponse = async init => {
      const body = JSON.parse(String(init?.body));
      if (body.operation_sequence !== operationSequence.toString()) return Response.json({ok: false, code: 'stale_browser_intent', message: 'Sequence changed'}, {status: 409});
      if (busy) return Response.json({ok: false, code: 'browser_operation_busy', message: 'Another page is preparing the window'}, {status: 409});
      operationSequence++; admitted.push(body);
      if (admitted.length === 1) { busy = true; return new Promise(resolve => { finishFirst = () => {busy = false; resolve(browserResult(init));}; }); }
      return browserResult(init);
    };
    renderMaterial(<><App /><App /></>); await act(flush);
    expect(ensureCalls()).toHaveLength(2); expect(admitted).toHaveLength(1);
    await advance(999); expect(metadataCalls()).toHaveLength(2);
    await advance(1); expect(ensureCalls()).toHaveLength(3); expect(admitted).toHaveLength(1);
    await act(async () => {finishFirst(); await flush();});
    await advance(1000);
    expect(ensureCalls()).toHaveLength(4); expect(admitted).toHaveLength(2); expect(metadataCalls()).toHaveLength(4);
    expect(new Set(ensureCalls().map(call => (call.body as {request_id: string}).request_id)).size).toBe(4);
    expect(ensureCalls().map(call => (call.body as {operation_sequence: string}).operation_sequence)).toEqual(['1', '1', '2', '2']);
    expect(screen.queryByRole('alert')).toBeNull(); expect(reconnectCalls()).toHaveLength(0);
    expect(screen.getAllByRole('button', {name: '重新连接', hidden: true}).every(button => !button.hasAttribute('disabled'))).toBe(true);
    await advance(5000); expect(ensureCalls()).toHaveLength(4);
  });

  it.each(['stale_browser_intent', 'browser_operation_busy'])('never automatically resubmits a manual restart after %s', async code => {
    const {client} = await mountBrowser();
    reconnectResponse = async () => Response.json({ok: false, code, message: 'Please retry explicitly'}, {status: 409});
    await reconnectBrowser(); await advance(10000);
    expect(reconnectCalls()).toHaveLength(1); expect(metadataCalls()).toHaveLength(2);
    expect(client.disconnect).not.toHaveBeenCalled(); expect(screen.getByText('Please retry explicitly')).toBeVisible();
    reconnectResponse = null; await reconnectBrowser();
    expect(reconnectCalls()).toHaveLength(2); expect(metadataCalls()).toHaveLength(3);
    expect((reconnectCalls()[1].body as {request_id: string}).request_id).not.toBe((reconnectCalls()[0].body as {request_id: string}).request_id);
  });

  it.each([
    [401, {ok: false, code: 'browser_operation_busy', message: 'Locked'}],
    [403, {ok: false, code: 'stale_browser_intent', message: 'Forbidden'}],
    [501, {ok: false, message: 'Unavailable'}],
    [409, {ok: false, message: 'Permanent receipt mismatch'}],
    [409, {code: 'stale_browser_intent', message: 'Missing failure marker'}],
    [409, {ok: false, code: 'different_failure', message: 'Permanent failure'}],
    [202, {ok: false, in_progress: true}],
  ])('does not retry non-admission ensure response %s %j', async (httpStatus, body) => {
    vi.useFakeTimers(); ensureResponse = async init => Response.json({...JSON.parse(String(init?.body)), ...body}, {status: httpStatus as number});
    renderMaterial(<App />); await act(flush); await advance(5000);
    expect(ensureCalls()).toHaveLength(1); expect(metadataCalls()).toHaveLength(1);
  });

  it('bounds repeated definite ensure rejections with the original 60-second deadline', async () => {
    vi.useFakeTimers(); ensureResponse = async () => Response.json({ok: false, code: 'browser_operation_busy', message: 'Busy'}, {status: 409});
    renderMaterial(<App />); await act(flush); await advance(59999);
    expect(ensureCalls()).toHaveLength(60); expect(screen.getByRole('button', {name: '重新连接'})).toBeDisabled();
    await advance(1);
    expect(screen.getByText('重新连接等待超时，请检查服务状态后重试。')).toBeVisible();
    expect(screen.getByRole('button', {name: '重新连接'})).toBeEnabled();
    expect(metadataCalls().every(call => call.signal?.aborted)).toBe(true);
    await advance(10000); expect(ensureCalls()).toHaveLength(60); expect(metadataCalls()).toHaveLength(60);
  });

  it.each(['ensure', 'restart'] as const)('bounds a stalled %s metadata GET and never lets its late response issue a POST', async action => {
    vi.useFakeTimers();
    if (action === 'restart') await mountBrowser();
    let finish!: (response: Response) => void;
    metadataResponse = () => new Promise(resolve => {finish = resolve;});
    if (action === 'restart') await reconnectBrowser(); else {renderMaterial(<App />); await act(flush);}
    const read = metadataCalls().at(-1)!; const initialEnsures = ensureCalls().length;
    await advance(60000); expect(read.signal?.aborted).toBe(true); expect(reconnectCalls()).toHaveLength(0);
    expect(screen.getByRole('button', {name: '重新连接'})).toBeEnabled();
    metadataResponse = null; await reconnectBrowser(); expect(reconnectCalls()).toHaveLength(1);
    await act(async () => {finish(browserMetadata()); await flush();});
    expect(reconnectCalls()).toHaveLength(1); expect(ensureCalls()).toHaveLength(initialEnsures);
  });

  it.each(['navigation', 'pagehide', 'logout', 'unmount'] as const)('cancels the ensure admission retry delay on %s', async interruption => {
    vi.useFakeTimers(); ensureResponse = async () => Response.json({ok: false, code: 'stale_browser_intent', message: 'Changed'}, {status: 409});
    const view = renderMaterial(<App />); await act(flush);
    expect(ensureCalls()).toHaveLength(1);
    if (interruption === 'navigation') fireEvent.click(screen.getByRole('link', {name: '设置'}));
    if (interruption === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    if (interruption === 'logout') fireEvent.click(screen.getByRole('button', {name: '锁定会话'}));
    if (interruption === 'unmount') view.unmount();
    await act(flush); expect(metadataCalls()[0].signal?.aborted).toBe(true);
    await advance(5000); expect(metadataCalls()).toHaveLength(1); expect(ensureCalls()).toHaveLength(1);
  });

  it('cancels an unresolved metadata GET on route departure before any mutation can be sent', async () => {
    await mountBrowser(); let finish!: (response: Response) => void;
    metadataResponse = () => new Promise(resolve => {finish = resolve;}); await reconnectBrowser();
    const read = metadataCalls().at(-1)!;
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    expect(read.signal?.aborted).toBe(true);
    await act(async () => {finish(browserMetadata()); await flush();});
    expect(reconnectCalls()).toHaveLength(0);
  });
});

describe('global notice transition lifetime', () => {
  it('retains text throughout dismissal and clears it only after the exit animation', async () => {
    await mountBrowser(); reconnectResponse = async () => Response.json({error: 'First operation failed'}, {status: 503}); await reconnectBrowser();
    fireEvent.click(within(screen.getByRole('alert')).getByRole('button'));
    expect(screen.getByText('First operation failed')).toBeInTheDocument();
    await advance(1000); expect(screen.queryByText('First operation failed')).toBeNull();
  });
  it('does not let the old exit clear a newer notice', async () => {
    await mountBrowser(); reconnectResponse = async () => Response.json({error: 'Old operation failed'}, {status: 503}); await reconnectBrowser();
    fireEvent.click(within(screen.getByRole('alert')).getByRole('button')); expect(screen.getByText('Old operation failed')).toBeInTheDocument();
    reconnectResponse = async () => Response.json({error: 'New operation failed'}, {status: 503}); await reconnectBrowser(); await advance(1000);
    expect(screen.getByText('New operation failed')).toBeVisible(); expect(screen.queryByText('Old operation failed')).toBeNull();
  });
  it('starts success dismissal at three seconds and retains its message until the exit finishes', async () => {
    await mountBrowser(); reconnectResponse = async init => browserResult(init, {engine_ready: false}); await reconnectBrowser();
    await advance(2999); expect(screen.getByText('浏览器已重启，验证引擎连接中。')).toBeVisible();
    await advance(1); expect(screen.getByText('浏览器已重启，验证引擎连接中。')).toBeInTheDocument();
    await advance(1000); expect(screen.queryByText('浏览器已重启，验证引擎连接中。')).toBeNull();
  });
});

describe('profile clipboard ownership generation', () => {
  it('replaces only the clipboard transport when the same viewer receives a new generation', async () => {
    const profile = {
      name: 'default', enabled: true, effective_enabled: true, password_enabled: true, idle_timeout_seconds: 180,
      viewer: {viewer_id: 'same-viewer', viewer_token: 'test-viewer-token', owner: true, generation: 1, expired: false, idle_timeout_seconds: 180},
      onDisconnected: vi.fn(), onLocked: vi.fn(),
    };
    let replace!: (value: typeof profile) => void;
    function Harness() { const [value, setValue] = useState(profile); replace = setValue; return <App profile={value} />; }
    renderMaterial(<Harness />);
    await waitFor(() => expect(clients).toHaveLength(1));
    act(() => clients[0].emit('connect'));
    const clipboardSockets = () => HelperSocket.instances.filter(socket => String(socket.url).includes('/api/clipboard/ws'));
    await waitFor(() => expect(clipboardSockets()).toHaveLength(1));
    const original = clipboardSockets()[0];
    act(() => replace({...profile, viewer: {...profile.viewer, generation: 2}}));
    await waitFor(() => expect(clipboardSockets()).toHaveLength(2));
    expect(original.close).toHaveBeenCalledTimes(1);
    expect(clients).toHaveLength(1);
    expect(clients[0].disconnect).not.toHaveBeenCalled();
    expect(calls.filter(call => call.path === '/api/browser/reconnect' && call.method === 'POST' && (call.body as {action?: string})?.action === 'restart')).toHaveLength(0);
  });
});
