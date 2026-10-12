import { StrictMode } from 'react';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { renderMaterial } from './test-render';
import type { AppStatus } from './types';

vi.mock('/novnc/core/rfb.js', () => ({default: class {
  addEventListener() {} disconnect() {} focus() {} sendKey() {}
}}));
class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 1; bufferedAmount = 0;
  send = vi.fn(); close = vi.fn();
  constructor(public url: string) { Socket.instances.push(this); }
}
const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve(); };
const advance = async (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); await flush(); });
let status: AppStatus;
let browserLocked: boolean;
let fidoLauncherReady: boolean;
let downloadName: string;
let active: boolean;
let generation: number;
let calls: {path: string; method: string; body?: Record<string, unknown>}[];
beforeEach(() => {
  Socket.instances = []; vi.stubGlobal('WebSocket', Socket);
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  status = {csrf_token: 'csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: true, settings_password_enabled: true, engine_connected: true};
  downloadName = 'webauthn-helper.exe';
  browserLocked = false; fidoLauncherReady = false; active = false; generation = 1; calls = [];
  const mode = () => ({mode: active ? 'native' : 'software', state: active ? 'native' : 'software', active, owned: active, generation, control_connected: true});
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input), method = init?.method || 'GET';
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({path, method, body});
    if (path === '/api/status') return Response.json(status);
    if (path === '/api/downloads') return browserLocked ? Response.json({error: 'browser locked'}, {status: 401}) : Response.json({files: [{name: downloadName, url: `/downloads/${downloadName}`, size: 1024, created_at: null}]});
    if (path === '/api/browser/reconnect') {
      if (!init?.method || init.method === 'GET') return Response.json({operation_scope: '79c046fa-b06a-4e27-b369-5ac27558655a', operation_sequence: '1'});
      const action = JSON.parse(String(init.body));
      return Response.json({ok: true, ...action, restarted: action.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (path === '/api/browser/mode') {
      if (browserLocked) return Response.json({error: 'browser locked'}, {status: 401});
      if (method === 'GET') return Response.json(mode());
      if (active || body.expected_generation !== generation) return Response.json({error: 'stale lease'}, {status: 409});
      active = body.mode === 'native'; generation++;
      return Response.json({...mode(), session_id: `session-${generation}`, token: 'private-memory-only-token', expires_in_ms: 120000, helper_url: 'ws://127.0.0.1:10233'});
    }
    if (path === '/api/helper/status') return browserLocked ? Response.json({error: 'browser locked'}, {status: 401}) : Response.json({...mode(), remaining_ms: 120000, experimental_fido_launcher_ready: fidoLauncherReady});
    if (path === '/api/helper/fido/open') return Response.json({version: 1, relay_id: body.relay_id, remaining_ms: 30000});
    if (path === '/api/helper/fido/exchange') return Response.json({version: 1, relay_id: body.relay_id, exchange_sequence: body.exchange_sequence, reports: [], remaining_ms: 30000});
    if (path === '/api/helper/stop') {
      if (!active || body.session_id !== `session-${generation}`) return Response.json({error: 'stale lease'}, {status: 409});
      active = false; generation++; return Response.json({ok: true});
    }
    if (path === '/api/browser/mode/renew') return Response.json({...mode(), remaining_ms: 120000});
    if (path === '/api/helper/refresh') return Response.json({session_id: `session-${generation}`, token: 'fresh-private-token', remaining_ms: 120000});
    if (path === '/api/login') { status[`${body.scope as 'vnc' | 'settings'}_authenticated`] = true; if (body.scope === 'vnc') browserLocked = false; return Response.json({ok: true}); }
    if (path === '/api/logout') { status[`${body.scope as 'vnc' | 'settings'}_authenticated`] = false; return Response.json({ok: true}); }
    if (path === '/api/security') return Response.json(status);
    if (path === '/api/keys') return Response.json({keys: []});
    if (path === '/api/runtime') return Response.json({state: 'ready'});
    if (path === '/api/requests/events') return new Response(new ReadableStream({start(controller) {
      controller.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify({requests: [], connected: !active, control_connected: true, native_qr_mode: active, mode_switching: false, cursor: `nav:${generation}`, events: []})}\n\n`));
      init?.signal?.addEventListener('abort', () => {try {controller.close();} catch {}});
    }}), {headers: {'Content-Type': 'text/event-stream'}});
    return Response.json({ok: true});
  }));
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function navigate(name: '浏览器' | '设置' | '下载') {
  fireEvent.click(within(screen.getByRole('navigation', {name: '主导航'})).getByRole('link', {name})); await act(flush);
}
async function selectMode(name: '原生中继' | '软件模拟') {
  fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'}));
  fireEvent.click(screen.getByRole('option', {name})); await act(flush);
}
async function startNative() {
  renderMaterial(<StrictMode><App /></StrictMode>); await act(flush); await selectMode('原生中继');
  const socket = Socket.instances[0];
  act(() => {socket.onopen?.(); socket.onmessage?.({data: JSON.stringify({type: 'status', state: 'paired', message: 'paired'})});});
  return socket;
}
const posts = () => calls.filter(call => call.path === '/api/browser/mode' && call.method === 'POST');
const stops = () => calls.filter(call => call.path === '/api/helper/stop');

describe('same-document navigation preserves the owned native session', () => {
  it('keeps native mode, address controls and one live socket through Settings and back, with no stored tokens', async () => {
    const localWrite = vi.spyOn(Storage.prototype, 'setItem');
    const socket = await startNative();
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const address = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    address.focus();
    await navigate('设置');
    expect(window.location.pathname).toBe('/settings'); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    expect(bar).toHaveAttribute('hidden'); expect(bar).toHaveAttribute('inert'); expect(bar).toHaveAttribute('aria-hidden', 'true');
    expect(address).not.toHaveFocus(); expect(screen.queryByRole('combobox', {name: '模式'})).toBeNull();
    expect(socket.close).not.toHaveBeenCalled(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
    await navigate('浏览器');
    expect(window.location.pathname).toBe('/'); expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBe(bar); expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBe(address);
    expect(Socket.instances).toHaveLength(1); expect(socket.send).toHaveBeenCalledOnce(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
    expect(localStorage.getItem('webauthn-browser.mode')).toBe('native');
    expect(localWrite.mock.calls).toEqual([['webauthn-browser.mode', 'native']]); expect(JSON.stringify(window.history.state)).not.toContain('token'); expect(document.body).not.toHaveTextContent('private-memory-only-token');
  });
  it('preserves the same native owner through Downloads and Settings and refreshes the list on re-entry', async () => {
    const socket = await startNative(); const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const address = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    await navigate('下载');
    expect(window.location.pathname).toBe('/downloads'); expect(screen.getByRole('heading', {name: '下载'})).toBeVisible();
    expect(screen.getByRole('link', {name: downloadName})).toHaveAttribute('download');
    expect(bar).toHaveAttribute('hidden'); expect(bar).toHaveAttribute('inert'); expect(screen.queryByRole('region', {name: '浏览器远程桌面'})).toBeNull();
    const nav = screen.getByRole('navigation', {name: '主导航'});
    expect(within(nav).getAllByRole('link').map(link => link.textContent)).toEqual(['浏览器', '设置', '下载']);
    expect(within(nav).getByRole('link', {name: '下载'})).toHaveAttribute('aria-current', 'page');
    expect(within(nav).getByRole('link', {name: '浏览器'})).not.toHaveAttribute('aria-current');
    expect(document.querySelector('.navigation-toggle')).toHaveStyle({visibility: 'hidden'});
    await navigate('设置'); downloadName = 'new.bin'; await navigate('下载');
    expect(screen.getByRole('link', {name: 'new.bin'})).toBeVisible(); expect(screen.queryByRole('link', {name: 'webauthn-helper.exe'})).toBeNull();
    for (const [distance, heading] of [[-1, '安全设置'], [1, '下载']] as const) {
      await act(async () => { const changed = new Promise<void>(resolve => window.addEventListener('popstate', () => resolve(), {once: true})); window.history.go(distance); await changed; await flush(); });
      expect(screen.getByRole('heading', {name: heading})).toBeVisible();
    }
    await navigate('浏览器');
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBe(bar); expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBe(address);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(Socket.instances).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
  });
  it('uses the VNC login boundary for Downloads without locking Settings', async () => {
    status.vnc_authenticated = false; window.history.replaceState({}, '', '/downloads');
    renderMaterial(<StrictMode><App /></StrictMode>); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(calls.filter(call => call.path === '/api/downloads')).toHaveLength(0);
    await navigate('设置'); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    await navigate('下载'); expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    fireEvent.change(screen.getByLabelText('密码'), {target: {value: 'test-only'}});
    fireEvent.click(screen.getByRole('button', {name: '解锁'})); await act(flush);
    expect(window.location.pathname).toBe('/downloads'); expect(screen.getByRole('table', {name: '下载文件'})).toBeVisible();
    const loginIndex = calls.findIndex(call => call.path === '/api/login');
    expect(calls.filter(call => call.path === '/api/downloads').length).toBeGreaterThan(0);
    expect(calls.every((call, index) => call.path !== '/api/downloads' || index > loginIndex)).toBe(true);
    expect(calls[loginIndex]?.body?.scope).toBe('vnc');
  });
  it('ignores a late Downloads 401 after leaving without revoking the native owner', async () => {
    const socket = await startNative(); const original = globalThis.fetch;
    let resolve!: (response: Response) => void; let signal!: AbortSignal;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) !== '/api/downloads') return original(input, init);
      signal = init!.signal!; return new Promise<Response>(done => {resolve = done;});
    }));
    await navigate('下载'); expect(screen.getByRole('status', {name: '正在读取下载列表'})).toBeVisible();
    await navigate('设置'); expect(signal.aborted).toBe(true);
    await act(async () => {resolve(Response.json({error: 'stale authorization'}, {status: 401})); await flush();});
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    await navigate('浏览器'); expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(socket.close).not.toHaveBeenCalled(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
  });
  it.each(['unauthorized list', 'logout'])('revokes the native owner on a Downloads %s while preserving Settings authorization', async reason => {
    const socket = await startNative(); if (reason === 'unauthorized list') browserLocked = true;
    await navigate('下载');
    if (reason === 'logout') {fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);}
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(socket.close).toHaveBeenCalledOnce(); expect(stops().length).toBeGreaterThan(0);
    if (reason === 'logout') expect(calls.find(call => call.path === '/api/logout')?.body).toEqual({scope: 'vnc'});
    await navigate('设置'); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
  });
  it('preserves dirty Settings edits when Downloads navigation is cancelled', async () => {
    const socket = await startNative(); await navigate('设置');
    fireEvent.click(screen.getByRole('link', {name: '验证器管理'})); await act(flush);
    fireEvent.click(screen.getByRole('button', {name: '添加验证器'})); await act(flush);
    const name = screen.getByRole('textbox', {name: '昵称'}); fireEvent.change(name, {target: {value: 'unsaved'}});
    await navigate('下载'); expect(window.location.pathname).toBe('/settings');
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: '取消'})); await act(flush);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()); expect(name).toHaveValue('unsaved');
    expect(calls.filter(call => call.path === '/api/downloads')).toHaveLength(0);
    await navigate('下载'); fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: '放弃更改'})); await act(flush);
    expect(window.location.pathname).toBe('/downloads'); expect(screen.getByRole('table', {name: '下载文件'})).toBeVisible(); expect(name).not.toBeInTheDocument();
    expect(socket.close).not.toHaveBeenCalled(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
  });
  it('keeps the edited address and its in-flight reconnect across Settings navigation', async () => {
    vi.useFakeTimers(); const first = await startNative();
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19005'}});
    expect(localStorage.getItem('webauthn-browser.helper-address')).toBe('localhost:19005');
    await navigate('设置'); await advance(1000);
    expect(first.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].url).toBe('ws://localhost:19005/');
    await navigate('浏览器');
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue('localhost:19005');
    expect(posts()).toHaveLength(1); expect(stops()).toHaveLength(0);
  });
  it('tears down VNC immediately when logout response is still pending', async () => {
    const socket = await startNative(); const original = globalThis.fetch; let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/api/logout' ? new Promise<Response>(done => {resolve = done;}) : original(input, init)));
    fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);
    expect(document.getElementById('browser-controls')).toBeNull(); expect(socket.close).toHaveBeenCalledOnce(); expect(stops().length).toBeGreaterThan(0);
    await act(async () => {status.vnc_authenticated = false; resolve(Response.json({ok: true})); await flush();});
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
  });
  it('retains software selection without creating a helper on return', async () => {
    const socket = await startNative(); await selectMode('软件模拟');
    expect(socket.close).toHaveBeenCalledOnce(); const before = posts().length;
    await navigate('设置'); await navigate('浏览器');
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟'); expect(posts()).toHaveLength(before); expect(Socket.instances).toHaveLength(1);
  });
  it('keeps the same helper and pending FIDO offer through 45 seconds on Settings, then relays later opaque traffic', async () => {
    vi.useFakeTimers(); const socket = await startNative();
    const relayId = 'r'.repeat(43), helperConnectionId = 'c'.repeat(43);
    const frame = (value: Record<string, unknown>) => act(() => socket.onmessage?.({data: JSON.stringify(value)}));
    const offer = (relay_id: string) => frame({type: 'fido_available', version: 1, experimental_fido: true, relay_id, helper_connection_id: helperConnectionId, remaining_ms: 30000});
    offer(relayId); await act(flush);
    fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'})); expect(screen.getByRole('listbox')).toBeVisible();
    fireEvent.click(screen.getByRole('link', {name: '设置', hidden: true})); await act(flush);
    for (const lease_sequence of [1, 2, 3]) {
      await advance(15000);
      expect(socket.send.mock.calls.map(([raw]) => JSON.parse(raw)).filter(value => value.type === 'fido_renew').at(-1)).toMatchObject({relay_id: relayId, lease_sequence});
      frame({type: 'fido_renewed', version: 1, relay_id: relayId, lease_sequence, remaining_ms: 30000}); await act(flush);
    }
    expect(screen.queryByRole('listbox')).toBeNull(); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    expect(calls.filter(call => call.path === '/api/browser/mode/renew')).toHaveLength(1);
    expect(calls.filter(call => call.path === '/api/helper/fido/open')).toHaveLength(0);
    expect(Socket.instances).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled(); expect(posts()).toHaveLength(1);
    await navigate('浏览器'); expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    fidoLauncherReady = true; await advance(1000);
    expect(calls.filter(call => call.path === '/api/helper/fido/open')).toHaveLength(1);
    const opaque = btoa('x'.repeat(64));
    for (const [i, relay_id] of [relayId, 's'.repeat(43)].entries()) {
      if (i) {offer(relay_id); await act(flush);}
      frame({type: 'fido_ready', version: 1, relay_id}); await act(flush);
      frame({type: 'fido_report', version: 1, relay_id, sequence: 0, data: opaque}); await advance(250);
      expect(calls.some(call => call.path === '/api/helper/fido/exchange' && call.body?.relay_id === relay_id && JSON.stringify(call.body.reports) === JSON.stringify([{sequence: 0, data: opaque}]))).toBe(true);
      frame({type: 'fido_close', version: 1, relay_id}); await act(flush);
    }
    expect(calls.filter(call => call.path === '/api/helper/fido/open')).toHaveLength(2);
    expect(calls.filter(call => call.path === '/api/helper/fido/cancel')).toHaveLength(2);
    expect(socket.close).not.toHaveBeenCalled(); expect(stops()).toHaveLength(0); expect(posts()).toHaveLength(1);
  });
  it.each([
    {from: 'Desktop', to: 'CLI', pending: 'open'},
    {from: 'CLI', to: 'Desktop', pending: 'exchange'},
  ])('keeps one App/native owner across $from → $to with fresh approved relay bindings and late old $pending/cancel', async ({pending}) => {
    vi.useFakeTimers(); fidoLauncherReady = true;
    const oldRelay = 'o'.repeat(43), oldConnection = 'd'.repeat(43);
    const newRelay = 'n'.repeat(43), newConnection = 'c'.repeat(43);
    const original = globalThis.fetch;
    let endpoint: Record<string, unknown> | null = null;
    let oldSignal!: AbortSignal;
    let finishOldRequest!: () => void;
    let finishOldCancel!: () => void;
    const binding = (body: Record<string, unknown>) => ({session_id: body.session_id, generation: body.generation,
      relay_id: body.relay_id, helper_connection_id: body.helper_connection_id});
    const matches = (body: Record<string, unknown>) => JSON.stringify(endpoint) === JSON.stringify(binding(body));
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input), body = init?.body ? JSON.parse(String(init.body)) : {};
      if (path === '/api/helper/refresh') {
        // The real refresh endpoint retires both the prior pending preparation
        // and its active FIDO attachment before publishing the next pair token.
        endpoint = null; return original(input, init);
      }
      if (!path.startsWith('/api/helper/fido/')) return original(input, init);
      calls.push({path, method: init?.method || 'GET', body});
      if (body.session_id !== `session-${generation}` || body.generation !== generation || !active)
        return Promise.resolve(Response.json({error: 'stale owner'}, {status: 409}));
      if (path.endsWith('/open')) {
        if (!fidoLauncherReady || endpoint) return Promise.resolve(Response.json({error: 'not ready'}, {status: 409}));
        endpoint = binding(body);
        const response = () => Response.json({version: 1, relay_id: body.relay_id, remaining_ms: 30000});
        if (body.relay_id === oldRelay && pending === 'open') {
          oldSignal = init!.signal!; return new Promise<Response>(resolve => {finishOldRequest = () => resolve(response());});
        }
        return Promise.resolve(response());
      }
      if (path.endsWith('/cancel')) {
        const cancel = () => {
          if (!matches(body)) return Response.json({error: 'stale binding'}, {status: 409});
          endpoint = null; return Response.json({ok: true});
        };
        if (body.relay_id === oldRelay) return new Promise<Response>(resolve => {finishOldCancel = () => resolve(cancel());});
        return Promise.resolve(cancel());
      }
      if (path.endsWith('/exchange')) {
        if (!matches(body)) return Promise.resolve(Response.json({error: 'stale binding'}, {status: 409}));
        const response = (reports: unknown[]) => Response.json({version: 1, relay_id: body.relay_id,
          exchange_sequence: body.exchange_sequence, reports, remaining_ms: 30000});
        if (body.relay_id === oldRelay && pending === 'exchange') {
          oldSignal = init!.signal!; return new Promise<Response>(resolve => {
            finishOldRequest = () => resolve(response([{sequence: 0, data: btoa('x'.repeat(64))}]));
          });
        }
        return Promise.resolve(response([]));
      }
      return Promise.resolve(Response.json({error: 'unexpected FIDO endpoint'}, {status: 400}));
    }));
    const first = await startNative();
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const owner = {session_id: `session-${generation}`, generation};
    const frame = (socket: Socket, value: Record<string, unknown>) => act(() => socket.onmessage?.({data: JSON.stringify(value)}));
    const offer = (socket: Socket, relay_id: string, helper_connection_id: string) => frame(socket,
      {type: 'fido_available', version: 1, experimental_fido: true, relay_id, helper_connection_id, remaining_ms: 30000});
    offer(first, oldRelay, oldConnection); await act(flush);
    if (pending === 'exchange') {frame(first, {type: 'fido_ready', version: 1, relay_id: oldRelay}); await act(flush);}
    const lateMessage = first.onmessage!, lateClose = first.onclose!, lateOpen = first.onopen!;
    fidoLauncherReady = false;
    act(() => first.onclose?.()); await act(flush);
    expect(first.close).toHaveBeenCalledOnce(); expect(oldSignal.aborted).toBe(true);
    expect(calls.filter(call => call.path === '/api/helper/fido/cancel')).toEqual([
      {path: '/api/helper/fido/cancel', method: 'POST', body: {...owner, relay_id: oldRelay, helper_connection_id: oldConnection}},
    ]);
    await advance(1000);
    expect(Socket.instances).toHaveLength(2); const second = Socket.instances[1];
    act(() => second.onopen?.()); await act(flush);
    const pair = JSON.parse(second.send.mock.calls[0][0]);
    expect(pair).toMatchObject({type: 'pair', session_id: owner.session_id});
    expect(pair.token).not.toBe(JSON.parse(first.send.mock.calls[0][0]).token);
    // A fresh helper process must supply its own successful consent response.
    // Mere socket open and even a premature physical offer grant no relay access.
    offer(second, newRelay, newConnection); await advance(2500);
    expect(second.close).not.toHaveBeenCalled(); expect(second.send).toHaveBeenCalledOnce();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    frame(second, {type: 'status', state: 'paired', message: 'approved by this helper process'});
    offer(second, newRelay, newConnection); await act(flush);
    expect(calls.filter(call => call.path === '/api/helper/fido/open')).toHaveLength(1);
    act(() => {
      lateOpen(); lateClose();
      lateMessage({data: JSON.stringify({type: 'fido_available', version: 1, experimental_fido: true,
        relay_id: oldRelay, helper_connection_id: oldConnection, remaining_ms: 30000})});
      lateMessage({data: JSON.stringify({type: 'fido_close', version: 1, relay_id: oldRelay})});
    });
    await act(async () => {finishOldRequest(); await flush();});
    fidoLauncherReady = true; await advance(1000);
    const newBinding = {...owner, relay_id: newRelay, helper_connection_id: newConnection};
    expect(calls.filter(call => call.path === '/api/helper/fido/open').map(call => call.body)).toEqual([
      {...owner, relay_id: oldRelay, helper_connection_id: oldConnection}, newBinding,
    ]);
    expect(second.send.mock.calls.map(([raw]) => JSON.parse(raw))).toContainEqual(expect.objectContaining({type: 'fido_open', relay_id: newRelay}));
    await act(async () => {finishOldCancel(); await flush();});
    expect(endpoint).toEqual(newBinding);
    frame(second, {type: 'fido_ready', version: 1, relay_id: newRelay}); await act(flush);
    const opaque = btoa('y'.repeat(64));
    frame(second, {type: 'fido_report', version: 1, relay_id: newRelay, sequence: 0, data: opaque}); await advance(25);
    expect(calls.some(call => call.path === '/api/helper/fido/exchange'
      && JSON.stringify(binding(call.body!)) === JSON.stringify(newBinding)
      && JSON.stringify(call.body!.reports) === JSON.stringify([{sequence: 0, data: opaque}]))).toBe(true);
    expect(second.send.mock.calls.map(([raw]) => JSON.parse(raw)).some(value => value.relay_id === oldRelay)).toBe(false);
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBe(bar);
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    expect(within(bar).queryByRole('alert')).toBeNull(); expect(second.close).not.toHaveBeenCalled();
    expect(Socket.instances).toHaveLength(2); expect(posts()).toHaveLength(1); expect(stops()).toHaveLength(0);
  });
  it('handles Back/Forward route changes with the same owner and preserves ordinary modifier-click links', async () => {
    const socket = await startNative(); await navigate('设置');
    await act(async () => { const changed = new Promise<void>(resolve => window.addEventListener('popstate', () => resolve(), {once: true})); window.history.back(); await changed; await flush(); });
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    await act(async () => { const changed = new Promise<void>(resolve => window.addEventListener('popstate', () => resolve(), {once: true})); window.history.forward(); await changed; await flush(); });
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    const browser = screen.getByRole('link', {name: '浏览器'});
    expect(browser).toHaveAttribute('href', '/');
    let intercepted = true; window.addEventListener('click', event => {intercepted = event.defaultPrevented; event.preventDefault();}, {once: true});
    const click = new MouseEvent('click', {bubbles: true, cancelable: true, ctrlKey: true}); fireEvent(browser, click);
    expect(intercepted).toBe(false); expect(window.location.pathname).toBe('/settings');
    expect(socket.close).not.toHaveBeenCalled(); expect(posts()).toHaveLength(1);
  });
  it('preserves the browser lease when Settings is separately locked, but VNC logout still revokes it', async () => {
    const socket = await startNative(); await navigate('设置');
    fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁设置'})).toBeVisible(); expect(stops()).toHaveLength(0); expect(socket.close).not.toHaveBeenCalled();
    await navigate('浏览器'); expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(socket.close).toHaveBeenCalledOnce(); expect(stops().length).toBeGreaterThan(0);
  });
  it('locks only VNC when a hidden helper discovers browser authorization expiry', async () => {
    vi.useFakeTimers(); const socket = await startNative(); await navigate('设置'); browserLocked = true;
    await advance(2000);
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible(); expect(document.getElementById('browser-controls')).toBeNull();
    expect(socket.close).toHaveBeenCalledOnce(); await navigate('浏览器'); expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
  });
  it('still revokes a hidden native lease on real pagehide and ignores late pairing callbacks', async () => {
    vi.useFakeTimers(); const socket = await startNative(); const lateMessage = socket.onmessage!; await navigate('设置');
    fireEvent(window, new PageTransitionEvent('pagehide')); await act(flush); act(() => lateMessage({data: JSON.stringify({type: 'status', state: 'paired', message: 'late'})}));
    await advance(5000); expect(socket.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(1); expect(stops().length).toBeGreaterThan(0);
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
  });
  it.each(['link', 'cross-route history', 'same-route history'])('guards unsaved edits across repeated %s navigation without losing history entries', async reason => {
    const socket = await startNative(); await navigate('设置');
    fireEvent.click(screen.getByRole('link', {name: '验证器管理'})); await act(flush);
    const originalLength = window.history.length;
    const originalState = window.history.state;
    fireEvent.click(screen.getByRole('button', {name: '添加验证器'})); await act(flush);
    const name = screen.getByRole('textbox', {name: '昵称'}); fireEvent.change(name, {target: {value: 'Unsaved key'}});
    const delta = reason === 'cross-route history' ? -2 : -1;
    const traverse = async (distance: number) => {
      await act(async () => {
        const changed = new Promise<void>(resolve => window.addEventListener('popstate', () => resolve(), {once: true}));
        window.history.go(distance); await changed; await flush();
      });
    };
    const leave = async () => {
      if (reason === 'link') await navigate('浏览器'); else await traverse(delta);
      await waitFor(() => expect(window.location.pathname + window.location.hash).toBe('/settings#authenticator'));
      expect(screen.getAllByRole('dialog', {name: '放弃尚未保存的更改？'})).toHaveLength(1);
    };
    await leave();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: '取消'})); await act(flush);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(name).toHaveValue('Unsaved key'); expect(socket.close).not.toHaveBeenCalled();
    expect(window.history.length).toBe(originalLength); expect(window.history.state).toEqual(originalState);
    await leave();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: '放弃更改'})); await act(flush);
    await waitFor(() => expect(window.location.pathname + window.location.hash).toBe(reason === 'same-route history' ? '/settings' : '/'));
    await waitFor(() => expect(name).not.toBeInTheDocument());
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    if (reason !== 'link') {
      expect(window.history.length).toBe(originalLength);
      await traverse(-delta);
      await waitFor(() => expect(window.location.pathname + window.location.hash).toBe('/settings#authenticator'));
      expect(window.history.state).toEqual(originalState);
      expect(screen.getByRole('heading', {name: '验证器管理'})).toBeVisible();
      expect(screen.queryByRole('textbox', {name: '昵称'})).toBeNull();
      // The original earlier entries remain usable after cancel and confirm.
      await traverse(delta);
      await waitFor(() => expect(window.location.pathname + window.location.hash).toBe(reason === 'same-route history' ? '/settings' : '/'));
    }
    await navigate('浏览器');
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继'); expect(posts()).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled();
  });
});
