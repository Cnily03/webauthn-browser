import { StrictMode } from 'react';
import { act, cleanup, fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserControls } from './BrowserControls';
import { DEFAULT_HELPER_ADDRESS } from './Helper';
import { setCsrfToken } from './api';
import { renderMaterial } from './test-render';

const MODE_KEY = 'webauthn-browser.mode';
const ADDRESS_KEY = 'webauthn-browser.helper-address';
const CUSTOM_ADDRESS = 'ws://localhost:10444';
const CSRF_TOKEN = 'csrf-memory-only';

class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;
  send = vi.fn();
  close = vi.fn(() => { this.readyState = 3; });
  open() { this.readyState = 1; this.onopen?.(); }
  constructor(public url: string) { Socket.instances.push(this); }
}

const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };

function fixture({foreignLease = false, onRequest}: {foreignLease?: boolean; onRequest?: (path: string) => void} = {}) {
  Socket.instances = [];
  vi.stubGlobal('WebSocket', Socket);
  setCsrfToken(CSRF_TOKEN);
  let generation = 40;
  let active = foreignLease;
  let sessionId = foreignLease ? 'foreign-session-capability' : '';
  let token = 0;
  const acquired: {session_id: string; token: string}[] = [];
  const snapshot = () => ({
    mode: active ? 'native' : 'software', state: active ? 'switching' : 'software',
    generation, active, owned: active, control_connected: true,
  });
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    onRequest?.(path);
    if (path === '/api/browser/mode' && init?.method === 'GET') return Response.json(snapshot());
    if (path === '/api/browser/mode' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      if (body.expected_generation !== generation || active) return Response.json({error: 'lease conflict'}, {status: 409});
      active = body.mode === 'native';
      generation++;
      sessionId = `fresh-session-capability-${generation}`;
      const lease = {session_id: sessionId, token: `pairing-secret-${++token}`};
      acquired.push(lease);
      return Response.json({...snapshot(), ...lease, expires_in_ms: 120000, helper_url: DEFAULT_HELPER_ADDRESS});
    }
    if (path === '/api/helper/status') return Response.json({...snapshot(), remaining_ms: 120000});
    if (path === '/api/helper/stop') {
      if (!active || JSON.parse(String(init?.body)).session_id !== sessionId) return Response.json({error: 'stale lease'}, {status: 409});
      active = false;
      generation++;
      return Response.json({ok: true});
    }
    if (path === '/api/helper/refresh') return Response.json({session_id: sessionId, token: `pairing-secret-${++token}`, remaining_ms: 120000});
    if (path === '/api/browser/mode/renew') return Response.json({...snapshot(), remaining_ms: 120000});
    return Response.json({ok: true});
  });
  vi.stubGlobal('fetch', fetcher);
  const props = {
    authConnection: {state: 'connected' as const, message: '验证事件已连接'}, connected: true, reconnecting: false,
    onReconnect: vi.fn(), onCtrlAltDelete: vi.fn(), onFullscreen: vi.fn(), onUnauthorized: vi.fn(),
  };
  const mount = () => renderMaterial(<StrictMode><BrowserControls {...props} /></StrictMode>);
  const calls = (path: string, method?: string) => fetcher.mock.calls.filter(([url, init]) => String(url) === path && (!method || init?.method === method));
  return {mount, calls, acquired};
}

function chooseMode(name: '原生中继' | '软件模拟') {
  fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'}));
  fireEvent.click(screen.getByRole('option', {name}));
}

function storedPreferences() {
  return Object.fromEntries(Array.from({length: localStorage.length}, (_, index) => {
    const key = localStorage.key(index)!;
    return [key, localStorage.getItem(key)];
  }));
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('browser control preferences', () => {
  it('hydrates native mode and helper address synchronously before the first mode request', async () => {
    localStorage.setItem(MODE_KEY, 'native');
    localStorage.setItem(ADDRESS_KEY, CUSTOM_ADDRESS);
    const timeline: string[] = [];
    const getItem = Storage.prototype.getItem;
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(function(this: Storage, key: string) {
      if (this === localStorage) timeline.push(`read:${key}`);
      return getItem.call(this, key);
    });
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const f = fixture({onRequest: path => timeline.push(`request:${path}`)});
    f.mount();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(CUSTOM_ADDRESS);
    await act(flush);
    const firstRequest = timeline.findIndex(event => event === 'request:/api/browser/mode');
    expect(firstRequest).toBeGreaterThan(timeline.indexOf(`read:${MODE_KEY}`));
    expect(firstRequest).toBeGreaterThan(timeline.indexOf(`read:${ADDRESS_KEY}`));
    expect(timeline).toContain(`read:${MODE_KEY}`);
    expect(timeline).toContain(`read:${ADDRESS_KEY}`);
    expect(f.calls('/api/browser/mode', 'POST').map(([, init]) => JSON.parse(String(init?.body)))).toEqual([{mode: 'native', expected_generation: 40}]);
    expect(Socket.instances.map(socket => socket.url)).toEqual(['ws://localhost:10444/']);
    expect(setItem.mock.calls).not.toContainEqual([MODE_KEY, 'software']);
  });

  it('persists edits immediately and restores native preferences after unmount without reusing the old lease', async () => {
    const writes = vi.spyOn(Storage.prototype, 'setItem');
    const f = fixture();
    const firstMount = f.mount();
    await act(flush);
    chooseMode('原生中继');
    expect(localStorage.getItem(MODE_KEY)).toBe('native');
    await act(flush);
    const firstSocket = Socket.instances[0];
    await act(async () => { firstSocket.onopen?.(); await flush(); });
    const firstPair = JSON.parse(firstSocket.send.mock.calls[0][0]);
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: CUSTOM_ADDRESS}});
    expect(localStorage.getItem(ADDRESS_KEY)).toBe(CUSTOM_ADDRESS);
    firstMount.unmount();
    await act(flush);
    expect(firstSocket.close).toHaveBeenCalled();
    expect(f.calls('/api/helper/stop').length).toBeGreaterThan(0);
    for (const [, init] of f.calls('/api/helper/stop')) expect(JSON.parse(String(init?.body))).toEqual({session_id: firstPair.session_id});

    // An unmount/mount models a reload. Advance the clock without running old
    // timers: preferences have no timestamp or expiry, unlike a native lease.
    vi.setSystemTime(new Date('2040-01-01T00:00:00Z'));
    f.mount();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(CUSTOM_ADDRESS);
    await act(flush);
    expect(f.acquired).toHaveLength(2);
    const secondSocket = Socket.instances.at(-1)!;
    expect(secondSocket).not.toBe(firstSocket);
    expect(secondSocket.url).toBe('ws://localhost:10444/');
    await act(async () => { secondSocket.onopen?.(); await flush(); });
    const secondPair = JSON.parse(secondSocket.send.mock.calls[0][0]);
    expect(secondPair.session_id).not.toBe(firstPair.session_id);
    expect(secondPair.token).not.toBe(firstPair.token);
    expect(storedPreferences()).toEqual({[MODE_KEY]: 'native', [ADDRESS_KEY]: CUSTOM_ADDRESS});
    expect(sessionStorage.length).toBe(0);
    expect(writes.mock.calls.every(([key]) => [MODE_KEY, ADDRESS_KEY].includes(key))).toBe(true);
    const serializedWrites = JSON.stringify(writes.mock.calls);
    for (const secret of [CSRF_TOKEN, ...f.acquired.flatMap(lease => [lease.session_id, lease.token])]) expect(serializedWrites).not.toContain(secret);
    expect(serializedWrites).not.toMatch(/expires|generation|session_id|credential/);
  });

  it('restores an explicit software selection while keeping the last edited helper address', async () => {
    const f = fixture();
    const firstMount = f.mount();
    await act(flush);
    chooseMode('原生中继');
    await act(flush);
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: CUSTOM_ADDRESS}});
    chooseMode('软件模拟');
    expect(localStorage.getItem(MODE_KEY)).toBe('software');
    expect(localStorage.getItem(ADDRESS_KEY)).toBe(CUSTOM_ADDRESS);
    await act(flush);
    firstMount.unmount();
    await act(flush);
    const acquiredBeforeReload = f.acquired.length;
    f.mount();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
    await act(flush);
    expect(f.acquired).toHaveLength(acquiredBeforeReload);
    expect(screen.queryByRole('textbox', {name: '辅助程序连接地址'})).not.toBeInTheDocument();
    chooseMode('原生中继');
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(CUSTOM_ADDRESS);
    await act(flush);
    expect(Socket.instances.at(-1)?.url).toBe('ws://localhost:10444/');
  });

  it.each(['native', 'software'] as const)('keeps saved %s intent without adopting or stopping another page’s native lease', async mode => {
    localStorage.setItem(MODE_KEY, mode);
    localStorage.setItem(ADDRESS_KEY, CUSTOM_ADDRESS);
    const f = fixture({foreignLease: true});
    const rendered = f.mount();
    await act(flush);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent(mode === 'native' ? '原生中继' : '软件模拟');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
    expect(f.calls('/api/helper/stop')).toHaveLength(0);
    expect(Socket.instances).toHaveLength(mode === 'native' ? 1 : 0);
    for (const socket of Socket.instances) {
      expect(socket.url).toBe('ws://localhost:10444/');
      act(() => socket.open());
      expect(socket.send).not.toHaveBeenCalled();
    }
    expect(localStorage.getItem(MODE_KEY)).toBe(mode);
    rendered.unmount();
    await act(flush);
    expect(f.calls('/api/helper/stop')).toHaveLength(0);
  });

  it.each(['', 'unexpected', '"native"', '{"mode":"native","token":"untrusted"}'])('ignores invalid stored mode %j rather than acquiring a native lease', async storedMode => {
    localStorage.setItem(MODE_KEY, storedMode);
    const f = fixture();
    f.mount();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
    await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
    expect(Socket.instances).toHaveLength(0);
  });

  it.each(['', '{broken-address', 'ws://example.com:10444'])('keeps invalid helper address %j editable and blocks acquisition until it is corrected', async invalidAddress => {
    localStorage.setItem(MODE_KEY, 'native');
    localStorage.setItem(ADDRESS_KEY, invalidAddress);
    const f = fixture();
    f.mount();
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(invalidAddress);
    await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
    expect(Socket.instances).toHaveLength(0);
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.closest('.MuiInputBase-root')).toContainElement(screen.getByRole('img', {name: '地址无效'}));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByText('地址无效', {selector: 'p, div'})).toBeNull();
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: CUSTOM_ADDRESS}});
    expect(localStorage.getItem(ADDRESS_KEY)).toBe(CUSTOM_ADDRESS);
    fireEvent.click(screen.getByRole('button', {name: '连接'}));
    await act(flush);
    expect(f.acquired).toHaveLength(1);
    expect(Socket.instances[0].url).toBe('ws://localhost:10444/');
  });

  it('continues with in-memory controls when storage reads throw', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('Storage disabled', 'SecurityError'); });
    const f = fixture();
    f.mount();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
    await act(flush);
    chooseMode('原生中继');
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(DEFAULT_HELPER_ADDRESS);
    await act(flush);
    expect(f.acquired).toHaveLength(1);
    expect(Socket.instances).toHaveLength(1);
  });

  it('keeps selection and address edits usable when storage writes throw', async () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('Storage full', 'QuotaExceededError'); });
    const f = fixture();
    f.mount();
    await act(flush);
    chooseMode('原生中继');
    await act(flush);
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: CUSTOM_ADDRESS}});
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toHaveValue(CUSTOM_ADDRESS);
    chooseMode('软件模拟');
    await act(flush);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
    expect(localStorage.length).toBe(0);
    expect(f.calls('/api/helper/stop').length).toBeGreaterThan(0);
  });

  it('does not require access to the localStorage property itself', async () => {
    vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => { throw new DOMException('Storage disabled', 'SecurityError'); });
    const f = fixture();
    f.mount();
    await act(flush);
    chooseMode('原生中继');
    await act(flush);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
    expect(f.acquired).toHaveLength(1);
  });
});
