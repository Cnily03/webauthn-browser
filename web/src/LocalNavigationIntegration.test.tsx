import { StrictMode } from 'react';
import { act, fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { renderMaterial } from './test-render';
import type { AppStatus } from './types';

vi.mock('/novnc/core/rfb.js', () => ({default: class {disconnect() {} addEventListener() {} focus() {} sendKey() {}}}));
class Socket {
  readyState = 0; onopen = null; onclose = null; onerror = null; onmessage = null;
  close() {this.readyState = 3;} send() {}
}
interface Feed {controller: ReadableStreamDefaultController<Uint8Array>; signal: AbortSignal;}
let status: AppStatus; let generation: number; let native: boolean; let feeds: Feed[]; let requests: string[]; let id = 0;
const flush = async () => {for (let i = 0; i < 30; i++) await Promise.resolve();};
const snapshot = () => ({connected: !native, control_connected: true, native_qr_mode: native, mode_switching: false, browser_mode: native ? 'native' : 'software', mode_generation: generation, requests: [], cursor: `toast:${generation}`});
const offer = (values = {}) => ({id: `toast:${++id}`, url: 'http://localhost:5544/callback?code=test-only%2B#fragment', remaining_ms: 5000, mode_generation: generation, ...values});
async function send(event: string, value: unknown) {await act(async () => {feeds.at(-1)!.controller.enqueue(new TextEncoder().encode(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`)); await flush();});}
async function start() {const view = renderMaterial(<StrictMode><App /></StrictMode>); await act(flush); return view;}
async function navigate(name: string) {fireEvent.click(within(screen.getByRole('navigation', {name: '主导航'})).getByRole('link', {name})); await act(flush);}
beforeEach(() => {
  vi.useFakeTimers(); feeds = []; requests = []; generation = 1; native = false;
  status = {csrf_token: 'test-csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: true, settings_password_enabled: true};
  vi.stubGlobal('ResizeObserver', class {observe() {} disconnect() {}});
  vi.stubGlobal('WebSocket', Socket); vi.spyOn(window, 'open').mockImplementation(() => null);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); requests.push(path); const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/api/status' || path === '/api/security') return Response.json(status);
    if (path === '/api/keys') return Response.json({keys: []});
    if (path === '/api/runtime') return Response.json({state: 'ready'});
    if (path === '/api/downloads') return Response.json({files: []});
    if (path === '/api/logout') {status[`${body.scope as 'vnc' | 'settings'}_authenticated`] = false; return Response.json({ok: true});}
    if (path === '/api/login') {status[`${body.scope as 'vnc' | 'settings'}_authenticated`] = true; return Response.json({ok: true});}
    if (path === '/api/browser/reconnect') {
      if (!init?.method || init.method === 'GET') return Response.json({operation_scope: '79c046fa-b06a-4e27-b369-5ac27558655a', operation_sequence: '1'});
      const action = JSON.parse(String(init.body));
      return Response.json({ok: true, ...action, restarted: action.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (path === '/api/browser/mode') {
      if (init?.method === 'POST') {native = body.mode === 'native'; generation++;}
      return Response.json({mode: native ? 'native' : 'software', state: native ? 'native' : 'software', active: native, owned: native, control_connected: true, generation, ...(native ? {session_id: `session-${generation}`, token: 'memory-only-test-token', expires_in_ms: 120000} : {})});
    }
    if (path === '/api/helper/status') return Response.json({mode: 'native', state: 'native', active: native, generation, remaining_ms: 120000, control_connected: true});
    if (path === '/api/helper/stop') {native = false; generation++; return Response.json({ok: true});}
    if (path === '/api/requests/events') return new Response(new ReadableStream<Uint8Array>({start(controller) {
      const signal = init!.signal as AbortSignal; feeds.push({controller, signal});
      controller.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify(snapshot())}\n\n`));
      signal.addEventListener('abort', () => {try {controller.close();} catch {}});
    }}), {headers: {'Content-Type': 'text/event-stream'}});
    return Response.json({ok: true});
  }));
});
afterEach(() => {vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals();});

describe('outer App local navigation lifecycle', () => {
  it('shows a single live toast via the existing authenticated stream, with an exact click-only target', async () => {
    await start(); const value = offer(); await send('local_navigation', value); await send('local_navigation', value);
    expect(screen.getAllByText(/^在本机浏览器打开 http/)).toHaveLength(1); expect(window.open).not.toHaveBeenCalled();
    expect(requests.every(path => path.startsWith('/api/'))).toBe(true);
    fireEvent.click(screen.getByRole('button', {name: '打开'}));
    expect(window.open).toHaveBeenCalledExactlyOnceWith(value.url, '_blank', 'noopener,noreferrer');
    await send('local_navigation', value); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
  });
  it.each(['设置', '下载'])('clears on route departure to %s, aborts the old stream, and does not replay after returning', async route => {
    await start(); const value = offer(); await send('local_navigation', value); const button = screen.getByRole('button', {name: '打开'}); const old = feeds.at(-1)!;
    await navigate(route); expect(old.signal.aborted).toBe(true); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); fireEvent.click(button);
    await navigate('浏览器'); await send('local_navigation', value); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
    await send('local_navigation', offer()); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
  });
  it('clears immediately on mode selection and rejects previous-generation offers after the new snapshot', async () => {
    await start(); const value = offer(); await send('local_navigation', value); const old = feeds.at(-1)!;
    fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'})); fireEvent.click(screen.getByRole('option', {name: '原生中继'})); await act(flush);
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(old.signal.aborted).toBe(true);
    await send('snapshot', snapshot()); await send('local_navigation', {...offer(), mode_generation: value.mode_generation});
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    await send('local_navigation', offer()); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible(); expect(window.open).not.toHaveBeenCalled();
  });
  it('locks and reauthenticates without retaining the old prompt or replaying its URL', async () => {
    await start(); const value = offer(); await send('local_navigation', value); const old = feeds.at(-1)!;
    fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(old.signal.aborted).toBe(true); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    fireEvent.change(screen.getByLabelText('密码'), {target: {value: 'test-only'}}); fireEvent.click(screen.getByRole('button', {name: '解锁'})); await act(flush);
    await send('local_navigation', value); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    await send('local_navigation', offer()); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible(); expect(window.open).not.toHaveBeenCalled();
  });
  it('clears on newer container navigation, stream lock and page lifecycle, without automatic opening', async () => {
    await start(); await send('local_navigation', offer()); await send('local_navigation_clear', {mode_generation: generation});
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); await send('local_navigation', offer());
    act(() => window.dispatchEvent(new PageTransitionEvent('pagehide'))); await act(flush);
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(feeds.at(-1)!.signal.aborted).toBe(true);
    act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))); await act(flush);
    await send('local_navigation', offer()); await send('locked', {}); expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
  it('invalidates on a same-path outer fragment navigation', async () => {
    await start(); const value = offer(); await send('local_navigation', value); const old = feeds.at(-1)!;
    await act(async () => {window.history.pushState({}, '', '/#new-outer-location'); window.dispatchEvent(new PopStateEvent('popstate')); await flush();});
    expect(window.location.hash).toBe('#new-outer-location'); expect(old.signal.aborted).toBe(true);
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); await send('local_navigation', value);
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
  it('does not start an event subscription while the browser scope is locked', async () => {
    status.vnc_authenticated = false; await start(); expect(feeds).toHaveLength(0); expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
  });
});
