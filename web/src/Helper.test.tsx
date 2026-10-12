import { StrictMode, useState } from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { bridgeAddress, HelperConnection, HelperDownloadLink, HelperPanel, HelperSetup, DEFAULT_HELPER_ADDRESS, parseAdvertisement } from './Helper';
import { setCsrfToken } from './api';
const session = {session_id: 'session-1', token: 'test-secret', generation: 1, expires_in_ms: 120000, helper_url: 'http://127.0.0.1:10233'};
const frame = JSON.stringify({type: 'advertisement', uuid: '0000fff9-0000-1000-8000-00805f9b34fb', data: 'AQID'});
const statusFrame = (state: string, message = `Helper status: ${state}`) => JSON.stringify({type: 'status', state, message});
const flush = async () => { for (let i = 0; i < 25; i++) await Promise.resolve(); };
const advance = async (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); await flush(); });
class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: unknown}) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  readyState = 1; bufferedAmount = 0; createdAt = Date.now();
  send = vi.fn(); close = vi.fn();
  constructor(public url: string) { Socket.instances.push(this); }
}
function network(override?: (path: string, init?: RequestInit) => Promise<Response> | undefined) {
  Socket.instances = []; vi.stubGlobal('WebSocket', Socket); setCsrfToken('csrf');
  let tokens = 0;
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const response = override?.(path, init); if (response) return response;
    if (path.endsWith('/status')) return Response.json({active: true, generation: session.generation, state: 'native', remaining_ms: 100000});
    if (path.endsWith('/renew')) return Response.json({generation: session.generation, remaining_ms: 120000});
    if (path.endsWith('/refresh')) return Response.json({session_id: session.session_id, token: `fresh-token-${++tokens}`, remaining_ms: 90000});
    return Response.json({ok: true});
  }); vi.stubGlobal('fetch', fetcher);
  const calls = (suffix: string) => fetcher.mock.calls.filter(([path]) => String(path).endsWith(suffix));
  return {fetcher, calls};
}
function setup(override?: (path: string, init?: RequestInit) => Promise<Response> | undefined, initialAddress = DEFAULT_HELPER_ADDRESS, expiresIn = session.expires_in_ms) {
  const f = network(override); const onClose = vi.fn(); const onAddress = vi.fn(); const onRestart = vi.fn();
  const rendered = render(<StrictMode><HelperPanel session={{...session, expires_in_ms: expiresIn}} onClose={onClose} onRestart={onRestart} onAddress={onAddress} initialAddress={initialAddress} /></StrictMode>);
  return {...f, onClose, onAddress, onRestart, rendered};
}
function expectDownloadControls() {
  const link = screen.getByRole('link', {name: '下载'});
  const address = screen.getByRole('textbox', {name: '辅助程序连接地址'});
  const connect = screen.getByRole('button', {name: '连接'});
  expect(link).toHaveAttribute('href', '/downloads');
  expect(link).toHaveAttribute('target', '_blank');
  expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  expect(link).not.toHaveAttribute('download');
  expect(link).toHaveTextContent(/^$/);
  expect(link.querySelector('svg')).toBeInTheDocument();
  expect(screen.queryByText('下载')).not.toBeInTheDocument();
  expect(screen.getAllByText('辅助程序连接地址')[0]).toBeVisible();
  expect(link.parentElement).toBe(connect.parentElement);
  expect(link.nextElementSibling).toContainElement(address);
  expect(link.nextElementSibling?.nextElementSibling).toBe(connect);
  expect(getComputedStyle(link.parentElement!).flexDirection).toBe('row');
  expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  return link;
}
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('native helper local bridge', () => {
  it('validates advertisement UUID, encoding, frame type and bounds', () => {
    expect(parseAdvertisement(frame)).toEqual({uuid: '0000fff9-0000-1000-8000-00805f9b34fb', data: 'AQID'});
    for (const input of [null, '{}', 'x'.repeat(8193), frame.replace('fff9', 'fff8'), frame.replace('AQID', '%%%'), frame.replace('advertisement', 'command'), frame.replace('AQID', btoa('x'.repeat(65))), frame.replace('AQID', 'AB==')]) expect(parseAdvertisement(input)).toBeNull();
  });
  it.each(['https://evil.test:10233', 'http://user:pass@localhost:10233', 'http://localhost:10233/path', 'http://localhost:10233/?token=x', 'http://localhost:80', 'localhost:10233#secret', 'ftp://localhost:10233', 'localhost:65536'])('rejects unsafe address %s before opening a socket', async address => {
    vi.useFakeTimers(); setup(undefined, address); await act(flush); await advance(3000);
    expect(Socket.instances).toHaveLength(0); expect(screen.getByRole('img', {name: '地址无效'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByLabelText('辅助程序连接地址')).toHaveAttribute('aria-invalid', 'true');
  });
  it.each([['127.0.0.1:10233', 'ws://127.0.0.1:10233/'], ['localhost:19000', 'ws://localhost:19000/'], ['https://localhost:19000', 'wss://localhost:19000/'], ['wss://127.0.0.1:19000', 'wss://127.0.0.1:19000/'], ['wss://localhost:19000', 'wss://localhost:19000/']])('normalizes local address %s', (address, expected) => {
    expect(bridgeAddress(address)).toBe(expected);
  });
  it('keeps a fixed built-in icon slot and identical input text-start CSS across connecting, approval, paired and invalid states', async () => {
    vi.useFakeTimers(); setup(); await act(flush);
    const input = screen.getByLabelText('辅助程序连接地址');
    const root = input.closest('.MuiInputBase-root')!;
    const geometry = () => {
      const slot = root.querySelector('.helper-status-adornment')!;
      const icon = slot.querySelector('svg')!;
      expect(slot).toHaveStyle({width: '20px', minWidth: '20px', height: '20px', maxHeight: 'none', flexShrink: '0', display: 'inline-flex', alignItems: 'center', justifyContent: 'center'});
      expect(icon).toHaveClass('MuiSvgIcon-root'); expect(icon).toHaveStyle({width: '20px', height: '20px', flexShrink: '0'});
      expect(input).toBeEnabled(); expect(screen.getByRole('button', {name: '连接'})).toBeEnabled();
      const rootStyle = getComputedStyle(root), slotStyle = getComputedStyle(slot), inputStyle = getComputedStyle(input);
      // jsdom has no rendered geometry. Compare every authored/computed term
      // controlling text start rather than pretending offsetLeft is a layout.
      return {rootLeft: rootStyle.paddingLeft, slotWidth: slotStyle.width, gap: slotStyle.marginRight, inputLeft: inputStyle.paddingLeft,
        inputRight: inputStyle.paddingRight, inputHeight: inputStyle.height, font: inputStyle.fontFamily};
    };
    const initial = geometry(); const spinning = screen.getByRole('progressbar', {name: '正在连接助手与原生引擎'});
    expect(spinning).toHaveAttribute('data-testid', 'AutorenewIcon');
    expect(getComputedStyle(spinning).animation).toContain('helper-status-spin');
    const rules = Array.from(document.styleSheets).flatMap(sheet => Array.from(sheet.cssRules));
    expect(rules.some(rule => rule.cssText.includes('prefers-reduced-motion: reduce') && rule.cssText.includes('animation: none'))).toBe(true);
    act(() => Socket.instances[0].onopen?.()); expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible(); expect(geometry()).toEqual(initial);
    act(() => Socket.instances[0].onmessage?.({data: statusFrame('paired')}));
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible(); expect(geometry()).toEqual(initial);
    fireEvent.change(input, {target: {value: 'invalid address'}});
    expect(screen.getByRole('img', {name: '地址无效'})).toBeVisible(); expect(geometry()).toEqual(initial); expect(screen.queryByRole('alert')).toBeNull();
  });
  it('auto-connects once in StrictMode, never probes, and sends the token only in the first frame', async () => {
    vi.useFakeTimers(); const f = setup(undefined, 'localhost:19000'); await act(flush);
    expect(Socket.instances).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0);
    const ws = Socket.instances[0]; expect(ws.url).toBe('ws://localhost:19000/');
    expect(ws.send).not.toHaveBeenCalled();
    expect(screen.getByRole('progressbar', {name: '正在连接助手与原生引擎'}).closest('.MuiInputBase-root')).toContainElement(screen.getByLabelText('辅助程序连接地址'));
    expect(Socket.instances).toHaveLength(1);
    act(() => ws.onopen?.()); expect(ws.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: session.token, session_id: session.session_id}));
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).not.toBeInTheDocument();
    await advance(8000);
    expect(Socket.instances).toHaveLength(1); expect(ws.close).not.toHaveBeenCalled(); expect(f.calls('/refresh')).toHaveLength(0);
    act(() => ws.onmessage?.({data: statusFrame('paired')}));
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toHaveClass('MuiSvgIcon-colorSuccess');
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    act(() => ws.onmessage?.({data: frame})); await act(flush);
    expect(f.calls('/advertisement')).toHaveLength(1);
    expect(document.body).not.toHaveTextContent(session.token);
    expect(f.fetcher.mock.calls.every(([path, init]) => !String(path).includes(session.token) && !String(init?.body).includes(session.token))).toBe(true);
  });
  it.each(['close', 'error'] as const)('replaces an owned unopened socket at its original1s deadline after a900ms %s', event => {
    vi.useFakeTimers(); setup();
    return act(async () => {
      await flush(); const first = Socket.instances[0]; const startedAt = Date.now();
      await vi.advanceTimersByTimeAsync(900); if (event === 'error') first.onerror?.(); else first.onclose?.();
      await vi.advanceTimersByTimeAsync(99); expect(Socket.instances).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1); await flush(); expect(Socket.instances).toHaveLength(2);
      expect(Date.now()).toBe(startedAt + 1000); expect(first.close).toHaveBeenCalledOnce();
    });
  });
  it.each(['close', 'error'])('retries a pre-open %s after exactly one second without refreshing the unused token', async event => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0];
    const lateOpen = first.onopen!;
    act(() => { if (event === 'close') first.onclose?.(); else first.onerror?.(); });
    await advance(999); expect(Socket.instances).toHaveLength(1);
    await advance(1); expect(Socket.instances).toHaveLength(2);
    expect(f.calls('/refresh')).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(0);
    act(() => lateOpen()); expect(first.send).not.toHaveBeenCalled();
    act(() => Socket.instances[1].onopen?.());
    expect(Socket.instances[1].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: session.token, session_id: session.session_id}));
  });
  it('times out each unopened socket at one second and replaces it immediately without a second retry delay', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush);
    for (let attempt = 0; attempt < 3; attempt++) {
      const current = Socket.instances[attempt];
      await advance(999); expect(Socket.instances).toHaveLength(attempt + 1); expect(current.close).not.toHaveBeenCalled();
      await advance(1); expect(current.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(attempt + 2);
      expect(current.send).not.toHaveBeenCalled();
    }
    expect(f.calls('/refresh')).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    expect(screen.getByRole('button', {name: '连接'})).toBeEnabled(); expect(screen.getByLabelText('辅助程序连接地址')).toBeEnabled();
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
  });
  it('makes every late callback from a timed-out transport inert while the replacement waits for approval', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0];
    const lateOpen = first.onopen!, lateMessage = first.onmessage!, lateError = first.onerror!, lateClose = first.onclose!;
    await advance(1000); const second = Socket.instances[1]; act(() => second.onopen?.());
    act(() => {lateOpen(); lateMessage({data: statusFrame('paired')}); lateMessage({data: frame}); lateError(); lateClose();}); await advance(5000);
    expect(Socket.instances).toHaveLength(2); expect(second.close).not.toHaveBeenCalled(); expect(first.send).not.toHaveBeenCalled(); expect(second.send).toHaveBeenCalledOnce();
    expect(f.calls('/advertisement')).toHaveLength(0); expect(f.calls('/refresh')).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(0);
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
  });
  it('cancels the establishment deadline when opening just before one second and keeps the live approval request', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const socket = Socket.instances[0];
    await advance(999); act(() => socket.onopen?.()); await advance(60001);
    expect(Socket.instances).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled(); expect(socket.send).toHaveBeenCalledOnce();
    expect(f.calls('/refresh')).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
  });
  it('cancels a pending establishment deadline on unmount without starting a replacement', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const socket = Socket.instances[0];
    await advance(999); f.rendered.unmount(); await advance(10000);
    expect(socket.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(1);
  });
  it.each(['close', 'error'])('rotates a sent one-use token before reconnecting after unexpected %s', async event => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0]; act(() => first.onopen?.());
    act(() => { if (event === 'close') first.onclose?.(); else first.onerror?.(); });
    await advance(1000);
    expect(f.calls('/refresh')).toHaveLength(1);
    expect(JSON.parse(String(f.calls('/refresh')[0][1]?.body))).toEqual({session_id: session.session_id, previous_token: session.token});
    expect(Socket.instances).toHaveLength(2); act(() => Socket.instances[1].onopen?.());
    expect(Socket.instances[1].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'fresh-token-1', session_id: session.session_id}));
    expect(f.calls('/stop')).toHaveLength(0);
  });
  it.each(['closed', 'rejected', 'denied', 'revoked', 'expired', 'lease_expired'])('retries %s every second without a warning or stale approval', async state => {
    vi.useFakeTimers(); const f = setup(); await act(flush);
    for (let index = 0; index < 3; index++) {
      const ws = Socket.instances[index]; act(() => ws.onopen?.());
      const lateMessage = ws.onmessage!; const lateClose = ws.onclose!;
      act(() => ws.onmessage?.({data: statusFrame(state)}));
      expect(ws.close).toHaveBeenCalledOnce();
      expect(screen.getByRole('button', {name: '连接'})).toBeEnabled();
      expect(screen.getByLabelText('辅助程序连接地址')).toBeEnabled();
      expect(screen.getByRole('progressbar', {name: '正在连接助手与原生引擎'})).toBeVisible();
      expect(screen.queryByRole('alert')).toBeNull();
      act(() => { lateMessage({data: statusFrame('paired')}); lateClose(); });
      expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
      await advance(999); expect(Socket.instances).toHaveLength(index + 1);
      await advance(1); expect(Socket.instances).toHaveLength(index + 2);
      expect(f.calls('/refresh')).toHaveLength(index + 1);
    }
    expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    const latest = Socket.instances.at(-1)!; act(() => latest.onopen?.());
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    act(() => latest.onmessage?.({data: statusFrame('paired')}));
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
  });
  it('cancels stale retries and sockets when the address changes', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0]; const lateOpen = first.onopen!;
    act(() => first.onerror?.());
    fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19001'}}); await advance(1000);
    expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].url).toBe('ws://localhost:19001/');
    act(() => Socket.instances[1].onopen?.()); await advance(1000); expect(Socket.instances).toHaveLength(2);
    act(() => lateOpen()); expect(first.send).not.toHaveBeenCalled();
    expect(f.onAddress).toHaveBeenCalledWith('localhost:19001');
    fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'https://foreign.test:10233'}}); await advance(3000);
    expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].close).toHaveBeenCalledOnce();
  });
  it('samples address edits every200ms without waiting for a quiet typing period', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0]; act(() => first.onopen?.());
    const input = screen.getByLabelText('辅助程序连接地址');
    await advance(50); fireEvent.change(input, {target: {value: 'localhost:19001'}});
    await advance(100); fireEvent.change(input, {target: {value: 'localhost:19002'}});
    await advance(49); expect(first.close).not.toHaveBeenCalled(); expect(f.calls('/refresh')).toHaveLength(0);
    await advance(1); expect(first.close).toHaveBeenCalledOnce(); expect(f.calls('/refresh')).toHaveLength(1);
    expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].url).toBe('ws://localhost:19002/');
    const lateOpen = Socket.instances[1].onopen!;
    await advance(50); fireEvent.change(input, {target: {value: 'localhost:19003'}});
    await advance(50); fireEvent.change(input, {target: {value: DEFAULT_HELPER_ADDRESS}});
    await advance(99); expect(Socket.instances).toHaveLength(2);
    await advance(1); expect(Socket.instances).toHaveLength(3); expect(Socket.instances[2].url).toBe('ws://127.0.0.1:10233/');
    act(() => {lateOpen(); Socket.instances[2].onopen?.();});
    expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(Socket.instances[2].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'fresh-token-1', session_id: session.session_id}));
  });
  it('keeps refresh single-flight, retries 429 after one second, and replaces a stale409 session', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void; let count = 0;
    const f = setup(path => path.endsWith('/refresh') ? (++count === 1 ? new Promise(done => { resolve = done; }) : Promise.resolve(Response.json({error: 'stale'}, {status: 409}))) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.()); act(() => Socket.instances[0].onclose?.());
    await advance(1000); await advance(3000);
    expect(f.calls('/refresh')).toHaveLength(1); expect(Socket.instances).toHaveLength(5); expect(Socket.instances.slice(1).every(socket => socket.send.mock.calls.length === 0)).toBe(true);
    await act(async () => { resolve(Response.json({error: 'slow down'}, {status: 429})); await flush(); });
    await advance(999); expect(f.calls('/refresh')).toHaveLength(1);
    await advance(1); expect(f.calls('/refresh')).toHaveLength(2);
    expect(f.onRestart).not.toHaveBeenCalled(); await advance(999); expect(f.onRestart).not.toHaveBeenCalled();
    await advance(1); expect(f.onRestart).toHaveBeenCalledOnce();
    await advance(4000); expect(f.calls('/refresh')).toHaveLength(2); expect(f.calls('/stop')).toHaveLength(1);
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible();
  });
  it('stops safely if a committed refresh response is lost and its old token is rejected on retry', async () => {
    vi.useFakeTimers(); let count = 0;
    const f = setup(path => path.endsWith('/refresh') ? (++count === 1 ? Promise.reject(new Error('response lost')) : Promise.resolve(Response.json({error: 'stale token'}, {status: 409}))) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.()); act(() => Socket.instances[0].onclose?.());
    await advance(1000); expect(f.calls('/refresh')).toHaveLength(1); expect(Socket.instances).toHaveLength(2);
    await advance(1000); await advance(3000);
    expect(f.calls('/refresh')).toHaveLength(2); expect(Socket.instances).toHaveLength(3); expect(Socket.instances.slice(1).every(socket => socket.send.mock.calls.length === 0 && socket.close.mock.calls.length === 1)).toBe(true); expect(f.calls('/stop')).toHaveLength(1);
    expect(f.onRestart).toHaveBeenCalledOnce(); expect(screen.queryByRole('alert')).toBeNull();
  });
  it('aborts a pending refresh on unmount and ignores its late result', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/refresh') ? new Promise(done => { resolve = done; }) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.()); act(() => Socket.instances[0].onclose?.()); await advance(1000);
    const signal = f.calls('/refresh')[0][1]?.signal; f.rendered.unmount(); expect(signal?.aborted).toBe(true);
    await act(async () => { resolve(Response.json({session_id: session.session_id, token: 'late-new-token', remaining_ms: 90000})); await flush(); });
    await advance(3000); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].close).toHaveBeenCalledOnce(); expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1);
  });
  it('clears green success after a paired transport loss and requires the new handshake', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0]; act(() => first.onopen?.());
    act(() => first.onmessage?.({data: statusFrame('paired')})); expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    act(() => first.onclose?.()); expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).not.toBeInTheDocument();
    await advance(1000); const second = Socket.instances[1]; act(() => second.onopen?.());
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).not.toBeInTheDocument();
    act(() => second.onmessage?.({data: statusFrame('paired')})); expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    expect(f.calls('/refresh')).toHaveLength(1);
  });
  it.each([{session_id: 'wrong', token: 'fresh', remaining_ms: 10000}, {session_id: session.session_id, token: session.token, remaining_ms: 10000}, {session_id: session.session_id, token: 'fresh', remaining_ms: 0}])('rejects malformed refresh without pairing its pre-established socket: %j', async response => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/refresh') ? Promise.resolve(Response.json(response)) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.()); act(() => Socket.instances[0].onerror?.()); await advance(1000);
    expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(Socket.instances[1].close).toHaveBeenCalledOnce(); expect(f.calls('/stop')).toHaveLength(1);
    expect(f.onRestart).not.toHaveBeenCalled(); await advance(1000); expect(f.onRestart).toHaveBeenCalledOnce();
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible();
  });
  it('bounds asynchronous forwarding to one in-flight plus eight queued and drops stale results', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void; let first = true;
    const f = setup(path => path.endsWith('/advertisement') && first ? (first = false, new Promise(done => { resolve = done; })) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('paired')})); await advance(1000);
    act(() => { for (let i = 0; i < 100; i++) ws.onmessage?.({data: frame}); });
    expect(f.calls('/advertisement')).toHaveLength(1);
    await act(async () => { resolve(Response.json({ok: true})); for (let i = 0; i < 10; i++) await flush(); });
    expect(f.calls('/advertisement')).toHaveLength(9);
    f.rendered.unmount(); await act(flush); expect(f.calls('/stop')).toHaveLength(1);
  });
  it('aborts in-flight forwarding on termination and rejects queued late frames', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/advertisement') ? new Promise(done => { resolve = done; }) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('paired')})); await advance(1000);
    const lateMessage = ws.onmessage!; act(() => { for (let i = 0; i < 20; i++) ws.onmessage?.({data: frame}); });
    const signal = f.calls('/advertisement')[0][1]?.signal;
    act(() => ws.onmessage?.({data: statusFrame('closed')})); expect(signal?.aborted).toBe(true);
    await act(async () => { resolve(Response.json({ok: true})); lateMessage({data: frame}); await flush(); });
    expect(f.calls('/advertisement')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0);
  });
  it('requires actual approval and native readiness before forwarding', async () => {
    vi.useFakeTimers(); let native = false;
    const f = setup(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: session.generation, state: native ? 'native' : 'switching', remaining_ms: 100000})) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.());
    for (const data of [statusFrame('scanning'), statusFrame('error'), '{', JSON.stringify({type: 'status', state: 'paired'}), JSON.stringify({type: 'command', state: 'paired', message: 'invalid'})]) {
      act(() => ws.onmessage?.({data})); expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).not.toBeInTheDocument();
    }
    act(() => ws.onmessage?.({data: frame})); await advance(1000); expect(f.calls('/advertisement')).toHaveLength(0);
    act(() => ws.onmessage?.({data: statusFrame('paired')})); act(() => ws.onmessage?.({data: frame})); await act(flush);
    expect(f.calls('/advertisement')).toHaveLength(0);
    native = true; await advance(1000); expect(f.calls('/advertisement')).toHaveLength(0);
    act(() => ws.onmessage?.({data: frame})); await act(flush); expect(f.calls('/advertisement')).toHaveLength(1);
  });
  it.each(['unmount', 'pagehide'])('cancels socket, retries and late callbacks on %s', async event => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const ws = Socket.instances[0]; const lateOpen = ws.onopen!;
    act(() => ws.onerror?.());
    if (event === 'unmount') f.rendered.unmount(); else fireEvent(window, new Event('pagehide'));
    await advance(3000); act(() => lateOpen());
    expect(Socket.instances).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(1); expect(ws.send).not.toHaveBeenCalled();
  });
  it.each(['unmount', 'pagehide'])('never opens after immediate %s before the mount microtask', async event => {
    const f = setup();
    if (event === 'unmount') f.rendered.unmount(); else fireEvent(window, new Event('pagehide'));
    await act(flush); expect(Socket.instances).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(1);
  });
  it('replaces an expired session without accepting an extension from status polling', async () => {
    vi.useFakeTimers(); const f = setup(undefined, DEFAULT_HELPER_ADDRESS, 1500); await act(flush);
    act(() => Socket.instances[0].onerror?.()); await advance(1000); expect(Socket.instances).toHaveLength(2);
    act(() => Socket.instances[1].onerror?.()); await advance(1000);
    expect(Socket.instances).toHaveLength(2); expect(f.calls('/stop')).toHaveLength(1); expect(f.onClose).not.toHaveBeenCalled();
    expect(f.onRestart).not.toHaveBeenCalled(); await advance(1000); expect(f.onRestart).toHaveBeenCalledOnce();
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible();
  });
  it.each([401, 403, 409])('safely replaces session on authenticated status failure %s', async status => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/status') ? Promise.resolve(Response.json({error: 'locked'}, {status})) : undefined);
    await act(flush); expect(f.onRestart).not.toHaveBeenCalled(); await advance(1000); expect(f.onRestart).toHaveBeenCalledOnce(); expect(f.onClose).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1);
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible();
  });
});

describe('helper downloads and compact controls', () => {
  it('links to the same-origin directory without fetching a binary manifest', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    render(<StrictMode><HelperDownloadLink /></StrictMode>); await act(flush);
    expect(screen.getByRole('link', {name: '下载'})).toHaveAttribute('href', '/downloads'); expect(fetcher).not.toHaveBeenCalled();
  });
  it('keeps Download left of address and always-enabled Connect, without helper text', async () => {
    const f = network(); const onConnect = vi.fn();
    render(<HelperSetup address={DEFAULT_HELPER_ADDRESS} onAddress={vi.fn()} onConnect={onConnect} />); await act(flush);
    fireEvent.click(expectDownloadControls()); await act(flush);
    expect(f.fetcher).not.toHaveBeenCalled(); expect(onConnect).not.toHaveBeenCalled(); expect(Socket.instances).toHaveLength(0);
    expect(screen.queryByText(/点击连接|正在建立扫码会话/)).not.toBeInTheDocument();
  });
  it('renders inline with no floating popup, helper text, fake QR, or binary selectors', async () => {
    const f = setup(); await act(flush); fireEvent.click(expectDownloadControls()); await act(flush);
    const pane = screen.getByRole('region', {name: '原生中继 · 本机助手'});
    expect(getComputedStyle(pane).position).not.toBe('fixed');
    expect(screen.queryByRole('button', {name: '收起'})).not.toBeInTheDocument();
    expect(screen.queryByText(/当前拦截请求|点击连接|扫描|剩余/)).not.toBeInTheDocument();
    expect(pane.querySelector('canvas, img')).toBeNull();
    expect(f.calls('/downloads')).toHaveLength(0); expect(Socket.instances).toHaveLength(1);
  });
});

describe('editable post-pair recovery', () => {
  it('keeps compact controls editable and stable across paired transport loss with a fresh token', async () => {
    vi.useFakeTimers(); const f = network(); const onPaired = vi.fn();
    render(<HelperPanel session={session} onClose={vi.fn()} onPaired={onPaired} />);
    await act(flush); const first = Socket.instances[0];
    act(() => first.onopen?.()); act(() => first.onmessage?.({data: statusFrame('paired')}));
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    expect(input).toBeEnabled(); expect(onPaired).toHaveBeenCalledOnce();
    const lateMessage = first.onmessage!;
    act(() => first.onclose?.()); expect(input).toBeEnabled();
    expect(screen.getByRole('link', {name: '下载'})).toBeVisible();
    await advance(999); expect(Socket.instances).toHaveLength(1);
    await advance(1); expect(Socket.instances).toHaveLength(2); expect(input).toBeEnabled();
    act(() => Socket.instances[1].onopen?.());
    expect(Socket.instances[1].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'fresh-token-1', session_id: session.session_id}));
    act(() => lateMessage({data: frame})); await act(flush);
    expect(f.calls('/advertisement')).toHaveLength(0);
    act(() => Socket.instances[1].onmessage?.({data: statusFrame('paired')}));
    expect(onPaired).toHaveBeenCalledOnce(); expect(input).toBeEnabled();
  });
  it('aborts a sampled pending refresh and retires its uncertain token before requesting the latest owner', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/refresh') ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); const first = Socket.instances[0]; act(() => first.onopen?.()); act(() => first.onclose?.());
    await advance(1000); const signal = f.calls('/refresh')[0][1]?.signal;
    fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19003'}});
    await advance(199); expect(signal?.aborted).toBe(false); expect(f.onRestart).not.toHaveBeenCalled();
    await advance(1); expect(signal?.aborted).toBe(true); expect(f.onRestart).toHaveBeenCalledExactlyOnceWith('localhost:19003'); expect(f.calls('/stop')).toHaveLength(1);
    await act(async () => {resolve(Response.json({session_id: session.session_id, token: 'late-uncertain-token', remaining_ms: 90000})); await flush();});
    await advance(2000); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].close).toHaveBeenCalledOnce(); expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(f.calls('/refresh')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(1);
    expect(f.onRestart).toHaveBeenCalledOnce(); expect(document.body).not.toHaveTextContent('late-uncertain-token');
  });
  it('stops retries and status polling immediately on mode exit', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = network(path => path.endsWith('/refresh') ? new Promise(done => { resolve = done; }) : undefined); const onClose = vi.fn();
    const rendered = render(<HelperPanel session={session} onClose={onClose} />); await act(flush);
    const first = Socket.instances[0]; act(() => first.onopen?.()); act(() => first.onclose?.()); await advance(1000);
    const refreshSignal = f.calls('/refresh')[0][1]?.signal; const statusSignal = f.calls('/status')[0][1]?.signal;
    const statusCount = f.calls('/status').length; rendered.unmount();
    expect(onClose).not.toHaveBeenCalled(); expect(refreshSignal?.aborted).toBe(true); expect(statusSignal?.aborted).toBe(true);
    await act(async () => { resolve(Response.json({session_id: session.session_id, token: 'late-token', remaining_ms: 90000})); await flush(); });
    await advance(5000); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].close).toHaveBeenCalledOnce(); expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1); expect(f.calls('/status')).toHaveLength(statusCount);
    expect(screen.queryByRole('textbox', {name: '辅助程序连接地址'})).not.toBeInTheDocument();
  });
  it('keeps the setup address editable while starting a session', () => {
    render(<HelperSetup address={DEFAULT_HELPER_ADDRESS} onAddress={vi.fn()} onConnect={vi.fn()} />);
    expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBeEnabled();
    expect(screen.getByRole('button', {name: '连接'})).toBeEnabled();
  });
});

describe('renewable global native lease', () => {
  it('renews the browser lease while the same paired transport stays alive beyond the original deadline', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush);
    const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('paired')}));
    await advance(44999); expect(f.calls('/renew')).toHaveLength(0);
    await advance(1); expect(f.calls('/renew')).toHaveLength(1);
    expect(JSON.parse(String(f.calls('/renew')[0][1]?.body))).toEqual({session_id: session.session_id, expected_generation: session.generation});
    await advance(90000);
    expect(f.calls('/renew')).toHaveLength(3); expect(f.calls('/stop')).toHaveLength(0); expect(Socket.instances).toHaveLength(1);
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
  });
  it('keeps a live pending approval without a retry timeout or repeated pairing frame', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.());
    await advance(60000);
    expect(Socket.instances).toHaveLength(1); expect(ws.close).not.toHaveBeenCalled(); expect(ws.send).toHaveBeenCalledOnce();
    expect(f.calls('/refresh')).toHaveLength(0); expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
    expect(screen.queryByRole('alert')).toBeNull();
  });
  it('ends a status generation mismatch without leaking or requiring a session ID from GET status', async () => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: 99, state: 'native', remaining_ms: 120000})) : undefined);
    await act(flush); await advance(3000);
    expect(f.calls('/stop')).toHaveLength(1); expect(f.calls('/refresh')).toHaveLength(0); expect(f.onRestart).toHaveBeenCalledOnce();
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull(); expect(screen.getByRole('button', {name: '连接'})).toBeEnabled();
  });
  it('aborts pending renewal on unmount and ignores the late extended deadline', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/renew') ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.()); await advance(45000); const signal = f.calls('/renew')[0][1]?.signal;
    const count = Socket.instances.length; f.rendered.unmount(); expect(signal?.aborted).toBe(true);
    await act(async () => {resolve(Response.json({generation: 1, remaining_ms: 120000})); await flush();}); await advance(120000);
    expect(f.calls('/renew')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(1); expect(Socket.instances).toHaveLength(count);
  });
});


describe('experimental FIDO helper socket integration', () => {
  const relayId = 'r'.repeat(43);
  const helperConnectionId = 'c'.repeat(43);
  const available = JSON.stringify({type: 'fido_available', version: 1, experimental_fido: true, relay_id: relayId, helper_connection_id: helperConnectionId, remaining_ms: 30000});
  const ready = JSON.stringify({type: 'fido_ready', version: 1, relay_id: relayId});
  const data = btoa('\xff'.repeat(64));
  function fidoNetwork(override?: (path: string, init?: RequestInit) => Promise<Response> | undefined) {
    return setup((path, init) => {
      const custom = override?.(path, init); if (custom) return custom;
      if (path.endsWith('/status')) return Promise.resolve(Response.json({active: true, generation: session.generation, state: 'native', remaining_ms: 100000, experimental_fido_available: true}));
      if (path.endsWith('/open')) return Promise.resolve(Response.json({version: 1, relay_id: relayId, remaining_ms: 30000}));
      if (path.endsWith('/exchange')) return Promise.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: JSON.parse(String(init?.body)).exchange_sequence, reports: [], remaining_ms: 30000}));
      if (path.endsWith('/fido/renew')) {
        const body = JSON.parse(String(init?.body));
        return Promise.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: body.lease_sequence, remaining_ms: body.remaining_ms}));
      }
      return undefined;
    });
  }
  const pair = async () => {
    await act(flush); const ws = Socket.instances[0];
    act(() => { ws.onopen?.(); ws.onmessage?.({data: statusFrame('paired')}); });
    return ws;
  };
  it('uses no FIDO endpoint for the normal BLE helper even when it emits availability', async () => {
    vi.useFakeTimers(); const f = setup(); const ws = await pair();
    act(() => { ws.onmessage?.({data: available}); ws.onmessage?.({data: frame}); }); await act(flush); await advance(2000);
    expect(f.calls('/open')).toHaveLength(0); expect(f.calls('/exchange')).toHaveLength(0); expect(f.calls('/advertisement')).toHaveLength(1);
    expect(ws.close).not.toHaveBeenCalled();
  });
  it('keeps early availability on this socket and starts exactly once after backend native readiness', async () => {
    vi.useFakeTimers(); let native = false;
    const f = fidoNetwork(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: 1, state: native ? 'native' : 'starting', remaining_ms: 100000, experimental_fido_available: native})) : undefined);
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush); expect(f.calls('/open')).toHaveLength(0);
    native = true; await advance(1000); expect(f.calls('/open')).toHaveLength(1);
    act(() => ws.onmessage?.({data: available})); await advance(1000); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(0);
    expect(JSON.parse(String(f.calls('/open')[0][1]?.body))).toEqual({session_id: session.session_id, generation: 1, relay_id: relayId, helper_connection_id: helperConnectionId});
    act(() => ws.onmessage?.({data: ready})); await act(flush); expect(f.calls('/exchange')).toHaveLength(1);
  });
  it('treats launcher readiness as permission to prepare a route only after real helper attachment', async () => {
    vi.useFakeTimers();
    const f = fidoNetwork(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: 1, state: 'native', remaining_ms: 100000,
      experimental_fido_available: false, experimental_fido_launcher_ready: true})) : undefined);
    const ws = await pair(); await advance(1000);
    expect(f.calls('/open')).toHaveLength(0); expect(f.calls('/exchange')).toHaveLength(0);
    expect(document.body).not.toHaveTextContent(/USB.*已连接|FIDO.*已连接/i);
    act(() => ws.onmessage?.({data: available})); await act(flush);
    expect(f.calls('/open')).toHaveLength(1);
    act(() => ws.onmessage?.({data: ready})); await act(flush);
    expect(f.calls('/exchange')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
  });
  it('keeps unavailable USB routing quiet without claiming readiness or interrupting healthy pairing', async () => {
    vi.useFakeTimers(); let launcherReady = false;
    const waiting = '实验性 USB 通道尚未就绪；辅助程序配对和蓝牙仍可使用。';
    // A denied monitor and delayed startup both appear as false readiness; the
    // UI deliberately reports only what this status contract actually proves.
    const f = fidoNetwork(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: 1, state: 'native', remaining_ms: 100000,
      experimental_fido_available: false, experimental_fido_launcher_ready: launcherReady})) : undefined);
    const ws = await pair();
    expect(screen.queryByText(waiting)).not.toBeInTheDocument();
    act(() => ws.onmessage?.({data: available})); await act(flush); await advance(1000);
    expect(screen.queryByText(waiting)).toBeNull(); expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    expect(f.calls('/open')).toHaveLength(0); expect(f.calls('/exchange')).toHaveLength(0);
    expect(document.body).not.toHaveTextContent(/USB.*已连接|FIDO.*已连接|监控.*拒绝/i);
    act(() => ws.onmessage?.({data: frame})); await act(flush); expect(f.calls('/advertisement')).toHaveLength(1);
    act(() => ws.onmessage?.({data: statusFrame('error', '助手扫描提示仍需处理')}));
    expect(screen.queryByText('助手扫描提示仍需处理')).toBeNull();
    launcherReady = true; await advance(1000);
    expect(screen.queryByText(waiting)).not.toBeInTheDocument();
    expect(screen.queryByText('助手扫描提示仍需处理')).toBeNull();
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(0);
    act(() => ws.onmessage?.({data: ready})); await act(flush);
    expect(f.calls('/exchange')).toHaveLength(1); expect(ws.close).not.toHaveBeenCalled();
  });
  it('keeps pending USB and pairing termination free of explanatory banners or false attachment claims', async () => {
    vi.useFakeTimers(); const f = setup(); const ws = await pair();
    act(() => ws.onmessage?.({data: available})); await act(flush);
    expect(screen.queryByText('实验性 USB 通道尚未就绪；辅助程序配对和蓝牙仍可使用。')).toBeNull(); expect(screen.queryByRole('alert')).toBeNull();
    act(() => ws.onmessage?.({data: statusFrame('expired', '配对已结束')})); await act(flush);
    expect(screen.queryByText('实验性 USB 通道尚未就绪；辅助程序配对和蓝牙仍可使用。')).not.toBeInTheDocument();
    expect(screen.queryByText('配对已结束')).toBeNull(); expect(screen.getByRole('progressbar')).toBeVisible(); expect(f.calls('/open')).toHaveLength(0);
  });
  it.each([false, 'true', 1, null])('requires an exact launcher readiness boolean (%j)', async launcherReady => {
    vi.useFakeTimers();
    const f = fidoNetwork(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: true, generation: 1, state: 'native', remaining_ms: 100000,
      experimental_fido_available: false, experimental_fido_launcher_ready: launcherReady})) : undefined);
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush); await advance(1000);
    expect(f.calls('/open')).toHaveLength(0); expect(f.calls('/exchange')).toHaveLength(0);
  });
  it('withdraws launcher readiness on status failure while preserving BLE', async () => {
    vi.useFakeTimers(); let failed = false;
    const f = fidoNetwork(path => path.endsWith('/status') ? (failed ? Promise.reject(new Error('offline')) : Promise.resolve(Response.json({active: true, generation: 1, state: 'native', remaining_ms: 100000,
      experimental_fido_available: false, experimental_fido_launcher_ready: true}))) : undefined);
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush); act(() => ws.onmessage?.({data: ready})); await act(flush);
    failed = true; await advance(1000);
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0); expect(ws.close).not.toHaveBeenCalled();
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).not.toBeInTheDocument();
  });
  it('routes renewal ACKs on the same socket beyond 30 seconds and still terminates on session expiry', async () => {
    vi.useFakeTimers(); let active = true;
    const f = fidoNetwork(path => path.endsWith('/status') ? Promise.resolve(Response.json({active, generation: 1, state: 'native', remaining_ms: 100000,
      experimental_fido_available: false, experimental_fido_launcher_ready: true})) : undefined);
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush); act(() => ws.onmessage?.({data: ready})); await act(flush);
    for (const lease_sequence of [1, 2]) {
      await advance(15000);
      expect(ws.send.mock.calls.map(([raw]) => JSON.parse(raw)).filter(value => value.type === 'fido_renew').at(-1)).toMatchObject({lease_sequence});
      act(() => ws.onmessage?.({data: JSON.stringify({type: 'fido_renewed', version: 1, relay_id: relayId, lease_sequence, remaining_ms: 30000})})); await act(flush);
    }
    await advance(1000);
    expect(f.calls('/fido/renew')).toHaveLength(2); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
    expect(Socket.instances).toHaveLength(1); expect(ws.close).not.toHaveBeenCalled();
    active = false; await advance(1000);
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(1); expect(ws.close).toHaveBeenCalledOnce();
    await advance(30000); expect(f.calls('/fido/renew')).toHaveLength(2); expect(f.calls('/open')).toHaveLength(1);
  });
  it('preserves paired BLE/session after FIDO protocol or authorization failures', async () => {
    vi.useFakeTimers(); const f = fidoNetwork(path => path.endsWith('/exchange') ? Promise.resolve(Response.json({error: 'sensitive payload'}, {status: 403})) : undefined);
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush);
    act(() => ws.onmessage?.({data: ready})); await act(flush);
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0); expect(ws.close).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('USB 中继已停止，请重新连接助手。');
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible(); expect(document.body).not.toHaveTextContent('sensitive payload');
    act(() => ws.onmessage?.({data: frame})); await act(flush); expect(f.calls('/advertisement')).toHaveLength(1);
    await advance(1000); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(1);
  });
  it.each(['disconnect', 'edit', 'unmount', 'pagehide'])('cancels FIDO on %s and ignores late old open results', async reason => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = fidoNetwork(path => path.endsWith('/open') ? new Promise(done => { resolve = done; }) : undefined);
    const ws = await pair(); const lateMessage = ws.onmessage!;
    act(() => ws.onmessage?.({data: available})); await act(flush); const signal = f.calls('/open')[0][1]?.signal;
    act(() => {
      if (reason === 'disconnect') ws.onclose?.();
      else if (reason === 'edit') fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19009'}});
      else if (reason === 'unmount') f.rendered.unmount();
      else window.dispatchEvent(new Event('pagehide'));
    });
    if (reason === 'edit') await advance(200);
    expect(signal?.aborted).toBe(true); expect(f.calls('/cancel')).toHaveLength(1);
    await act(async () => { resolve(Response.json({version: 1, relay_id: relayId, remaining_ms: 30000})); await flush(); });
    act(() => lateMessage({data: ready})); await advance(1000); expect(f.calls('/exchange')).toHaveLength(0);
    expect(ws.send.mock.calls.map(([raw]) => JSON.parse(raw)).some(v => v.type === 'fido_open')).toBe(false);
    if (reason === 'disconnect' || reason === 'edit') {
      expect(f.calls('/refresh')).toHaveLength(1); const next = Socket.instances[1];
      act(() => { next.onopen?.(); next.onmessage?.({data: statusFrame('paired')}); }); await act(flush);
      expect(f.calls('/open')).toHaveLength(1);
    }
  });
  it('cancels only experimental transport when backend leaves native mode', async () => {
    vi.useFakeTimers(); let native = true; let resolve!: (response: Response) => void;
    const f = fidoNetwork(path => {
      if (path.endsWith('/status')) return Promise.resolve(Response.json({active: true, generation: 1, state: native ? 'native' : 'starting', remaining_ms: 100000, experimental_fido_available: true}));
      if (path.endsWith('/exchange')) return new Promise(done => { resolve = done; });
      return undefined;
    });
    const ws = await pair(); act(() => ws.onmessage?.({data: available})); await act(flush); act(() => ws.onmessage?.({data: ready})); await act(flush);
    const signal = f.calls('/exchange')[0][1]?.signal; native = false; await advance(1000);
    expect(signal?.aborted).toBe(true); expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0); expect(ws.close).not.toHaveBeenCalled();
    await act(async () => { resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 0, remaining_ms: 30000, reports: [{sequence: 0, data}]})); await flush(); });
    expect(ws.send.mock.calls.map(([raw]) => JSON.parse(raw)).some(v => v.type === 'fido_report')).toBe(false);
  });
  it('keeps binary, oversized, and malformed frames isolated from BLE recovery', async () => {
    vi.useFakeTimers(); const f = fidoNetwork(); const ws = await pair();
    act(() => ws.onmessage?.({data: available})); await act(flush); act(() => ws.onmessage?.({data: ready})); await act(flush);
    act(() => ws.onmessage?.({data: 'x'.repeat(8193)})); await act(flush);
    expect(f.calls('/cancel')).toHaveLength(1); expect(ws.close).not.toHaveBeenCalled();
    act(() => ws.onmessage?.({data: frame})); await act(flush); expect(f.calls('/advertisement')).toHaveLength(1);
  });
});

describe('serialized session replacement and cancellation', () => {
  it('retries only the restart handoff while the parent is busy, then yields retry ownership once accepted', async () => {
    vi.useFakeTimers();
    const f = network(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: false, generation: 2, state: 'software', remaining_ms: 0})) : undefined);
    const onRestart = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(false).mockReturnValue(true);
    render(<HelperPanel session={session} onClose={vi.fn()} onRestart={onRestart} />); await act(flush);
    await advance(999); expect(onRestart).not.toHaveBeenCalled();
    await advance(1); expect(onRestart).toHaveBeenCalledTimes(1);
    await advance(1000); expect(onRestart).toHaveBeenCalledTimes(2);
    await advance(1000); expect(onRestart).toHaveBeenCalledTimes(3);
    await advance(5000); expect(onRestart).toHaveBeenCalledTimes(3);
    expect(f.calls('/stop')).toHaveLength(1); expect(f.calls('/refresh')).toHaveLength(0);
    expect(screen.getByRole('progressbar')).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
  });
  it.each(['unmount', 'pagehide'])('cancels an already scheduled restart on %s and ignores late callbacks', async reason => {
    vi.useFakeTimers(); let invalidate = false;
    const f = setup(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: !invalidate, generation: 1, state: 'native', remaining_ms: 120000})) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.()); const lateMessage = ws.onmessage!;
    invalidate = true; await advance(1000); expect(f.calls('/stop')).toHaveLength(1); expect(f.onRestart).not.toHaveBeenCalled();
    if (reason === 'unmount') f.rendered.unmount(); else fireEvent(window, new Event('pagehide'));
    act(() => lateMessage({data: statusFrame('paired')})); await advance(5000);
    expect(f.onRestart).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1); expect(Socket.instances).toHaveLength(1);
  });
  it('queues every explicit Connect while cancelling the scheduled automatic replacement timer', async () => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/status') ? Promise.resolve(Response.json({active: false, generation: 2, state: 'software', remaining_ms: 0})) : undefined);
    await act(flush); expect(f.onRestart).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', {name: '连接'})); fireEvent.click(screen.getByRole('button', {name: '连接'}));
    expect(f.onRestart).toHaveBeenCalledTimes(2); await advance(5000); expect(f.onRestart).toHaveBeenCalledTimes(2);
    expect(screen.getByLabelText('辅助程序连接地址')).toBeEnabled(); expect(screen.getByRole('button', {name: '连接'})).toBeEnabled();
    expect(screen.getByRole('progressbar')).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
  });
  it.each([{generation: 999, remaining_ms: 120000}, {generation: 1, remaining_ms: 0}])('safely replaces an invalid renewal without retrying expired credentials: %j', async renewal => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/renew') ? Promise.resolve(Response.json(renewal)) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('paired')}));
    await advance(45000); expect(f.onRestart).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1);
    expect(ws.close).toHaveBeenCalledOnce(); expect(screen.getByRole('progressbar')).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
    await advance(999); expect(f.onRestart).not.toHaveBeenCalled(); await advance(1); expect(f.onRestart).toHaveBeenCalledOnce();
    await advance(5000); expect(f.onRestart).toHaveBeenCalledOnce(); expect(f.calls('/renew')).toHaveLength(1);
  });
  it('drops old advertisements and replaces a failed backend relay without replaying authentication data', async () => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/advertisement') ? Promise.resolve(Response.json({error: 'bridge offline'}, {status: 503})) : undefined);
    await act(flush); const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('paired')}));
    const lateMessage = ws.onmessage!; act(() => ws.onmessage?.({data: frame})); await act(flush);
    expect(ws.close).toHaveBeenCalledOnce(); expect(f.calls('/stop')).toHaveLength(1); expect(f.onRestart).not.toHaveBeenCalled();
    act(() => lateMessage({data: frame})); await advance(1000);
    expect(f.onRestart).toHaveBeenCalledOnce(); expect(f.calls('/advertisement')).toHaveLength(1); expect(screen.queryByRole('alert')).toBeNull();
  });
});


describe('periodic address sampling and explicit restart generations', () => {
  it('samples setup values on the fixed200ms clock and accepts same-address manual requests immediately', async () => {
    vi.useFakeTimers(); const onConnect = vi.fn();
    function Setup() { const [address, setAddress] = useState(DEFAULT_HELPER_ADDRESS); return <HelperSetup address={address} onAddress={setAddress} onConnect={onConnect} />; }
    const view = render(<Setup />); const input = screen.getByLabelText('辅助程序连接地址');
    await advance(50); fireEvent.change(input, {target: {value: 'localhost:19001'}});
    await advance(100); fireEvent.change(input, {target: {value: 'localhost:19002'}});
    await advance(49); expect(onConnect).not.toHaveBeenCalled();
    await advance(1); expect(onConnect).toHaveBeenCalledExactlyOnceWith('localhost:19002');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); expect(onConnect).toHaveBeenCalledTimes(2);
    await advance(199); expect(onConnect).toHaveBeenCalledTimes(2);
    fireEvent.change(input, {target: {value: 'localhost:'}}); await advance(1);
    expect(onConnect).toHaveBeenCalledTimes(3); expect(onConnect).toHaveBeenLastCalledWith('localhost:'); expect(screen.getByRole('img', {name: '地址无效'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
    view.unmount(); await advance(1000); expect(onConnect).toHaveBeenCalledTimes(3);
  });
  it('does not reconnect if an edit returns to the observed address before the next sample', async () => {
    vi.useFakeTimers(); setup(); await act(flush); const socket = Socket.instances[0];
    await advance(50); fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19002'}});
    await advance(100); fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: DEFAULT_HELPER_ADDRESS}});
    await advance(50); expect(Socket.instances).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled();
    act(() => socket.onopen?.()); await advance(1000); expect(Socket.instances).toHaveLength(1);
  });
  it('immediately replaces same-address connecting and live approval sockets only on explicit Connect', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const first = Socket.instances[0]; const lateOpen = first.onopen!;
    fireEvent.click(screen.getByRole('button', {name: '连接'}));
    expect(first.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(2); expect(f.calls('/refresh')).toHaveLength(0);
    act(() => {lateOpen(); Socket.instances[1].onopen?.();}); await act(flush);
    expect(first.send).not.toHaveBeenCalled(); await advance(2000); expect(Socket.instances).toHaveLength(2);
    const second = Socket.instances[1]; fireEvent.click(screen.getByRole('button', {name: '连接'})); expect(second.close).toHaveBeenCalledOnce();
    await act(flush); expect(f.calls('/refresh')).toHaveLength(1); expect(Socket.instances).toHaveLength(3);
    const third = Socket.instances[2]; act(() => third.onopen?.()); await advance(2000);
    expect(third.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'fresh-token-1', session_id: session.session_id}));
    expect(Socket.instances).toHaveLength(3); expect(third.close).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(0);
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
  });
  it.each([200, 401])('aborts old status requests and ignores their late%s result after an immediate manual restart', async responseStatus => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void; let count = 0;
    const f = setup(path => path.endsWith('/status') && ++count === 1 ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); const first = Socket.instances[0]; const signal = f.calls('/status')[0][1]?.signal;
    fireEvent.click(screen.getByRole('button', {name: '连接'}));
    expect(first.close).toHaveBeenCalledOnce(); expect(signal?.aborted).toBe(true); expect(Socket.instances).toHaveLength(2);
    await act(flush); const latest = Socket.instances[1]; act(() => {latest.onopen?.(); latest.onmessage?.({data: statusFrame('paired')});});
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    await act(async () => {resolve(Response.json(responseStatus === 200 ? {active: false, generation: 999, state: 'software', remaining_ms: 0} : {error: 'expired old status'}, {status: responseStatus})); await flush();});
    await advance(1000); expect(latest.close).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
  });
  it.each([200, 401])('aborts old renewal requests and ignores their late%s result after a sampled address change', async responseStatus => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void; let count = 0;
    const f = setup(path => path.endsWith('/renew') && ++count === 1 ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); const first = Socket.instances[0]; act(() => {first.onopen?.(); first.onmessage?.({data: statusFrame('paired')});});
    await advance(45000); const signal = f.calls('/renew')[0][1]?.signal;
    fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19009'}}); await advance(200);
    expect(signal?.aborted).toBe(true); expect(first.close).toHaveBeenCalledOnce(); expect(f.calls('/renew')).toHaveLength(2);
    const latest = Socket.instances[1]; act(() => {latest.onopen?.(); latest.onmessage?.({data: statusFrame('paired')});});
    await act(async () => {resolve(Response.json(responseStatus === 200 ? {generation: 999, remaining_ms: 0} : {error: 'expired old renewal'}, {status: responseStatus})); await flush();});
    await advance(1000); expect(latest.close).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(0); expect(f.onRestart).not.toHaveBeenCalled();
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
  });
  it('aborts a manually cancelled token rotation and immediately hands off only the exact old lease', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/refresh') ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); act(() => Socket.instances[0].onopen?.());
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush); const signal = f.calls('/refresh')[0][1]?.signal;
    fireEvent.click(screen.getByRole('button', {name: '连接'}));
    expect(signal?.aborted).toBe(true); expect(f.onRestart).toHaveBeenCalledExactlyOnceWith(DEFAULT_HELPER_ADDRESS);
    expect(JSON.parse(String(f.calls('/stop')[0][1]?.body))).toEqual({session_id: session.session_id});
    await act(async () => {resolve(Response.json({session_id: session.session_id, token: 'old-rotation-result', remaining_ms: 90000})); await flush();});
    await advance(1000); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].close).toHaveBeenCalledOnce(); expect(Socket.instances[1].send).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1); expect(f.onRestart).toHaveBeenCalledOnce();
  });
  it('stops address sampling and ignores manual Connect after pagehide', async () => {
    vi.useFakeTimers(); const f = setup(); await act(flush); const socket = Socket.instances[0];
    fireEvent(window, new Event('pagehide')); fireEvent.change(screen.getByLabelText('辅助程序连接地址'), {target: {value: 'localhost:19001'}});
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await advance(5000);
    expect(socket.close).toHaveBeenCalledOnce(); expect(Socket.instances).toHaveLength(1); expect(f.onRestart).not.toHaveBeenCalled(); expect(f.calls('/stop')).toHaveLength(1);
  });
});


describe('actual helper transport independent of token refresh', () => {
  it('continues one-second socket establishment attempts while the only token refresh is stalled', async () => {
    vi.useFakeTimers(); const f = setup(path => path.endsWith('/refresh') ? new Promise<Response>(() => {}) : undefined);
    await act(flush); const first = Socket.instances[0], startedAt = first.createdAt;
    act(() => {first.onopen?.(); first.onmessage?.({data: statusFrame('paired')}); first.onclose?.();});
    await advance(999); expect(Socket.instances).toHaveLength(1);
    await advance(1); expect(Socket.instances).toHaveLength(2); expect(f.calls('/refresh')).toHaveLength(1);
    await advance(2000);
    expect(Socket.instances.map(socket => socket.createdAt - startedAt)).toEqual([0, 1000, 2000, 3000]);
    expect(Socket.instances.slice(1).every(socket => socket.send.mock.calls.length === 0)).toBe(true);
    expect(f.calls('/refresh')).toHaveLength(1); expect(f.calls('/stop')).toHaveLength(0);
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    const count = Socket.instances.length; f.rendered.unmount(); await advance(5000);
    expect(Socket.instances).toHaveLength(count); expect(Socket.instances.at(-1)!.close).toHaveBeenCalledOnce();
    expect(f.calls('/refresh')[0][1]?.signal?.aborted).toBe(true);
  });
  it('preserves an OPEN refresh-wait socket and pairs that exact transport once with the fresh token', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/refresh') ? new Promise<Response>(done => {resolve = done;}) : undefined);
    await act(flush); act(() => {Socket.instances[0].onopen?.(); Socket.instances[0].onclose?.();}); await advance(1000);
    const pending = Socket.instances[1], staleOpen = pending.onopen!;
    act(() => pending.onopen?.()); expect(pending.onmessage).toBeNull(); await advance(6000);
    expect(Socket.instances).toHaveLength(2); expect(pending.close).not.toHaveBeenCalled(); expect(pending.send).not.toHaveBeenCalled();
    await act(async () => {resolve(Response.json({session_id: session.session_id, token: 'new-real-token', remaining_ms: 90000})); await flush();});
    expect(Socket.instances).toHaveLength(2); expect(pending.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'new-real-token', session_id: session.session_id}));
    act(() => {staleOpen(); pending.onopen?.();}); expect(pending.send).toHaveBeenCalledOnce();
    await advance(6000); expect(pending.close).not.toHaveBeenCalled(); expect(f.calls('/refresh')).toHaveLength(1);
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
  });
  it('keeps the unopened deadline after fresh-token handoff and never reuses the spent token', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    const f = setup(path => path.endsWith('/refresh') ? new Promise<Response>(done => {resolve = done;}) : undefined);
    await act(flush); const start = Date.now(); act(() => {Socket.instances[0].onopen?.(); Socket.instances[0].onclose?.();});
    await advance(1750); const pending = Socket.instances[1];
    await act(async () => {resolve(Response.json({session_id: session.session_id, token: 'fresh-unused-token', remaining_ms: 90000})); await flush();});
    const staleOpen = pending.onopen!;
    await advance(249); expect(Socket.instances).toHaveLength(2);
    await advance(1); expect(Socket.instances).toHaveLength(3); expect(Socket.instances[2].createdAt).toBe(start + 2000);
    act(() => {staleOpen(); Socket.instances[2].onopen?.();});
    expect(pending.send).not.toHaveBeenCalled(); expect(Socket.instances[2].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'fresh-unused-token', session_id: session.session_id}));
    expect(f.calls('/refresh')).toHaveLength(1);
  });
  it('retains the retry gap when a fresh token arrives after an early socket failure', async () => {
    vi.useFakeTimers(); let resolve!: (response: Response) => void;
    setup(path => path.endsWith('/refresh') ? new Promise<Response>(done => {resolve = done;}) : undefined);
    await act(flush); const start = Date.now(); act(() => {Socket.instances[0].onopen?.(); Socket.instances[0].onclose?.();});
    await advance(1900); act(() => Socket.instances[1].onerror?.()); await advance(50);
    await act(async () => {resolve(Response.json({session_id: session.session_id, token: 'fresh-after-error', remaining_ms: 90000})); await flush();});
    expect(Socket.instances).toHaveLength(2); await advance(49); expect(Socket.instances).toHaveLength(2);
    await advance(1); expect(Socket.instances[2].createdAt).toBe(start + 2000);
    act(() => Socket.instances[2].onopen?.()); expect(JSON.parse(Socket.instances[2].send.mock.calls[0][0]).token).toBe('fresh-after-error');
  });
  it('lets an immediate manual Connect replace queued startup without creating a duplicate pending socket', async () => {
    vi.useFakeTimers(); network(); const onConnect = vi.fn();
    render(<HelperConnection session={null} address={DEFAULT_HELPER_ADDRESS} onAddress={vi.fn()} onConnect={onConnect} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(Socket.instances).toHaveLength(1); expect(Socket.instances[0].send).not.toHaveBeenCalled(); expect(onConnect).toHaveBeenCalledOnce();
  });
});
