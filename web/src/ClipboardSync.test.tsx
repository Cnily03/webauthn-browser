import { useState, type ReactElement } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ClipboardSync } from './ClipboardSync';
import { renderMaterial } from './test-render';
import { ApiError, browserTransportUrl } from './api';
const profile = vi.hoisted(() => ({name: null as string | null, headers: {} as Record<string, string>}));
vi.mock('./profiles', () => ({browserProfileName: () => profile.name, profileViewerHeaders: () => profile.headers}));
vi.mock('./api', async importOriginal => ({...await importOriginal<typeof import('./api')>(), browserTransportUrl: vi.fn()}));
beforeEach(() => { profile.name = null; profile.headers = {}; vi.mocked(browserTransportUrl).mockReset(); });
class Socket {
  static OPEN = 1;
  static instances: Socket[] = [];
  readyState = 1;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  send = vi.fn(); close = vi.fn();
  constructor(public url: URL) { Socket.instances.push(this); }
  receive(frame: unknown) { this.onmessage?.({ data: JSON.stringify(frame) }); }
}
afterEach(() => { vi.unstubAllGlobals(); Socket.instances = []; });
function setup() {
  vi.stubGlobal('WebSocket', Socket); vi.stubGlobal('isSecureContext', true);
  const readText = vi.fn().mockRejectedValue(new DOMException('A fresh gesture is required', 'NotAllowedError'));
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { readText, writeText: vi.fn().mockResolvedValue(undefined) } });
  let replace!: (element: ReactElement) => void;
  function Harness() { const [element, setElement] = useState(<ClipboardSync connected copyAgain={vi.fn()} />); replace = setElement; return element; }
  const view = renderMaterial(<Harness />);
  const socket = Socket.instances[0]; return { ...view, rerender: (element: ReactElement) => act(() => replace(element)), socket, readText };
}
describe('MUI clipboard permission and lifecycle', () => {
  it('lets the browser handle the initial read without showing a permission banner', async () => {
    const { socket, readText } = setup(); let resolve!: (value: string) => void;
    readText.mockReturnValue(new Promise<string>(r => { resolve = r; }));
    act(() => {
      socket.receive({ type: 'read', id: 'native-prompt' });
      expect(readText).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () => resolve('current'));
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'read_result', id: 'native-prompt', text: 'current' }));
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it('uses an icon-only fallback and calls readText synchronously in its click handler', async () => {
    const { socket, readText } = setup(); expect(readText).not.toHaveBeenCalled();
    await act(async () => socket.receive({ type: 'read', id: 'p' }));
    const paste = screen.getByRole('button', { name: '粘贴剪贴板内容' });
    expect(paste).toHaveTextContent('');
    expect(paste.querySelector('svg')).not.toBeNull();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/允许本次粘贴/)).not.toBeInTheDocument();
    let resolve!: (value: string) => void;
    readText.mockReturnValue(new Promise<string>(r => { resolve = r; }));
    act(() => {
      fireEvent.click(paste);
      // No microtask/permissions.query is allowed before the browser API call.
      expect(readText).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    await act(async () => resolve('latest'));
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'read_result', id: 'p', text: 'latest' }));
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
  it('retains an actionable ended-paste message instead of treating it as ordinary success', async () => {
    const {socket} = setup();
    await act(async () => socket.receive({type: 'read', id: 'expired'}));
    expect(screen.getByRole('button', {name: '粘贴剪贴板内容'})).toBeVisible();
    await act(async () => socket.receive({type: 'cancel', id: 'expired'}));
    expect(screen.queryByRole('button', {name: '粘贴剪贴板内容'})).not.toBeInTheDocument();
    expect(screen.getByRole('img', {name: '粘贴已结束'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
    await act(async () => socket.receive({type: 'copy', id: 'success', text: 'new'}));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
  it.each(['unmount', 'pagehide', 'disconnect'] as const)('drops late permission response on %s', async mode => {
    const { socket, readText, unmount } = setup(); let resolve!: (value: string) => void;
    readText.mockReturnValue(new Promise<string>(r => { resolve = r; }));
    act(() => socket.receive({ type: 'read', id: 'p' }));
    act(() => { if (mode === 'unmount') unmount(); if (mode === 'pagehide') window.dispatchEvent(new Event('pagehide')); if (mode === 'disconnect') socket.onclose?.(); });
    await act(async () => resolve('secret')); expect(socket.send).not.toHaveBeenCalled();
  });
  it.each(['unmount', 'pagehide', 'disconnect'] as const)('drops late icon-click permission rejection on %s', async mode => {
    const { socket, readText, unmount } = setup();
    await act(async () => socket.receive({ type: 'read', id: 'p' }));
    let reject!: (error: Error) => void;
    readText.mockReturnValue(new Promise<string>((_, r) => { reject = r; }));
    act(() => fireEvent.click(screen.getByRole('button', { name: '粘贴剪贴板内容' })));
    act(() => { if (mode === 'unmount') unmount(); if (mode === 'pagehide') window.dispatchEvent(new Event('pagehide')); if (mode === 'disconnect') socket.onclose?.(); });
    await act(async () => reject(new DOMException('Permission denied', 'NotAllowedError')));
    expect(screen.queryByRole('button', { name: '粘贴剪贴板内容' })).not.toBeInTheDocument();
    expect(readText).toHaveBeenCalledTimes(2);
    expect(socket.send).not.toHaveBeenCalled();
  });
  it('removes an available fallback on pagehide without reading again', async () => {
    const { socket, readText } = setup();
    await act(async () => socket.receive({ type: 'read', id: 'p' }));
    expect(screen.getByRole('button', { name: '粘贴剪贴板内容' })).toBeVisible();
    act(() => window.dispatchEvent(new Event('pagehide')));
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(readText).toHaveBeenCalledTimes(1);
  });
  it('fails closed in an insecure context without offering a permission retry', async () => {
    vi.stubGlobal('isSecureContext', false);
    vi.stubGlobal('WebSocket', Socket);
    const readText = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { readText } });
    renderMaterial(<ClipboardSync connected copyAgain={vi.fn()} />);
    await act(async () => Socket.instances[0].receive({ type: 'read', id: 'insecure' }));
    expect(readText).not.toHaveBeenCalled();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByRole('img', {name: '剪贴板不可用'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
    expect(Socket.instances[0].send).toHaveBeenCalledWith(JSON.stringify({ type: 'read_result', id: 'insecure', error: 'unavailable' }));
  });
  it('handles synchronous websocket policy rejection without crashing the page', () => {
    vi.stubGlobal('WebSocket', class { constructor() { throw new Error('SecurityError'); } });
    renderMaterial(<ClipboardSync connected copyAgain={vi.fn()} />);
    expect(screen.getByRole('img', {name: '剪贴板连接不可用'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
  });
  it('shows connection failure and never retries permission reads in background', async () => {
    const { socket, readText } = setup(); act(() => socket.onclose?.());
    expect(screen.getByRole('img', {name: '剪贴板已断开'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull(); expect(readText).not.toHaveBeenCalled();
  });
  it('recovers a clipboard-only disconnect after hours without reloading or reading in the background', async () => {
    vi.useFakeTimers();
    const {socket, readText} = setup();
    act(() => socket.onopen?.());
    await act(async () => vi.advanceTimersByTime(6 * 60 * 60 * 1000));
    expect(Socket.instances).toHaveLength(1);
    const oldMessage = socket.onmessage;
    act(() => socket.onclose?.());
    await act(async () => vi.advanceTimersByTime(500));
    expect(Socket.instances).toHaveLength(2);
    const replacement = Socket.instances[1];
    await act(async () => { replacement.onopen?.(); replacement.receive({type: 'copy', id: 'new', text: 'new copy'}); });
    expect(replacement.send).toHaveBeenCalledWith(JSON.stringify({type: 'copy_result', id: 'new'}));
    act(() => oldMessage?.({data: JSON.stringify({type: 'read', id: 'stale'})}));
    expect(readText).not.toHaveBeenCalled();
    expect(screen.queryByRole('img', {name: '剪贴板已断开'})).not.toBeInTheDocument();
  });
  it('drops a late read after reconnect and handles a fresh paste independently', async () => {
    vi.useFakeTimers();
    const {socket, readText} = setup();
    let finish!: (value: string) => void;
    readText.mockReturnValueOnce(new Promise<string>(resolve => { finish = resolve; }));
    act(() => { socket.onopen?.(); socket.receive({type: 'read', id: 'old'}); socket.onclose?.(); });
    await act(async () => vi.advanceTimersByTime(500));
    readText.mockResolvedValue('fresh');
    const replacement = Socket.instances[1];
    await act(async () => { replacement.onopen?.(); replacement.receive({type: 'read', id: 'fresh'}); finish('stale'); });
    expect(socket.send).not.toHaveBeenCalled();
    expect(replacement.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'read_result', id: 'fresh', text: 'fresh'}));
  });
  it.each(['unmount', 'pagehide', 'ownership loss'] as const)('cancels scheduled recovery on %s', async reason => {
    vi.useFakeTimers();
    const {socket, unmount, rerender} = setup();
    act(() => socket.onclose?.());
    act(() => {
      if (reason === 'unmount') unmount();
      else if (reason === 'pagehide') window.dispatchEvent(new Event('pagehide'));
      else rerender(<ClipboardSync connected={false} copyAgain={vi.fn()} />);
    });
    await act(async () => vi.advanceTimersByTime(60000));
    expect(Socket.instances).toHaveLength(1);
  });
  it('times out a stuck opening socket and backs off repeated failures', async () => {
    vi.useFakeTimers();
    const {socket} = setup();
    await act(async () => vi.advanceTimersByTime(1000));
    expect(socket.close).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTime(500));
    expect(Socket.instances).toHaveLength(2);
    act(() => Socket.instances[1].onerror?.());
    await act(async () => vi.advanceTimersByTime(999));
    expect(Socket.instances).toHaveLength(2);
    await act(async () => vi.advanceTimersByTime(1));
    expect(Socket.instances).toHaveLength(3);
  });
  it('keeps backing off when a bridge repeatedly closes immediately after opening', async () => {
    vi.useFakeTimers(); const {socket} = setup();
    act(() => { socket.onopen?.(); socket.onclose?.(); });
    await act(async () => vi.advanceTimersByTime(500));
    act(() => { Socket.instances[1].onopen?.(); Socket.instances[1].onclose?.(); });
    await act(async () => vi.advanceTimersByTime(500));
    expect(Socket.instances).toHaveLength(2);
    await act(async () => vi.advanceTimersByTime(500));
    expect(Socket.instances).toHaveLength(3);
  });
  it('requests a fresh single-use profile ticket on every reconnect', async () => {
    vi.useFakeTimers(); profile.name = 'work'; profile.headers = {'X-Viewer-Token': 'owner', 'X-Owner-Generation': '1'};
    vi.mocked(browserTransportUrl).mockResolvedValueOnce(new URL('ws://localhost/p/work/api/clipboard/ws?ticket=one'))
      .mockResolvedValueOnce(new URL('ws://localhost/p/work/api/clipboard/ws?ticket=two'));
    setup(); await act(async () => {});
    act(() => { Socket.instances[0].onopen?.(); Socket.instances[0].onclose?.(); });
    await act(async () => vi.advanceTimersByTime(500));
    expect(browserTransportUrl).toHaveBeenCalledTimes(2);
    expect(Socket.instances[1].url.searchParams.get('ticket')).toBe('two');
  });
  it.each([401, 403])('does not retry revoked admission (%s)', async status => {
    vi.useFakeTimers(); profile.name = 'work';
    vi.mocked(browserTransportUrl).mockRejectedValue(new ApiError('revoked', status));
    setup(); await act(async () => {});
    await act(async () => vi.advanceTimersByTime(60000));
    expect(browserTransportUrl).toHaveBeenCalledTimes(1); expect(Socket.instances).toHaveLength(0);
  });
  it('does not adopt a changed viewer during a queued reconnect', async () => {
    vi.useFakeTimers();
    const {socket} = setup(); act(() => socket.onclose?.());
    profile.headers = {'X-Viewer-Token': 'successor', 'X-Owner-Generation': '2'};
    await act(async () => vi.advanceTimersByTime(500));
    expect(Socket.instances).toHaveLength(1);
  });
  it('resets the clipboard alone for a new ownership generation', async () => {
    const {socket, rerender, readText} = setup();
    const staleMessage = socket.onmessage;
    profile.headers = {'X-Viewer-Token': 'successor', 'X-Owner-Generation': '2'};
    rerender(<ClipboardSync connected sessionKey="viewer:2" copyAgain={vi.fn()} />);
    expect(socket.close).toHaveBeenCalledTimes(1); expect(Socket.instances).toHaveLength(2);
    act(() => staleMessage?.({data: JSON.stringify({type: 'read', id: 'stale'})}));
    expect(readText).not.toHaveBeenCalled();
  });
  it('blocks an old fallback click immediately when viewer identity changes', async () => {
    const {socket, readText} = setup();
    await act(async () => socket.receive({type: 'read', id: 'old'}));
    const fallback = screen.getByRole('button', {name: '粘贴剪贴板内容'});
    profile.headers = {'X-Viewer-Token': 'successor', 'X-Owner-Generation': '2'};
    fireEvent.click(fallback);
    expect(readText).toHaveBeenCalledTimes(1);
  });
  it('ignores a ticket response that arrives after teardown', async () => {
    profile.name = 'work'; let finish!: (url: URL) => void;
    vi.mocked(browserTransportUrl).mockReturnValue(new Promise<URL>(resolve => { finish = resolve; }));
    const {unmount} = setup(); unmount();
    await act(async () => finish(new URL('ws://localhost/?ticket=stale')));
    expect(Socket.instances).toHaveLength(0);
  });

});
