import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ClipboardSync } from './ClipboardSync';
import { renderMaterial } from './test-render';
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
  const view = renderMaterial(<ClipboardSync connected copyAgain={vi.fn()} />);
  const socket = Socket.instances[0]; return { ...view, socket, readText };
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
});
