import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PendingHelperTransport } from './pendingHelperTransport';

class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;
  send = vi.fn(); close = vi.fn(() => { this.readyState = 3; });
  constructor(public url: string) { Socket.instances.push(this); }
  open() { this.readyState = 1; this.onopen?.(); }
}
const address = 'ws://localhost:10233/';
let controller: PendingHelperTransport;
beforeEach(() => { vi.useFakeTimers(); Socket.instances = []; vi.stubGlobal('WebSocket', Socket); controller = new PendingHelperTransport(); });
afterEach(() => { controller.stop(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('real pending helper transport before backend capability', () => {
  it('constructs promptly and replaces each unopened socket exactly every1s with no extra delay', () => {
    controller.start(address); expect(Socket.instances).toHaveLength(1);
    for (let attempt = 1; attempt <= 3; attempt++) {
      vi.advanceTimersByTime(999); expect(Socket.instances).toHaveLength(attempt);
      vi.advanceTimersByTime(1); expect(Socket.instances).toHaveLength(attempt + 1);
      expect(Socket.instances[attempt - 1].close).toHaveBeenCalledOnce();
    }
    expect(Socket.instances.every(socket => socket.send.mock.calls.length === 0)).toBe(true);
  });
  it.each(['error', 'close'] as const)('uses only the remaining establishment window after a900ms %s', event => {
    const startedAt = Date.now(); controller.start(address); const first = Socket.instances[0];
    vi.advanceTimersByTime(900); if (event === 'error') first.onerror?.(); else first.onclose?.();
    expect(first.close).toHaveBeenCalledOnce(); vi.advanceTimersByTime(99); expect(Socket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1); expect(Socket.instances).toHaveLength(2); expect(Date.now()).toBe(startedAt + 1000);
    expect(controller.take(address)?.startedAt).toBe(startedAt + 1000);
  });
  it('does not kill an OPEN socket while awaiting capability or consume unsolicited paired/data frames', () => {
    controller.start(address); const socket = Socket.instances[0]; socket.open();
    expect(socket.onmessage).toBeNull(); vi.advanceTimersByTime(60000);
    expect(Socket.instances).toHaveLength(1); expect(socket.close).not.toHaveBeenCalled(); expect(socket.send).not.toHaveBeenCalled();
  });
  it('retries server-driven5s pre-pair closure without a client OPEN deadline', () => {
    controller.start(address); const socket = Socket.instances[0]; socket.open();
    vi.advanceTimersByTime(5000); expect(socket.close).not.toHaveBeenCalled(); socket.onclose?.();
    vi.advanceTimersByTime(999); expect(Socket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1); expect(Socket.instances).toHaveLength(2); expect(socket.send).not.toHaveBeenCalled();
  });
  it.each([false, true])('hands off the exact socket once with opened=%s and its original start time', opened => {
    const startedAt = Date.now(); controller.start(address); const socket = Socket.instances[0];
    const staleOpen = socket.onopen!, staleClose = socket.onclose!;
    vi.advanceTimersByTime(700); if (opened) socket.open();
    const handed = controller.take(address);
    expect(handed).toEqual({socket, opened, startedAt}); expect(socket.close).not.toHaveBeenCalled();
    expect(socket.onopen).toBeNull(); expect(socket.onclose).toBeNull(); expect(socket.onmessage).toBeNull();
    staleOpen(); staleClose(); vi.advanceTimersByTime(10000);
    expect(Socket.instances).toHaveLength(1); expect(socket.send).not.toHaveBeenCalled();
    expect(controller.take(address)).toBeNull(); controller.stop(); expect(socket.close).not.toHaveBeenCalled();
  });
  it('invalidates old callbacks across immediate same-address and back/forth replacements', () => {
    controller.start(address); const first = Socket.instances[0]; const lateOpen = first.onopen!, lateError = first.onerror!;
    controller.start(address); expect(first.close).toHaveBeenCalledOnce();
    controller.start('ws://localhost:19000/'); controller.start(address);
    lateOpen(); lateError(); vi.advanceTimersByTime(999);
    expect(Socket.instances).toHaveLength(4); expect(Socket.instances.at(-1)?.url).toBe(address);
    expect(controller.take(address)?.opened).toBe(false);
  });
  it('cannot hand an old-address or already-closed candidate to a new binding', () => {
    controller.start(address); const socket = Socket.instances[0];
    expect(controller.take('ws://localhost:19000/')).toBeNull(); expect(socket.close).toHaveBeenCalledOnce();
    controller.start(address); Socket.instances[1].readyState = 3; expect(controller.take(address)).toBeNull();
    vi.advanceTimersByTime(2000); expect(Socket.instances).toHaveLength(2);
  });
  it.each([false, true])('transfers the remaining retry deadline between attempts, opened=%s', opened => {
    const start = Date.now(); controller.start(address); const socket = Socket.instances[0];
    if (opened) socket.open(); vi.advanceTimersByTime(900); socket.onclose?.(); vi.advanceTimersByTime(50);
    const handed = controller.take(address); expect(handed?.socket).toBeUndefined();
    expect(handed?.retryAt).toBe(start + (opened ? 1900 : 1000));
    vi.advanceTimersByTime(5000); expect(Socket.instances).toHaveLength(1); expect(controller.take(address)).toBeNull();
  });
  it('cancels every timer and ignores late events after stop', () => {
    controller.start(address); const socket = Socket.instances[0], lateClose = socket.onclose!;
    controller.stop(); lateClose(); vi.advanceTimersByTime(60000);
    expect(Socket.instances).toHaveLength(1); expect(socket.close).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
  });
  it('serializes constructor failures with one retry per second and stops them cleanly', () => {
    const constructor = vi.fn(function() { throw new DOMException('blocked', 'SecurityError'); });
    vi.stubGlobal('WebSocket', constructor); controller.start(address); expect(constructor).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(999); expect(constructor).toHaveBeenCalledOnce();
    vi.advanceTimersByTime(1); expect(constructor).toHaveBeenCalledTimes(2);
    controller.stop(); vi.advanceTimersByTime(5000); expect(constructor).toHaveBeenCalledTimes(2);
  });
});
