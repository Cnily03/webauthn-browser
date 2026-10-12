import { afterEach, describe, expect, it, vi } from 'vitest';
import { LiveClipboard, MAX_CLIPBOARD_BYTES } from './clipboard';
const tick = async () => { await Promise.resolve(); await Promise.resolve(); };
const deferred = <T,>() => { let resolve!: (v: T) => void, reject!: (e: Error) => void; const promise = new Promise<T>((r, j) => { resolve = r; reject = j; }); return { promise, resolve, reject }; };
function setup(secure = true) {
  const send = vi.fn(), update = vi.fn();
  const port = { readText: vi.fn<() => Promise<string>>().mockResolvedValue('fresh 中文\n🎉'), writeText: vi.fn().mockResolvedValue(undefined), write: vi.fn().mockResolvedValue(undefined) };
  return { send, update, port, sync: new LiveClipboard(send, update, port, secure) };
}
afterEach(() => vi.unstubAllGlobals());
describe('demand-driven clipboard with no retained fallback', () => {
  it('does not read on construction; every SelectionRequest reads fresh including empty/Unicode', async () => {
    const { sync, port, send } = setup(); expect(port.readText).not.toHaveBeenCalled();
    sync.receive({ type: 'read', id: '1' }); await tick();
    expect(send).toHaveBeenLastCalledWith({ type: 'read_result', id: '1', text: 'fresh 中文\n🎉' });
    port.readText.mockResolvedValue(''); sync.receive({ type: 'read', id: '2' }); await tick();
    expect(port.readText).toHaveBeenCalledTimes(2); expect(send).toHaveBeenLastCalledWith({ type: 'read_result', id: '2', text: '' });
  });
  it('writes each remote copy immediately and never reads local clipboard for copy', async () => {
    const { sync, port, send } = setup(); sync.receive({ type: 'copy', id: 'a', text: 'remote' });
    expect(port.writeText).toHaveBeenCalledWith('remote'); expect(port.readText).not.toHaveBeenCalled(); await tick();
    expect(send).toHaveBeenCalledWith({ type: 'copy_result', id: 'a' });
  });
  it('uses a fresh gesture read after denial, without sending a stale value', async () => {
    const { sync, port, send, update } = setup(); port.readText.mockRejectedValueOnce(new Error('denied'));
    sync.receive({ type: 'read', id: 'a' }); await tick(); expect(send).not.toHaveBeenCalled(); expect(update.mock.lastCall?.[0]).toEqual({ kind: 'read', message: '' });
    sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(2); await tick(); expect(send.mock.lastCall?.[0].text).toBe('fresh 中文\n🎉');
  });
  it('does not read without a rejected request or duplicate an in-flight permission attempt', async () => {
    const { sync, port, update } = setup(); const initial = deferred<string>(), retry = deferred<string>();
    port.readText.mockReturnValueOnce(initial.promise).mockReturnValueOnce(retry.promise);
    sync.retryRead(); expect(port.readText).not.toHaveBeenCalled();
    sync.receive({ type: 'read', id: 'a' }); sync.retryRead();
    expect(port.readText).toHaveBeenCalledTimes(1);
    initial.reject(new DOMException('Gesture required', 'NotAllowedError')); await tick();
    sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(2);
    expect(update.mock.lastCall?.[0]).toEqual({ kind: 'ready', message: '' });
    sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(2);
    retry.resolve('fresh'); await tick(); sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(2);
  });
  it('handles a synchronous browser rejection while preserving a direct gesture retry', async () => {
    const { sync, port, send, update } = setup();
    port.readText.mockImplementationOnce(() => { throw new DOMException('Gesture required', 'NotAllowedError'); });
    sync.receive({ type: 'read', id: 'sync-denial' });
    expect(update.mock.lastCall?.[0]).toEqual({ kind: 'read', message: '' });
    sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(2); await tick();
    expect(send).toHaveBeenCalledWith({ type: 'read_result', id: 'sync-denial', text: 'fresh 中文\n🎉' });
  });
  it.each(['newer', 'cancel', 'dispose', 'copy', 'copy_failed'] as const)('does not revive a stale gesture retry after %s', async reason => {
    const { sync, port, send, update } = setup(); const retry = deferred<string>();
    port.readText.mockRejectedValueOnce(new DOMException('Gesture required', 'NotAllowedError')).mockReturnValueOnce(retry.promise);
    sync.receive({ type: 'read', id: 'old' }); await tick(); sync.retryRead();
    if (reason === 'newer') sync.receive({ type: 'read', id: 'new' });
    if (reason === 'cancel') sync.receive({ type: 'cancel', id: 'old' });
    if (reason === 'dispose') sync.dispose();
    if (reason === 'copy') sync.receive({ type: 'copy', id: 'new', text: 'new copy' });
    if (reason === 'copy_failed') sync.receive({ type: 'copy_failed', id: 'new', error: 'unsupported' });
    await tick(); const latestUpdate = update.mock.lastCall?.[0];
    retry.reject(new DOMException('Late denial', 'NotAllowedError')); await tick();
    sync.retryRead();
    expect(port.readText).toHaveBeenCalledTimes(reason === 'newer' ? 3 : 2);
    expect(update.mock.lastCall?.[0]).toEqual(latestUpdate);
    expect(send.mock.calls.some(([frame]) => frame.id === 'old' && typeof frame.text === 'string')).toBe(false);
  });
  it('uses only the newest request ID after an old permission prompt finishes', async () => {
    const { sync, port, send } = setup(); const old = deferred<string>();
    port.readText.mockRejectedValueOnce(new Error('denied')).mockReturnValueOnce(old.promise).mockRejectedValueOnce(new Error('denied')).mockResolvedValueOnce('newest');
    sync.receive({ type: 'read', id: 'old' }); await tick(); sync.retryRead();
    sync.receive({ type: 'read', id: 'new' }); await tick();
    old.resolve('old secret'); await tick();
    sync.retryRead(); await tick();
    expect(send.mock.calls.filter(([frame]) => typeof frame.text === 'string').map(([frame]) => frame)).toEqual([{ type: 'read_result', id: 'new', text: 'newest' }]);
  });
  it.each(['newer', 'cancel', 'dispose', 'copy'] as const)('drops in-flight read after %s', async reason => {
    const { sync, port, send } = setup(); const old = deferred<string>(); port.readText.mockReturnValueOnce(old.promise);
    sync.receive({ type: 'read', id: 'old' });
    if (reason === 'newer') sync.receive({ type: 'read', id: 'new' });
    if (reason === 'cancel') sync.receive({ type: 'cancel', id: 'old' });
    if (reason === 'dispose') sync.dispose();
    if (reason === 'copy') sync.receive({ type: 'copy', id: 'new', text: 'new copy' });
    old.resolve('stale secret'); await tick(); expect(send.mock.calls.some(([f]) => f.text === 'stale secret')).toBe(false);
  });
  it('does not retry a canceled permission request', async () => {
    const { sync, port } = setup(); port.readText.mockRejectedValue(new Error('denied')); sync.receive({ type: 'read', id: 'a' }); await tick();
    sync.receive({ type: 'cancel', id: 'a' }); sync.retryRead(); expect(port.readText).toHaveBeenCalledTimes(1);
  });
  it('fails closed in insecure context without touching the clipboard', async () => {
    const { sync, port, send } = setup(false); sync.receive({ type: 'read', id: 'a' }); await tick();
    expect(port.readText).not.toHaveBeenCalled(); expect(send).toHaveBeenCalledWith({ type: 'read_result', id: 'a', error: 'unavailable' });
  });
  it('fails closed when the browser has no read API without a retry icon state', async () => {
    const send = vi.fn(), update = vi.fn(); const sync = new LiveClipboard(send, update, {} as Clipboard, true);
    sync.receive({ type: 'read', id: 'missing-api' }); await tick(); sync.retryRead();
    expect(send).toHaveBeenCalledExactlyOnceWith({ type: 'read_result', id: 'missing-api', error: 'unavailable' });
    expect(update.mock.lastCall?.[0].kind).toBe('unavailable');
  });
  it('rejects oversize bytes both ways without retaining or writing them', async () => {
    const { sync, port, send } = setup(); const text = '界'.repeat(Math.ceil(MAX_CLIPBOARD_BYTES / 3));
    port.readText.mockResolvedValue(text); sync.receive({ type: 'read', id: 'a' }); await tick();
    expect(send).toHaveBeenCalledWith({ type: 'read_result', id: 'a', error: 'too_large' });
    sync.receive({ type: 'copy', id: 'b', text }); expect(port.writeText).not.toHaveBeenCalled();
  });
  it('shows remote unsupported/oversize copy errors instead of implying old system clipboard was updated', () => {
    const { sync, port, update } = setup(); sync.receive({ type: 'copy_failed', id: 'bad', error: 'too_large' });
    expect(update.mock.lastCall?.[0].message).toContain('未同步'); expect(port.writeText).not.toHaveBeenCalled();
  });
  it('does not publish late copy completion after disconnect', async () => {
    const { sync, port, send, update } = setup(); const pending = deferred<void>(); port.writeText.mockReturnValue(pending.promise);
    sync.receive({ type: 'copy', id: 'a', text: 'value' }); sync.dispose(); pending.resolve(); await tick(); expect(send).not.toHaveBeenCalled(); expect(update).not.toHaveBeenCalled();
  });
  it('suppresses stale write reporting, without pretending already submitted browser writes can be canceled', async () => {
    const { sync, port, send } = setup(); const older = deferred<void>(), newer = deferred<void>();
    port.writeText.mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise);
    sync.receive({ type: 'copy', id: 'older', text: 'older' }); sync.receive({ type: 'copy', id: 'newer', text: 'newer' });
    expect(port.writeText).toHaveBeenCalledTimes(2); newer.resolve(); await tick(); older.resolve(); await tick();
    expect(send.mock.calls.map(([f]) => f.id)).toEqual(['newer']);
  });
  it('reports gesture copy failure only after the browser write rejects', async () => {
    const { sync, port, send } = setup(); const write = deferred<void>();
    vi.stubGlobal('ClipboardItem', class {}); port.write.mockReturnValue(write.promise);
    sync.copyAgain(() => {}); sync.receive({ type: 'copy', id: 'fresh', text: 'fresh' });
    expect(send).not.toHaveBeenCalled(); write.reject(new Error('denied')); await tick();
    expect(send).toHaveBeenCalledWith({ type: 'copy_result', id: 'fresh', error: 'denied' }); sync.dispose();
  });
  it('gesture copy retry starts write before requesting NEW remote copy; never replays failed text', async () => {
    const { sync, port, send } = setup(); let blob!: Promise<Blob>;
    vi.stubGlobal('ClipboardItem', class { constructor(data: Record<string, Promise<Blob>>) { blob = data['text/plain']; } });
    port.writeText.mockRejectedValue(new Error('denied')); sync.receive({ type: 'copy', id: 'old', text: 'discarded' }); await tick();
    const order: string[] = []; port.write.mockImplementation(() => { order.push('write'); return blob.then(() => undefined); });
    sync.copyAgain(() => order.push('remote Copy')); expect(order).toEqual(['write', 'remote Copy']);
    sync.receive({ type: 'copy', id: 'new', text: 'fresh selection' }); expect((await blob).size).toBe(new Blob(['fresh selection']).size); await tick();
    expect(port.writeText).toHaveBeenCalledTimes(1); expect(send).toHaveBeenCalledWith({ type: 'copy_result', id: 'new' }); sync.dispose();
  });
  it('cancels gesture-copy wait on a newer paste without overwriting new status', async () => {
    const { sync, port, update } = setup(); let blob!: Promise<Blob>;
    vi.stubGlobal('ClipboardItem', class { constructor(data: Record<string, Promise<Blob>>) { blob = data['text/plain']; } });
    port.write.mockImplementation(() => blob.then(() => undefined)); sync.copyAgain(() => {});
    sync.receive({ type: 'read', id: 'paste' }); await tick(); expect(update.mock.lastCall?.[0].kind).toBe('ready'); sync.dispose();
  });
});
