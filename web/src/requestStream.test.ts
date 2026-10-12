import { afterEach, describe, expect, it, vi } from 'vitest';
import { consumeRequestEvents, requestIdentity, RequestStream, validateSnapshot, type RequestSnapshot } from './requestStream';

const snapshot = (cursor = 'stream:1'): RequestSnapshot => ({connected: true, cursor, requests: []});
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
function source() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const response = new Response(new ReadableStream<Uint8Array>({start(value) { controller = value; }}), {headers: {'Content-Type': 'text/event-stream'}});
  return {response, controller, send: (text: string) => controller.enqueue(new TextEncoder().encode(text))};
}
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe('request event parser', () => {
  it('decodes split UTF-8 and CRLF, and ignores lifecycle events and SSE ids', async () => {
    const controller = new AbortController();
    const received = vi.fn(() => controller.abort());
    const data = new TextEncoder().encode('id: untrusted\r\nevent: approved\r\ndata: {}\r\n\r\n: heartbeat\r\nevent: snapshot\r\ndata: {"connected":true,"cursor":"valid:1","requests":[{"id":"测试"}]}\r\n\r\n');
    let index = 0;
    const response = new Response(new ReadableStream({pull(stream) { if (index < data.length) stream.enqueue(data.slice(index, ++index)); }}));
    await consumeRequestEvents(response, {signal: controller.signal, current: () => true, onActivity: vi.fn(), onSnapshot: received});
    expect(received).toHaveBeenCalledOnce();
    expect(received).toHaveBeenCalledWith({connected: true, cursor: 'valid:1', requests: [{id: '测试'}]});
  });
  it('rejects injected cursors and malformed snapshots', () => {
    for (const value of [null, {}, {...snapshot(), cursor: ''}, {...snapshot(), cursor: 'id\nheader'}, {...snapshot(), connected: 'yes'}, {...snapshot(), requests: {}},
      {...snapshot(), control_connected: 'true'}, {...snapshot(), native_qr_mode: 1}, {...snapshot(), mode_switching: null}, {...snapshot(), mode_error: 1}, {...snapshot(), mode_error: 'arbitrary'}]) {
      expect(() => validateSnapshot(value)).toThrow('验证事件格式无效');
    }
  });
  it('accepts the exact extension upgrade status but rejects lookalikes', () => {
    const upgrade = {...snapshot(), connected: false, mode_error: 'extension_upgrade_required'};
    expect(validateSnapshot(upgrade)).toEqual(upgrade);
    for (const mode_error of ['extension_upgrade_required_extra', 'extension_upgrade_required\n', 'extension_upgrade']) {
      expect(() => validateSnapshot({...upgrade, mode_error})).toThrow('验证事件格式无效');
    }
  });
  it('recognizes session-lock events without JSON data', async () => {
    const feed = source(); feed.send('event: locked\n\n');
    await expect(consumeRequestEvents(feed.response, {signal: new AbortController().signal, current: () => true, onActivity: vi.fn(), onSnapshot: vi.fn()})).rejects.toMatchObject({status: 401});
  });
  it('bounds buffered and multi-line event payloads', async () => {
    for (const content of ['x'.repeat(2 * 1024 * 1024 + 1), 'event: snapshot\ndata: ' + 'x'.repeat(1024 * 1024 + 1) + '\ndata: ' + 'y'.repeat(1024 * 1024) + '\n\n']) {
      const feed = source(); feed.send(content);
      await expect(consumeRequestEvents(feed.response, {signal: new AbortController().signal, current: () => true, onActivity: vi.fn(), onSnapshot: vi.fn()})).rejects.toThrow('验证事件过大');
    }
  });
  it('ignores countdown-only updates but includes authorization metadata', () => {
    expect(requestIdentity({id: 'a', remaining_ms: 10, candidates: [{key_id: 'k', remaining_ms: 5}]})).toBe(requestIdentity({id: 'a', remaining_ms: 9, candidates: [{key_id: 'k', remaining_ms: 4}]}));
    expect(requestIdentity({id: 'a', origin: 'https://one'})).not.toBe(requestIdentity({id: 'a', origin: 'https://two'}));
  });
});

describe('request stream lifecycle', () => {
  function fixture() {
    const feeds: ReturnType<typeof source>[] = [];
    const fetcher = vi.fn(() => { const feed = source(); feeds.push(feed); return Promise.resolve(feed.response); });
    const refreshStatus = vi.fn(async () => ({vnc_authenticated: true, csrf_token: `csrf-${fetcher.mock.calls.length}`}));
    const onSnapshot = vi.fn();
    const onUnauthorized = vi.fn();
    const onConnection = vi.fn();
    const stream = new RequestStream({refreshStatus, onSnapshot, onUnauthorized, onConnection, fetch: fetcher as typeof fetch});
    return {stream, feeds, fetcher, refreshStatus, onSnapshot, onUnauthorized, onConnection};
  }
  it.each([
    [{control_connected: true, native_qr_mode: true, mode_switching: false}, 'connected', '原生验证模式'],
    [{control_connected: false, native_qr_mode: true, mode_switching: false}, 'offline', '验证引擎连接已断开'],
    [{control_connected: true, native_qr_mode: false, mode_switching: false}, 'offline', '虚拟验证器未就绪'],
    [{control_connected: true, native_qr_mode: true, mode_switching: true}, 'connecting', '验证模式切换中…'],
    [{control_connected: false, native_qr_mode: true, mode_switching: true}, 'offline', '验证引擎连接已断开'],
    [{control_connected: true, mode_switching: true, mode_error: 'native_mode_timeout'}, 'offline', '原生验证模式切换失败：浏览器未确认切换，正在恢复…'],
    [{control_connected: true, mode_switching: false, mode_error: 'proxy_mode_timeout'}, 'offline', '验证器拦截恢复失败：浏览器未确认切换，请重新启动容器浏览器后重试'],
    [{control_connected: true, mode_error: 'native_mode_api_error'}, 'offline', '原生验证模式切换失败：浏览器报告错误，请重新启动容器浏览器后重试'],
    [{control_connected: true, mode_error: 'extension_upgrade_required'}, 'offline', '浏览器验证扩展版本过旧或不兼容，请等待扩展重新加载；若仍未恢复，请更新并重新创建容器，保留现有数据卷'],
    [{control_connected: false, mode_error: 'extension_upgrade_required'}, 'offline', '浏览器验证扩展版本过旧或不兼容，请等待扩展重新加载；若仍未恢复，请更新并重新创建容器，保留现有数据卷'],
    [{native_qr_mode: true}, 'offline', '虚拟验证器未就绪'],
  ] as const)('reports engine status %j without authorizing software requests', (status, state, message) => {
    const f = fixture();
    f.stream.applySnapshot(snapshot());
    const ticket = f.stream.ticket();
    const next = {...snapshot('stream:2'), connected: false, ...status};
    f.stream.applySnapshot(next);
    expect(f.onConnection).toHaveBeenLastCalledWith(state, message);
    expect(f.onSnapshot).toHaveBeenLastCalledWith(next);
    expect(f.stream.ready).toBe(false);
    expect(f.stream.accepts(ticket)).toBe(false);
    expect(f.stream.accepts(f.stream.ticket())).toBe(false);
    f.stream.applySnapshot(snapshot('stream:3'));
    expect(f.onConnection).toHaveBeenLastCalledWith('connected', '验证事件已连接');
    expect(f.stream.accepts(ticket)).toBe(false);
    expect(f.stream.accepts(f.stream.ticket())).toBe(true);
  });
  it('an upgrade error overrides connected flags and revokes pending authorization', () => {
    const f = fixture();
    f.stream.applySnapshot(snapshot());
    const ticket = f.stream.ticket();
    f.stream.applySnapshot({...snapshot('stream:2'), control_connected: true, native_qr_mode: true, mode_error: 'extension_upgrade_required'});
    expect(f.stream.ready).toBe(false);
    expect(f.stream.accepts(ticket)).toBe(false);
    expect(f.stream.accepts(f.stream.ticket())).toBe(false);
    expect(f.onConnection).toHaveBeenLastCalledWith('offline', expect.stringContaining('浏览器验证扩展版本过旧或不兼容'));
  });
  it('revokes choices on a gap, revalidates CSRF and resumes with only validated cursor', async () => {
    vi.useFakeTimers();
    const f = fixture(); f.stream.start(); await flush();
    f.feeds[0].send('id: poison\nevent: snapshot\ndata: ' + JSON.stringify(snapshot('trusted:5')) + '\n\n'); await flush();
    const ticket = f.stream.ticket(); expect(f.stream.accepts(ticket)).toBe(true);
    f.feeds[0].controller.error(new Error('offline')); await flush();
    expect(f.stream.accepts(ticket)).toBe(false);
    expect(f.onSnapshot).toHaveBeenLastCalledWith(null);
    await vi.advanceTimersByTimeAsync(500);
    expect(f.refreshStatus).toHaveBeenCalledTimes(2);
    expect(f.fetcher).toHaveBeenLastCalledWith('/api/requests/events', expect.objectContaining({credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'text/event-stream', 'X-CSRF-Token': 'csrf-1', 'Last-Event-ID': 'trusted:5'}}));
    f.stream.stop();
  });
  it('revokes a stalled stream after 45 seconds, and reconnects without approving', async () => {
    vi.useFakeTimers();
    const f = fixture(); f.stream.start(); await flush();
    f.feeds[0].send('event: snapshot\ndata: ' + JSON.stringify(snapshot()) + '\n\n'); await flush();
    const ticket = f.stream.ticket();
    await vi.advanceTimersByTimeAsync(45000);
    expect(f.stream.accepts(ticket)).toBe(false);
    expect(f.onConnection).toHaveBeenLastCalledWith('disconnected', '验证事件已断开，正在重连…');
    await vi.advanceTimersByTimeAsync(500); expect(f.fetcher).toHaveBeenCalledTimes(2);
    f.stream.stop();
  });
  it('invalidates resync choices and rejects stale recovery snapshots', async () => {
    const f = fixture(); f.stream.start(); await flush();
    f.stream.applySnapshot(snapshot()); const ticket = f.stream.ticket();
    f.stream.applySnapshot({...snapshot('stream:2'), resync: true});
    expect(f.stream.accepts(ticket)).toBe(false);
    f.stream.applyRecoverySnapshot(snapshot('old:1'), ticket, 'stream:2');
    expect(f.stream.cursor).toBe('stream:2');
    const current = f.stream.ticket();
    f.stream.applyRecoverySnapshot(snapshot('old:2'), current, 'stream:1');
    expect(f.stream.cursor).toBe('stream:2');
    f.stream.stop();
  });
  it('does not fetch from a status refresh that belongs to an old generation', async () => {
    let resolve!: (status: {vnc_authenticated: boolean; csrf_token: string}) => void;
    const fetcher = vi.fn();
    const stream = new RequestStream({refreshStatus: () => new Promise(done => { resolve = done; }), onSnapshot: vi.fn(), onConnection: vi.fn(), onUnauthorized: vi.fn(), fetch: fetcher});
    stream.start(); stream.stop(); resolve({vnc_authenticated: true, csrf_token: 'old'}); await flush();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('stops on locked or unauthorized sessions instead of reconnecting', async () => {
    vi.useFakeTimers();
    const f = fixture(); f.stream.start(); await flush();
    f.feeds[0].send('event: locked\n\n'); await flush();
    expect(f.onUnauthorized).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(60000); expect(f.fetcher).toHaveBeenCalledOnce();
    f.stream.stop();
  });
});

describe('live authenticated local navigation events', () => {
  const hint = {id: 'stream:1', url: 'http://localhost:5555/callback?token=test-only#keep', remaining_ms: 5000, mode_generation: 4};
  const navigationSnapshot = (values: Partial<RequestSnapshot> = {}) => ({...snapshot(), control_connected: true, mode_generation: 4, ...values});
  function fixture() {
    const feeds: ReturnType<typeof source>[] = [];
    const received = vi.fn(); const unauthorized = vi.fn();
    const fetcher = vi.fn(() => {const feed = source(); feeds.push(feed); return Promise.resolve(feed.response);});
    const stream = new RequestStream({refreshStatus: async () => ({vnc_authenticated: true, csrf_token: 'navigation-csrf'}), onSnapshot: vi.fn(), onConnection: vi.fn(), onUnauthorized: unauthorized, onLocalNavigation: received, fetch: fetcher as typeof fetch});
    const send = async (event: string, value: unknown) => {feeds.at(-1)!.send(`event: ${event}\ndata: ${JSON.stringify(value)}\n\n`); await flush();};
    return {stream, feeds, received, unauthorized, fetcher, send};
  }
  it('requires an authenticated stream and matching current snapshot without altering the approval cursor', async () => {
    const f = fixture(); f.stream.start(); await flush(); f.received.mockClear();
    await f.send('local_navigation', hint); expect(f.received).not.toHaveBeenCalled();
    await f.send('snapshot', navigationSnapshot()); f.received.mockClear();
    await f.send('local_navigation', {...hint, mode_generation: 3}); expect(f.received).not.toHaveBeenCalled();
    await f.send('local_navigation', {...hint, id: 'previous-instance:999'}); expect(f.received).not.toHaveBeenCalled();
    await f.send('local_navigation', hint); expect(f.received).toHaveBeenCalledExactlyOnceWith(hint);
    expect(f.stream.cursor).toBe('stream:1');
    expect(f.fetcher).toHaveBeenCalledWith('/api/requests/events', expect.objectContaining({credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'text/event-stream', 'X-CSRF-Token': 'navigation-csrf'}}));
    f.stream.stop();
  });
  it('supports actual native control state without enabling software approval and preserves the prompt on ordinary countdown snapshots', async () => {
    const f = fixture(); f.stream.start(); await flush();
    const native = navigationSnapshot({connected: false, native_qr_mode: true, browser_mode: 'native'});
    await f.send('snapshot', native); f.received.mockClear(); await f.send('local_navigation', hint);
    expect(f.received).toHaveBeenLastCalledWith(hint); expect(f.stream.ready).toBe(false);
    f.received.mockClear(); await f.send('snapshot', {...native, cursor: 'stream:2'});
    expect(f.received).not.toHaveBeenCalled();
    await f.send('local_navigation_clear', {mode_generation: 3}); expect(f.received).not.toHaveBeenCalled();
    await f.send('local_navigation_clear', {mode_generation: 4}); expect(f.received).toHaveBeenCalledExactlyOnceWith(null);
    f.stream.stop();
  });
  it.each([{cursor: 'new-instance:1'}, {mode_generation: 5}, {mode_switching: true}, {control_connected: false}, {mode_error: 'native_mode_timeout'}, {resync: true}] as Partial<RequestSnapshot>[])('clears an offered URL on the boundary %j', async boundary => {
    const f = fixture(); f.stream.start(); await flush(); await f.send('snapshot', navigationSnapshot()); await f.send('local_navigation', hint); f.received.mockClear();
    await f.send('snapshot', navigationSnapshot(boundary)); expect(f.received).toHaveBeenCalledWith(null);
    f.stream.stop();
  });
  it('clears on a transport gap and lock, and does not replay history/snapshot payloads on reconnection', async () => {
    vi.useFakeTimers(); const f = fixture(); f.stream.start(); await flush(); await f.send('snapshot', navigationSnapshot()); await f.send('local_navigation', hint);
    f.received.mockClear(); f.feeds[0].controller.error(new Error('test interruption')); await flush(); expect(f.received).toHaveBeenCalledWith(null);
    await vi.advanceTimersByTimeAsync(500); f.received.mockClear();
    await f.send('snapshot', {...navigationSnapshot(), events: [{type: 'local_navigation', ...hint}], local_navigation: hint});
    expect(f.received.mock.calls.every(([value]) => value === null)).toBe(true);
    f.received.mockClear(); await f.send('local_navigation', {...hint, id: 'stream:2'}); expect(f.received).toHaveBeenLastCalledWith({...hint, id: 'stream:2'});
    f.feeds.at(-1)!.send('event: locked\n\n'); await flush(); expect(f.received).toHaveBeenLastCalledWith(null); expect(f.unauthorized).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(60000); expect(f.fetcher).toHaveBeenCalledTimes(2);
    f.stream.stop();
  });
  it('ignores malformed local events without echoing targets or disrupting the credential stream', async () => {
    const f = fixture(); f.stream.start(); await flush(); await f.send('snapshot', navigationSnapshot()); f.received.mockClear();
    for (const value of [null, {}, {...hint, url: 'http://evil.test/'}, {...hint, remaining_ms: -1}, {...hint, mode_generation: '4'}]) await f.send('local_navigation', value);
    f.feeds[0].send('event: local_navigation\ndata: not-json\n\nevent: local_navigation_clear\ndata: nope\n\n'); await flush();
    expect(f.received).not.toHaveBeenCalled(); expect(f.stream.ready).toBe(true); f.stream.stop();
  });
  it('never delivers a body resolved after its authenticated connection was stopped', async () => {
    const feed = source(); let resolve!: (value: Response) => void; const received = vi.fn();
    const stream = new RequestStream({refreshStatus: async () => ({vnc_authenticated: true, csrf_token: 'csrf'}), fetch: vi.fn(() => new Promise<Response>(done => {resolve = done;})), onSnapshot: vi.fn(), onConnection: vi.fn(), onUnauthorized: vi.fn(), onLocalNavigation: received});
    stream.start(); await flush(); stream.stop(); received.mockClear();
    feed.send(`event: snapshot\ndata: ${JSON.stringify(navigationSnapshot())}\n\nevent: local_navigation\ndata: ${JSON.stringify(hint)}\n\n`); resolve(feed.response); await flush();
    expect(received).not.toHaveBeenCalled();
  });
});
