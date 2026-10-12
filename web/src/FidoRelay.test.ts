import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FidoRelay, validFidoReport } from './FidoRelay';
import { setCsrfToken } from './api';
const relayId = 'r'.repeat(43);
const connectionId = 'c'.repeat(43);
const data = btoa(String.fromCharCode(...Array.from({length: 64}, (_, i) => i)));
const binding = {session_id: 'session-1', generation: 7, relay_id: relayId, helper_connection_id: connectionId};
const enabled = {paired: true, nativeReady: true, backendAvailable: true};
const MAX_MESSAGE_REPORTS = 129;
const MAX_QUEUE = 2 * MAX_MESSAGE_REPORTS;
// A genuine maximal CTAPHID framing fixture; production forwarding stays opaque.
const maxMessage = (offset = 0) => Array.from({length: MAX_MESSAGE_REPORTS}, (_, index) => {
  const bytes = new Uint8Array(64).fill(index);
  bytes.set([1, 2, 3, 4]);
  if (index === 0) bytes.set([0x81, 0x1d, 0xb9], 4); // PING, 7,609-byte opaque payload.
  else bytes[4] = index - 1;
  return {sequence: offset + index, data: btoa(String.fromCharCode(...bytes))};
});

const availability = (extra = {}) => ({type: 'fido_available', experimental_fido: true, version: 1, relay_id: relayId, helper_connection_id: connectionId, remaining_ms: 30000, ...extra});
const ready = (extra = {}) => ({type: 'fido_ready', version: 1, relay_id: relayId, ...extra});
const renewed = (lease_sequence = 1, extra = {}) => ({type: 'fido_renewed', version: 1, relay_id: relayId, lease_sequence, remaining_ms: 30000, ...extra});
const report = (sequence = 0, extra = {}) => ({type: 'fido_report', version: 1, relay_id: relayId, sequence, data, ...extra});
const flush = async () => { for (let i = 0; i < 25; i++) await Promise.resolve(); };
const deferred = () => { let resolve!: (value: Response) => void; let reject!: (error: unknown) => void; const promise = new Promise<Response>((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };
function setup(override?: (path: string, body: any, init: RequestInit) => Promise<Response> | undefined) {
  const socket = {readyState: 1 as const, bufferedAmount: 0, send: vi.fn(), close: vi.fn()};
  const onError = vi.fn(); const onStatus = vi.fn(); let live = true;
  const fetcher = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const path = String(input); const body = JSON.parse(String(init.body));
    const custom = override?.(path, body, init); if (custom) return custom;
    if (path.endsWith('/open')) return Response.json({version: 1, relay_id: body.relay_id, remaining_ms: 30000});
    if (path.endsWith('/exchange')) return Response.json({version: 1, relay_id: body.relay_id, exchange_sequence: body.exchange_sequence, reports: [], remaining_ms: 30000});
    if (path.endsWith('/renew')) return Response.json({version: 1, relay_id: body.relay_id, lease_sequence: body.lease_sequence, remaining_ms: body.remaining_ms});
    return Response.json({ok: true});
  });
  vi.stubGlobal('fetch', fetcher); setCsrfToken('csrf');
  const adapter = new FidoRelay({socket, ...binding, live: () => live, onError, onStatus});
  const calls = (suffix: string) => fetcher.mock.calls.filter(([path]) => String(path).endsWith(suffix));
  const bodies = (suffix: string) => calls(suffix).map(([, init]) => JSON.parse(String(init?.body)));
  const frames = () => socket.send.mock.calls.map(([frame]) => JSON.parse(frame));
  const open = async () => { adapter.update(enabled); adapter.receive(availability()); await flush(); };
  const start = async () => { await open(); adapter.receive(ready()); await flush(); };
  return {adapter, socket, onError, onStatus, fetcher, calls, bodies, frames, open, start, stale: () => { live = false; }};
}
beforeEach(() => vi.useFakeTimers());
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('opaque experimental FIDO adapter', () => {
  it('requires all endpoint and native gates; retains same-socket availability until native readiness', async () => {
    const f = setup();
    f.adapter.update({paired: false, nativeReady: true, backendAvailable: true});
    f.adapter.receive(availability()); await flush(); expect(f.fetcher).not.toHaveBeenCalled();
    f.adapter.update({paired: true, nativeReady: false, backendAvailable: false}); f.adapter.receive(availability());
    f.adapter.update({paired: true, nativeReady: true, backendAvailable: false}); await flush(); expect(f.fetcher).not.toHaveBeenCalled();
    f.adapter.update(enabled); await flush();
    expect(f.bodies('/open')).toEqual([binding]);
    expect(f.calls('/open')[0][1]).toMatchObject({method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: {'X-CSRF-Token': 'csrf'}});
    expect(f.frames()).toEqual([{type: 'fido_open', version: 1, relay_id: relayId, remaining_ms: 30000}]);
    f.adapter.update(enabled); f.adapter.receive(availability()); await flush();
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(0);
  });
  it('leaves BLE/default sessions untouched without real supplied availability', async () => {
    const f = setup(); f.adapter.update(enabled);
    for (const value of [null, {}, {type: 'status', state: 'paired'}, {type: 'advertisement', data: 'AQID'}]) expect(f.adapter.receive(value)).toBe(false);
    await vi.advanceTimersByTimeAsync(60000);
    expect(f.fetcher).not.toHaveBeenCalled(); expect(f.socket.send).not.toHaveBeenCalled(); expect(f.socket.close).not.toHaveBeenCalled();
  });
  it('opens from launcher readiness only with real helper availability and all live native gates', async () => {
    const f = setup();
    const launcher = {...enabled, backendAvailable: false, backendLauncherReady: true};
    f.adapter.update(launcher); await flush(); expect(f.calls('/open')).toHaveLength(0);
    f.adapter.update({...launcher, nativeReady: false}); f.adapter.receive(availability()); await flush(); expect(f.calls('/open')).toHaveLength(0);
    f.adapter.update(launcher); await flush(); expect(f.bodies('/open')).toEqual([binding]);
    f.adapter.update({...launcher, backendLauncherReady: false}); await flush(); expect(f.calls('/cancel')).toHaveLength(1);
  });
  it('reports USB waiting separately from errors and clears it only for genuine readiness or attachment removal', async () => {
    const f = setup(); const unavailable = {...enabled, backendAvailable: false, backendLauncherReady: false};
    f.adapter.update(unavailable);
    expect(f.onStatus).toHaveBeenLastCalledWith('');
    f.adapter.receive(availability()); await flush();
    expect(f.onStatus).toHaveBeenLastCalledWith('实验性 USB 通道尚未就绪；辅助程序配对和蓝牙仍可使用。');
    const count = f.onStatus.mock.calls.length;
    f.adapter.update(unavailable); expect(f.onStatus).toHaveBeenCalledTimes(count);
    expect(f.onError).not.toHaveBeenCalled(); expect(f.calls('/open')).toHaveLength(0);
    f.adapter.update({...unavailable, backendLauncherReady: true}); await flush();
    expect(f.onStatus).toHaveBeenLastCalledWith(''); expect(f.calls('/open')).toHaveLength(1);
    expect(f.onError).not.toHaveBeenCalled();
    const g = setup(); g.adapter.update(unavailable); g.adapter.receive(availability());
    g.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId});
    expect(g.onStatus).toHaveBeenLastCalledWith(''); expect(g.onError).not.toHaveBeenCalled();
  });
  it('forwards opaque reports in both directions with serial exchanges and batches of eight', async () => {
    const pending = deferred();
    const f = setup((path, body) => path.endsWith('/exchange') && body.exchange_sequence === 0 ? pending.promise : undefined);
    await f.start();
    for (let i = 0; i < 10; i++) f.adapter.receive(report(i));
    await vi.advanceTimersByTimeAsync(1000); expect(f.calls('/exchange')).toHaveLength(1);
    pending.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 0, reports: [{sequence: 0, data}, {sequence: 1, data}], remaining_ms: 28000})); await flush();
    expect(f.frames().filter(v => v.type === 'fido_report')).toEqual([report(0), report(1)]);
    await vi.advanceTimersByTimeAsync(19); expect(f.calls('/exchange')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); await flush();
    expect(f.bodies('/exchange')[1]).toEqual({...binding, exchange_sequence: 1, reports: Array.from({length: 8}, (_, sequence) => ({sequence, data}))});
    await vi.advanceTimersByTimeAsync(20); await flush();
    expect(f.bodies('/exchange')[2].reports).toEqual([{sequence: 8, data}, {sequence: 9, data}]);
    expect(f.bodies('/exchange')[2].exchange_sequence).toBe(2);
  });
  it.each([
    {data: btoa('x'.repeat(63))}, {data: btoa('x'.repeat(65))}, {data: data.slice(0, -3) + 'B=='},
    {data: data.replace(/=/g, '')}, {data: ' '.repeat(88)}, {data: '_'.repeat(86) + '=='},
    {sequence: -1}, {sequence: '0'}, {sequence: 0.5}, {sequence: Number.MAX_SAFE_INTEGER}, {extra: true},
  ])('rejects invalid report shape/encoding %j', extra => { expect(validFidoReport({sequence: 0, data, ...extra})).toBe(false); });
  it('accepts exactly 64 arbitrary opaque bytes without interpreting content', () => {
    expect(validFidoReport({sequence: 0, data})).toBe(true);
    expect(validFidoReport({sequence: 0, data: btoa('\xff'.repeat(64))})).toBe(true);
  });
  it.each([
    {version: '1'}, {version: 2}, {experimental_fido: 'true'}, {remaining_ms: 0}, {remaining_ms: 30001}, {remaining_ms: 1.5},
    {relay_id: 'short'}, {helper_connection_id: 'bad'}, {relay_id: '/'.repeat(43)}, {extra: true},
  ])('rejects malformed availability without opening %j', async extra => {
    const f = setup(); f.adapter.update(enabled); f.adapter.receive(availability(extra)); await flush();
    expect(f.calls('/open')).toHaveLength(0); expect(f.onError).toHaveBeenCalledOnce(); expect(f.socket.close).not.toHaveBeenCalled();
  });
  it.each([
    {version: 2}, {relay_id: 'x'.repeat(43)}, {sequence: 1}, {sequence: '0'}, {data: 'secret malformed payload'}, {extra: true},
  ])('closes only the experimental relay for invalid incoming frame %j', async extra => {
    const f = setup(); await f.start(); f.adapter.receive(report(0, extra)); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.onError).toHaveBeenCalledOnce(); expect(f.socket.close).not.toHaveBeenCalled();
    expect(f.onError.mock.calls.flat().join()).not.toContain('secret malformed payload');
  });
  it('rejects replayed incoming sequence and duplicate ready', async () => {
    const f = setup(); await f.start(); f.adapter.receive(report(0)); f.adapter.receive(report(0)); await flush(); expect(f.calls('/cancel')).toHaveLength(1);
    const g = setup(); await g.start(); g.adapter.receive(ready()); await flush(); expect(g.calls('/cancel')).toHaveLength(1);
  });
  it('rejects reports before ready without exchanging', async () => {
    const f = setup(); await f.open(); f.adapter.receive(report()); await flush(); expect(f.calls('/exchange')).toHaveLength(0); expect(f.calls('/cancel')).toHaveLength(1);
  });
  it.each([
    {version: '1'}, {relay_id: 'x'.repeat(43)}, {exchange_sequence: 1}, {remaining_ms: 0}, {remaining_ms: 30001}, {reports: null},
    {reports: [{sequence: 1, data}]}, {reports: [{sequence: 0, data}, {sequence: 0, data}]},
    {reports: Array.from({length: 9}, (_, sequence) => ({sequence, data}))}, {reports: [{sequence: 0, data: 'bad'}]}, {extra: true},
  ])('validates full exchange response before sending any report %j', async extra => {
    const f = setup(path => path.endsWith('/exchange') ? Promise.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 0, reports: [{sequence: 0, data}], remaining_ms: 30000, ...extra})) : undefined);
    await f.start(); expect(f.calls('/cancel')).toHaveLength(1); expect(f.frames().filter(v => v.type === 'fido_report')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1000); expect(f.calls('/exchange')).toHaveLength(1);
  });
  it.each([{version: '1'}, {relay_id: 'x'.repeat(43)}, {remaining_ms: 0}, {remaining_ms: 30001}, {extra: true}])('rejects invalid open response %j', async extra => {
    const f = setup(path => path.endsWith('/open') ? Promise.resolve(Response.json({version: 1, relay_id: relayId, remaining_ms: 30000, ...extra})) : undefined);
    await f.open(); expect(f.calls('/cancel')).toHaveLength(1); expect(f.frames().some(v => v.type === 'fido_open')).toBe(false);
  });
  it.each([401, 403, 409, 429, 500])('never retries an uncertain or rejected report exchange: HTTP %i', async status => {
    const f = setup(path => path.endsWith('/exchange') ? Promise.resolve(Response.json({error: 'server secret'}, {status})) : undefined);
    await f.start(); await vi.advanceTimersByTimeAsync(1000); f.adapter.update(enabled); f.adapter.receive(availability()); await flush();
    expect(f.calls('/exchange')).toHaveLength(1); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.onError.mock.calls.flat().join()).not.toContain('server secret'); expect(f.socket.close).not.toHaveBeenCalled();
  });
  it('does not replay reports after a lost response', async () => {
    const f = setup(path => path.endsWith('/exchange') ? Promise.reject(new Error('private report')) : undefined);
    await f.start(); await vi.advanceTimersByTimeAsync(1000); expect(f.calls('/exchange')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.onError.mock.calls.flat().join()).not.toContain('private report');
  });
  it('aborts in-flight open on close and ignores its late response', async () => {
    const pending = deferred(); const f = setup(path => path.endsWith('/open') ? pending.promise : undefined);
    await f.open(); const signal = f.calls('/open')[0][1]?.signal; f.adapter.close(); f.adapter.close();
    expect(signal?.aborted).toBe(true); expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/cancel')[0][1]?.keepalive).toBe(true);
    pending.resolve(Response.json({version: 1, relay_id: relayId, remaining_ms: 30000})); await flush();
    expect(f.frames().some(v => v.type === 'fido_open')).toBe(false); expect(f.calls('/exchange')).toHaveLength(0);
  });
  it('aborts in-flight exchange and ignores late reports after native mode is lost', async () => {
    const pending = deferred(); const f = setup(path => path.endsWith('/exchange') ? pending.promise : undefined); await f.start();
    const signal = f.calls('/exchange')[0][1]?.signal; f.adapter.update({...enabled, nativeReady: false}); expect(signal?.aborted).toBe(true);
    pending.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 0, reports: [{sequence: 0, data}], remaining_ms: 30000})); await flush();
    f.adapter.update(enabled); await vi.advanceTimersByTimeAsync(1000);
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(1); expect(f.frames().some(v => v.type === 'fido_report')).toBe(false);
  });
  it('closes on queue overflow without closing BLE or replaying queued reports', async () => {
    const pending = deferred(); const f = setup(path => path.endsWith('/exchange') ? pending.promise : undefined); await f.start();
    for (let i = 0; i < MAX_QUEUE; i++) f.adapter.receive(report(i)); expect(f.calls('/cancel')).toHaveLength(0);
    f.adapter.receive(report(MAX_QUEUE)); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/exchange')).toHaveLength(1); expect(f.socket.close).not.toHaveBeenCalled();
  });
  it('bounds socket buffered bytes before either open or reports are sent', async () => {
    const f = setup(); f.socket.bufferedAmount = 65536; await f.open(); expect(f.socket.send).not.toHaveBeenCalled(); expect(f.calls('/cancel')).toHaveLength(1);
    const pending = deferred(); const g = setup(path => path.endsWith('/exchange') ? pending.promise : undefined); await g.start(); g.socket.bufferedAmount = 65530;
    pending.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 0, reports: [{sequence: 0, data}], remaining_ms: 30000})); await flush();
    expect(g.calls('/cancel')).toHaveLength(1); expect(g.frames().some(v => v.type === 'fido_report')).toBe(false); expect(g.socket.close).not.toHaveBeenCalled();
  });
  it.each(['open', 'ready', 'exchange'])('times out a stalled %s without retry', async stage => {
    const pending = deferred(); const f = setup(path => path.endsWith(`/${stage}`) ? pending.promise : undefined);
    await f.open(); if (stage === 'exchange') { f.adapter.receive(ready()); await flush(); }
    await vi.advanceTimersByTimeAsync(5000); await flush(); expect(f.calls('/cancel')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(5000); expect(f.calls('/open')).toHaveLength(1); expect(f.socket.close).not.toHaveBeenCalled();
  });
  it('never extends an availability deadline with status polling or server leases', async () => {
    const f = setup(); f.adapter.update(enabled); f.adapter.receive(availability({remaining_ms: 100})); await flush(); f.adapter.receive(ready()); await flush();
    await vi.advanceTimersByTimeAsync(99); expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1); expect(f.calls('/cancel')).toHaveLength(1);
  });
  it('does not retain expired or helper-closed pending availability', async () => {
    const f = setup(); f.adapter.update({...enabled, nativeReady: false}); f.adapter.receive(availability({remaining_ms: 10})); await vi.advanceTimersByTimeAsync(11); f.adapter.update(enabled); await flush(); expect(f.calls('/open')).toHaveLength(0);
    const g = setup(); g.adapter.update({...enabled, nativeReady: false}); g.adapter.receive(availability()); g.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId}); g.adapter.update(enabled); await flush(); expect(g.calls('/open')).toHaveLength(0);
  });
  it('requires fresh local attachment after close, serializes cancellation, and ignores late old frames', async () => {
    const pending = deferred(); const f = setup(path => path.endsWith('/cancel') ? pending.promise : undefined); await f.start();
    const second = 'n'.repeat(43); f.adapter.receive(availability({relay_id: second})); await flush(); expect(f.calls('/open')).toHaveLength(1);
    expect(f.calls('/cancel')).toHaveLength(1);
    f.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId}); f.adapter.receive(report());
    pending.resolve(Response.json({ok: true})); await flush(); expect(f.calls('/open')).toHaveLength(2);
    f.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId}); f.adapter.receive(report());
    f.adapter.receive(ready({relay_id: second})); await flush(); expect(f.calls('/exchange')).toHaveLength(2); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.bodies('/exchange')[1].exchange_sequence).toBe(0);
  });
  it.each(['success', 'rejection'])('bounds a hung cancel, accepts a fresh explicit attachment after expiry, and ignores late %s', async outcome => {
    const canceled = deferred();
    const f = setup(path => path.endsWith('/cancel') ? canceled.promise : undefined);
    await f.start();
    f.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId}); await flush();
    expect(f.calls('/cancel')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(30001);
    const replacement = 'n'.repeat(43);
    f.adapter.receive(availability({relay_id: replacement})); await flush();
    expect(f.calls('/open')).toHaveLength(2);
    expect(f.calls('/cancel')[0][1]?.signal?.aborted).toBe(true);
    expect(f.calls('/cancel')[0][1]?.keepalive).toBe(true);
    f.adapter.receive(ready({relay_id: replacement})); await flush();
    const exchanges = f.calls('/exchange').length;
    if (outcome === 'success') canceled.resolve(Response.json({ok: true}));
    else canceled.reject(new Error('late cancel transport error'));
    await flush();
    f.adapter.receive(report(0)); // Delayed bytes from the terminal old attachment.
    await vi.advanceTimersByTimeAsync(20);
    expect(f.calls('/open')).toHaveLength(2); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.bodies('/exchange').at(-1)).toMatchObject({relay_id: replacement, reports: []});
    expect(f.calls('/exchange').length).toBeGreaterThan(exchanges);
    expect(f.onError).not.toHaveBeenCalled();
  });

  it('does not bypass a live backend lease or retry a rejected fresh attachment after cancel timeout', async () => {
    const canceled = deferred(); const rejected = 'n'.repeat(43); const replacement = 'p'.repeat(43);
    const f = setup((path, body) => {
      if (path.endsWith('/cancel') && body.relay_id === relayId) return canceled.promise;
      if (path.endsWith('/open') && body.relay_id === rejected) return Promise.resolve(Response.json({error: 'Existing relay is still live'}, {status: 409}));
      return undefined;
    });
    await f.start();
    f.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId}); await flush();
    await vi.advanceTimersByTimeAsync(5000);
    f.adapter.receive(availability({relay_id: rejected})); await flush();
    expect(f.calls('/open')).toHaveLength(2);
    expect(f.frames().filter(frame => frame.type === 'fido_open').map(frame => frame.relay_id)).toEqual([relayId]);
    f.adapter.receive(availability({relay_id: rejected})); f.adapter.update(enabled);
    await vi.advanceTimersByTimeAsync(25001); expect(f.calls('/open')).toHaveLength(2);
    f.adapter.receive(availability({relay_id: replacement})); await flush();
    f.adapter.receive(ready({relay_id: replacement})); await flush();
    expect(f.calls('/open')).toHaveLength(3);
    expect(f.bodies('/exchange').at(-1)).toMatchObject({relay_id: replacement, exchange_sequence: 0, reports: []});
    canceled.resolve(Response.json({ok: true})); await flush();
    expect(f.calls('/open')).toHaveLength(3); expect(f.onError).toHaveBeenCalledOnce();
  });

  it('pins connection IDs to the socket and cannot attach through stale live callback', async () => {
    const f = setup(); await f.open(); f.adapter.receive(availability({relay_id: 'n'.repeat(43), helper_connection_id: 'x'.repeat(43)})); await flush(); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(1);
    const g = setup(); g.stale(); g.adapter.update(enabled); g.adapter.receive(availability()); await flush(); expect(g.fetcher).not.toHaveBeenCalled();
  });
  it('invalid binary/oversized/unparseable socket traffic only stops an active experimental relay', async () => {
    const f = setup(); f.adapter.invalidFrame(); expect(f.onError).not.toHaveBeenCalled(); await f.start(); f.adapter.invalidFrame(); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.socket.close).not.toHaveBeenCalled();
  });
});

describe('bounded renewable experimental FIDO adapter', () => {
  const beginRenewal = async (f: ReturnType<typeof setup>) => {
    // A short initial grant keeps malformed/timeout test cases focused. Renewals
    // themselves request the normal maximum, still bounded by both peers.
    f.adapter.update(enabled); f.adapter.receive(availability({remaining_ms: 2000})); await flush();
    f.adapter.receive(ready()); await flush(); await vi.advanceTimersByTimeAsync(1000);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toEqual([
      {type: 'fido_renew', version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 30000},
    ]);
  };

  it('renews the same attachment beyond 30 seconds with strictly increasing lease and exchange sequences', async () => {
    const f = setup(); await f.start();
    await vi.advanceTimersByTimeAsync(15000);
    expect(f.calls('/renew')).toHaveLength(0);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toEqual([
      {type: 'fido_renew', version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 30000},
    ]);
    f.adapter.receive(renewed()); await flush();
    await vi.advanceTimersByTimeAsync(15000);
    expect(f.frames().filter(frame => frame.type === 'fido_renew').map(frame => frame.lease_sequence)).toEqual([1, 2]);
    f.adapter.receive(renewed(2)); await flush(); await vi.advanceTimersByTimeAsync(1000);
    expect(f.bodies('/renew')).toEqual([1, 2].map(lease_sequence => ({...binding, lease_sequence, remaining_ms: 30000})));
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0); expect(f.onError).not.toHaveBeenCalled();
    expect(f.bodies('/exchange').every((body, index) => body.exchange_sequence === index)).toBe(true);
    expect(f.socket.close).not.toHaveBeenCalled();
  });

  it('forwards reports during both renewal ACKs with serial exchanges and unchanged sequences', async () => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    const previousExchanges = f.calls('/exchange').length;
    for (let i = 0; i < 5; i++) f.adapter.receive(report(i));
    await vi.advanceTimersByTimeAsync(100);
    expect(f.calls('/exchange').length).toBeGreaterThan(previousExchanges);
    f.adapter.receive(renewed()); await flush();
    for (let i = 5; i < 10; i++) f.adapter.receive(report(i));
    await vi.advanceTimersByTimeAsync(100);
    expect(f.bodies('/exchange').flatMap(body => body.reports)).toEqual(Array.from({length: 10}, (_, sequence) => ({sequence, data})));
    pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 29900})); await flush();
    await vi.advanceTimersByTimeAsync(20);
    expect(f.bodies('/exchange').every((body, index) => body.exchange_sequence === index)).toBe(true);
    expect(f.calls('/renew')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
  });

  it.each(['normal', 'helper', 'backend'])('delivers a maximal 129-report message exactly once during %s without waiting for renewal ACKs', async stage => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined);
    if (stage === 'normal') await f.start();
    else {
      await beginRenewal(f);
      if (stage === 'backend') { f.adapter.receive(renewed()); await flush(); }
    }
    const message = maxMessage();
    for (const frame of message) f.adapter.receive({type: 'fido_report', version: 1, relay_id: relayId, ...frame});
    expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(400);
    expect(f.bodies('/exchange').flatMap(body => body.reports)).toEqual(message);
    expect(f.bodies('/exchange').every(body => body.reports.length <= 8)).toBe(true);
    expect(f.calls('/cancel')).toHaveLength(0); expect(f.onError).not.toHaveBeenCalled();
    if (stage !== 'normal') {
      if (stage === 'helper') { f.adapter.receive(renewed()); await flush(); }
      pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 29000})); await flush();
    }
    // A later authenticator operation on the same live attachment keeps ordering.
    const second = maxMessage(message.length);
    for (const frame of second) f.adapter.receive({type: 'fido_report', version: 1, relay_id: relayId, ...frame});
    await vi.advanceTimersByTimeAsync(400);
    expect(f.bodies('/exchange').flatMap(body => body.reports)).toEqual([...message, ...second]);
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
  });

  it('keeps slow-touch-like opaque reports flowing beyond 30 seconds, then delivers a full response and another operation', async () => {
    const f = setup((path, body) => path.endsWith('/renew') ? new Promise(resolve => {
      setTimeout(() => resolve(Response.json({version: 1, relay_id: body.relay_id, lease_sequence: body.lease_sequence, remaining_ms: body.remaining_ms - 200})), 200);
    }) : undefined);
    f.socket.send.mockImplementation(raw => {
      const frame = JSON.parse(raw);
      if (frame.type === 'fido_renew') setTimeout(() => f.adapter.receive(renewed(frame.lease_sequence)), 200);
    });
    await f.start();
    const expected = [];
    const bytes = new Uint8Array(64); bytes.set([1, 2, 3, 4, 0xbb, 0, 1, 2]);
    const keepaliveData = btoa(String.fromCharCode(...bytes));
    for (let sequence = 0; sequence < 350; sequence++) {
      const frame = {sequence, data: keepaliveData}; expected.push(frame);
      f.adapter.receive({type: 'fido_report', version: 1, relay_id: relayId, ...frame});
      await vi.advanceTimersByTimeAsync(100);
    }
    for (let operation = 0; operation < 2; operation++) {
      const message = maxMessage(expected.length); expected.push(...message);
      for (const frame of message) f.adapter.receive({type: 'fido_report', version: 1, relay_id: relayId, ...frame});
      await vi.advanceTimersByTimeAsync(400);
    }
    expect(f.bodies('/exchange').flatMap(body => body.reports)).toEqual(expected);
    expect(f.bodies('/renew').map(body => body.lease_sequence)).toEqual([1, 2]);
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
    expect(f.onError).not.toHaveBeenCalled();
  });

  it('retains a new two-peer lease when an older exchange completes after renewal', async () => {
    const exchange = deferred();
    const f = setup((path, body) => path.endsWith('/exchange') && body.exchange_sequence === 50 ? exchange.promise : undefined);
    await beginRenewal(f);
    f.adapter.receive(renewed()); await flush();
    await vi.advanceTimersByTimeAsync(100);
    exchange.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 50, reports: [], remaining_ms: 1000})); await flush();
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.calls('/cancel')).toHaveLength(0); expect(f.onError).not.toHaveBeenCalled();
    expect(f.calls('/exchange').length).toBeGreaterThan(51);
  });

  it('does not let a renewal ACK clear a concurrent stalled exchange timeout', async () => {
    const exchange = deferred();
    const f = setup((path, body) => path.endsWith('/exchange') && body.exchange_sequence === 750 ? exchange.promise : undefined);
    await f.start(); await vi.advanceTimersByTimeAsync(15000);
    f.adapter.receive(renewed()); await flush();
    await vi.advanceTimersByTimeAsync(4999); expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1); expect(f.calls('/cancel')).toHaveLength(1);
    exchange.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 750, reports: [{sequence: 0, data}], remaining_ms: 30000})); await flush();
    expect(f.frames().some(frame => frame.type === 'fido_report')).toBe(false);
  });

  it('waits for a preexisting exchange before sending helper renewal', async () => {
    const pending = deferred();
    const f = setup((path, body) => path.endsWith('/exchange') && body.exchange_sequence === 49 ? pending.promise : undefined);
    f.adapter.update(enabled); f.adapter.receive(availability({remaining_ms: 3000})); await flush(); f.adapter.receive(ready()); await flush();
    await vi.advanceTimersByTimeAsync(1600);
    expect(f.frames().some(frame => frame.type === 'fido_renew')).toBe(false);
    expect(f.calls('/exchange')).toHaveLength(50);
    pending.resolve(Response.json({version: 1, relay_id: relayId, exchange_sequence: 49, reports: [], remaining_ms: 2020})); await flush();
    await vi.advanceTimersByTimeAsync(20);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    expect(f.calls('/exchange')).toHaveLength(51);
  });

  it('subtracts helper and backend roundtrips and renews from the conservative acknowledged deadline', async () => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    await vi.advanceTimersByTimeAsync(100); f.adapter.receive(renewed(1, {remaining_ms: 1000})); await flush();
    expect(f.bodies('/renew')).toEqual([{...binding, lease_sequence: 1, remaining_ms: 900}]);
    await vi.advanceTimersByTimeAsync(100);
    pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 700})); await flush();
    // Helper deadline 2000, backend conservative deadline 1800. From ACK at
    // 1200, the next renewal is at 1500 (not 1550 or 1600).
    await vi.advanceTimersByTimeAsync(299); expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(299); expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1); expect(f.calls('/cancel')).toHaveLength(1);
  });

  it.each(['helper', 'backend'])('keeps the old expiry armed until the %s renewal ACK finishes', async stage => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    if (stage === 'backend') { f.adapter.receive(renewed()); await flush(); }
    await vi.advanceTimersByTimeAsync(999); expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1); expect(f.calls('/cancel')).toHaveLength(1);
    if (stage === 'backend') {
      expect(f.calls('/renew')[0][1]?.signal?.aborted).toBe(true);
      pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 30000})); await flush();
    } else f.adapter.receive(renewed());
    await vi.advanceTimersByTimeAsync(30000); expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/open')).toHaveLength(1);
  });

  it.each(['helper', 'backend'])('times out %s renewal after five seconds without retrying or affecting BLE', async stage => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await f.start(); await vi.advanceTimersByTimeAsync(15000);
    if (stage === 'backend') { f.adapter.receive(renewed()); await flush(); }
    await vi.advanceTimersByTimeAsync(4999); expect(f.calls('/cancel')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1); expect(f.calls('/cancel')).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(30000);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    expect(f.calls('/renew')).toHaveLength(stage === 'backend' ? 1 : 0);
    expect(f.onError).toHaveBeenCalledOnce(); expect(f.socket.close).not.toHaveBeenCalled();
  });

  it.each([
    {version: '1'}, {version: 2}, {relay_id: 'x'.repeat(43)}, {lease_sequence: 0}, {lease_sequence: 2},
    {lease_sequence: '1'}, {lease_sequence: 1.5}, {remaining_ms: 0}, {remaining_ms: 30001}, {remaining_ms: 1.5}, {extra: true},
  ])('rejects invalid helper renewal ACK %j before the backend can renew', async extra => {
    const f = setup(); await beginRenewal(f); f.adapter.receive(renewed(1, extra)); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/renew')).toHaveLength(0); expect(f.onError).toHaveBeenCalledOnce();
  });

  it.each([
    {version: '1'}, {version: 2}, {relay_id: 'x'.repeat(43)}, {lease_sequence: 0}, {lease_sequence: 2},
    {lease_sequence: '1'}, {remaining_ms: 0}, {remaining_ms: 30001}, {remaining_ms: 1.5}, {extra: true},
  ])('rejects invalid backend renewal ACK %j and cancels both peers', async extra => {
    const f = setup(path => path.endsWith('/renew') ? Promise.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 30000, ...extra})) : undefined);
    await beginRenewal(f); f.adapter.receive(renewed()); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/renew')).toHaveLength(1);
    expect(f.frames().filter(frame => frame.type === 'fido_close')).toHaveLength(1); expect(f.socket.close).not.toHaveBeenCalled();
  });

  it.each(['early', 'pending', 'completed', 'next'])('rejects %s helper renewal ACK replays', async stage => {
    const pending = deferred();
    const f = setup(path => path.endsWith('/renew') && stage === 'pending' ? pending.promise : undefined);
    if (stage === 'early') await f.start();
    else {
      await beginRenewal(f);
      f.adapter.receive(renewed()); await flush();
      if (stage === 'next') await vi.advanceTimersByTimeAsync(15000);
    }
    f.adapter.receive(renewed()); await flush();
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/renew')).toHaveLength(stage === 'early' ? 0 : 1);
  });

  it.each(['helper', 'backend'])('keeps the queue limit at 258 during %s renewal', async stage => {
    const pending = deferred(); const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    if (stage === 'backend') { f.adapter.receive(renewed()); await flush(); }
    for (let i = 0; i < MAX_QUEUE; i++) f.adapter.receive(report(i)); expect(f.calls('/cancel')).toHaveLength(0);
    f.adapter.receive(report(MAX_QUEUE)); await flush(); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.bodies('/exchange').every(body => body.reports.length === 0)).toBe(true);
  });

  it.each(['paired', 'nativeReady', 'backendAvailable', 'live', 'close'])('cancels a renewal when %s becomes invalid and ignores late completion', async gate => {
    const pending = deferred(); const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    f.adapter.receive(renewed()); await flush();
    if (gate === 'close') f.adapter.close();
    else { if (gate === 'live') f.stale(); f.adapter.update({...enabled, ...(gate === 'live' ? {} : {[gate]: false})}); }
    expect(f.calls('/renew')[0][1]?.signal?.aborted).toBe(true);
    pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 30000})); await flush();
    f.adapter.update(enabled); await vi.advanceTimersByTimeAsync(30000);
    expect(f.calls('/cancel')).toHaveLength(1); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/renew')).toHaveLength(1);
  });

  it.each([401, 403, 409, 429, 500, 'lost'])('does not retry an ambiguous or rejected backend renewal: %s', async status => {
    const f = setup(path => path.endsWith('/renew') ? (status === 'lost' ? Promise.reject(new Error('private renewal details')) : Promise.resolve(Response.json({error: 'private renewal details'}, {status: status as number}))) : undefined);
    await beginRenewal(f); f.adapter.receive(renewed()); await flush(); await vi.advanceTimersByTimeAsync(30000);
    f.adapter.update(enabled); f.adapter.receive(availability()); await flush();
    expect(f.calls('/renew')).toHaveLength(1); expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(1);
    expect(f.onError.mock.calls.flat().join()).not.toContain('private renewal details');
  });

  it('rejects helper ACKs whose entire grant was consumed by transit', async () => {
    const f = setup(); await beginRenewal(f); await vi.advanceTimersByTimeAsync(100);
    f.adapter.receive(renewed(1, {remaining_ms: 100})); await flush();
    expect(f.calls('/renew')).toHaveLength(0); expect(f.calls('/cancel')).toHaveLength(1);
  });

  it('rejects backend ACKs whose entire grant was consumed by transit', async () => {
    const pending = deferred(); const f = setup(path => path.endsWith('/renew') ? pending.promise : undefined); await beginRenewal(f);
    f.adapter.receive(renewed()); await flush(); await vi.advanceTimersByTimeAsync(100);
    pending.resolve(Response.json({version: 1, relay_id: relayId, lease_sequence: 1, remaining_ms: 100})); await flush();
    expect(f.calls('/cancel')).toHaveLength(1);
  });
});

describe('Native offer renewal before genuine browser HID readiness', () => {
  const waiting = {...enabled, backendAvailable: false, backendLauncherReady: false};
  function offered() {
    const f = setup(); f.adapter.update(waiting); f.adapter.receive(availability()); return f;
  }
  it('keeps a Native offer alive beyond45 seconds, then opens with separate monotonic helper/native counters', async () => {
    const f = offered();
    for (let lease = 1; lease <= 3; lease++) {
      await vi.advanceTimersByTimeAsync(15000);
      expect(f.frames().at(-1)).toEqual({type: 'fido_renew', version: 1, relay_id: relayId, lease_sequence: lease, remaining_ms: 30000});
      f.adapter.receive(renewed(lease)); await flush();
    }
    expect(f.fetcher).not.toHaveBeenCalled();
    expect(f.frames().some(frame => frame.type === 'fido_report' || frame.type === 'fido_open')).toBe(false);
    f.adapter.update({...waiting, backendLauncherReady: true}); await flush();
    expect(f.bodies('/open')).toEqual([binding]);
    expect(f.frames().filter(frame => frame.type === 'fido_open')).toHaveLength(1);
    f.adapter.receive(ready()); await flush();
    // First opaque authentication traffic, then another request/cancel-shaped
    // report. This adapter must preserve bytes/sequences without parsing CTAP.
    f.adapter.receive(report(0)); await vi.advanceTimersByTimeAsync(20); await flush();
    expect(f.bodies('/exchange').at(-1).reports).toEqual([{sequence: 0, data}]);
    f.adapter.update({...waiting, backendLauncherReady: true}); // Settings navigation leaves live Native authorization intact.
    const other = btoa('\x91'.repeat(64));
    f.adapter.receive(report(1, {data: other})); await vi.advanceTimersByTimeAsync(20); await flush();
    expect(f.bodies('/exchange').at(-1).reports).toEqual([{sequence: 1, data: other}]);
    await vi.advanceTimersByTimeAsync(14960);
    expect(f.frames().filter(frame => frame.type === 'fido_renew').at(-1).lease_sequence).toBe(4);
    f.adapter.receive(renewed(4)); await flush();
    expect(f.bodies('/renew')).toEqual([{...binding, lease_sequence: 1, remaining_ms: 30000}]);
    await vi.advanceTimersByTimeAsync(15000); f.adapter.receive(renewed(5)); await flush();
    expect(f.bodies('/renew').map(body => body.lease_sequence)).toEqual([1, 2]);
    expect(f.calls('/open')).toHaveLength(1); expect(f.calls('/cancel')).toHaveLength(0);
    expect(f.onError).not.toHaveBeenCalled();
  });
  it('waits for a pending offer ACK before opening after late READY and accounts for helper transit', async () => {
    const f = offered(); await vi.advanceTimersByTimeAsync(15000);
    f.adapter.update({...waiting, backendLauncherReady: true}); await flush();
    expect(f.calls('/open')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(250); f.adapter.receive(renewed(1, {remaining_ms: 20000})); await flush();
    expect(f.calls('/open')).toHaveLength(1);
    expect(f.frames().filter(frame => frame.type === 'fido_open')[0].remaining_ms).toBe(19750);
    f.adapter.receive(ready()); await flush();
    expect(f.calls('/exchange')).toHaveLength(1); expect(f.onError).not.toHaveBeenCalled();
  });
  it('does not postpone the waiting renewal on repeated status polling', async () => {
    const f = offered();
    for (let i = 0; i < 15; i++) { f.adapter.update(waiting); await vi.advanceTimersByTimeAsync(1000); }
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    expect(f.calls('/open')).toHaveLength(0);
  });
  it('never renews or opens an offer without confirmed Native authorization', async () => {
    const f = setup(); f.adapter.update({...waiting, nativeReady: false}); f.adapter.receive(availability());
    await vi.advanceTimersByTimeAsync(30000);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(0);
    expect(f.fetcher).not.toHaveBeenCalled();
    f.adapter.update(enabled); await flush(); expect(f.calls('/open')).toHaveLength(0);
  });
  it.each(['native', 'paired', 'live', 'close', 'detach'])('terminates pending unopened renewal on%s and ignores its late ACK', async cause => {
    const f = offered(); await vi.advanceTimersByTimeAsync(15000);
    if (cause === 'close') f.adapter.close();
    else if (cause === 'detach') f.adapter.receive({type: 'fido_close', version: 1, relay_id: relayId});
    else { if (cause === 'live') f.stale(); f.adapter.update({...waiting, ...(cause === 'native' ? {nativeReady: false} : cause === 'paired' ? {paired: false} : {})}); }
    f.adapter.receive(renewed()); f.adapter.update(enabled); f.adapter.receive(availability());
    await vi.advanceTimersByTimeAsync(60000); await flush();
    expect(f.calls('/open')).toHaveLength(0); expect(f.calls('/renew')).toHaveLength(0);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    expect(f.socket.close).not.toHaveBeenCalled();
  });
  it('rejects a stalled offer renewal without retrying or forwarding any report', async () => {
    const f = offered(); await vi.advanceTimersByTimeAsync(20000); await flush();
    expect(f.onError).toHaveBeenCalledOnce(); expect(f.fetcher).not.toHaveBeenCalled();
    f.adapter.receive(renewed()); f.adapter.update(enabled); f.adapter.receive(availability());
    await vi.advanceTimersByTimeAsync(30000);
    expect(f.frames().filter(frame => frame.type === 'fido_renew')).toHaveLength(1);
    expect(f.calls('/open')).toHaveLength(0);
  });
  it.each([{lease_sequence: 0}, {lease_sequence: 2}, {lease_sequence: '1'}, {version: 2},
    {remaining_ms: 0}, {remaining_ms: 30001}, {remaining_ms: 1.5}, {extra: true}])('rejects malformed/replayed unopened ACK%j', async extra => {
    const f = offered(); await vi.advanceTimersByTimeAsync(15000); f.adapter.receive(renewed(1, extra)); await flush();
    expect(f.onError).toHaveBeenCalledOnce(); expect(f.fetcher).not.toHaveBeenCalled();
    expect(f.frames().filter(frame => frame.type === 'fido_close')).toHaveLength(1);
  });
  it('rejects reports before open and cannot turn them into an implicit activation', async () => {
    const f = offered(); await vi.advanceTimersByTimeAsync(15000); f.adapter.receive(report()); await flush();
    expect(f.onError).toHaveBeenCalledOnce(); expect(f.fetcher).not.toHaveBeenCalled();
    expect(f.frames().filter(frame => frame.type === 'fido_report')).toHaveLength(0);
  });
  it('ignores an old waiting ACK after a fresh local attachment replaces the offer', async () => {
    const f = offered(); await vi.advanceTimersByTimeAsync(15000);
    const replacement = 'n'.repeat(43); f.adapter.receive(availability({relay_id: replacement}));
    f.adapter.receive(renewed()); await flush(); expect(f.onError).not.toHaveBeenCalled();
    f.adapter.update(enabled); await flush();
    expect(f.bodies('/open')).toEqual([{...binding, relay_id: replacement}]);
  });
});
