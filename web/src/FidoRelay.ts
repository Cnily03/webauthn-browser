import { request } from './api';

// Experimental transport only. Reports are opaque fixed-size bytes; this layer
// never parses CTAP, relying-party information, credentials, or device identity.
const VERSION = 1;
const MAX_BATCH = 8;
// CTAPHID §11.2.4 permits one initialization + 128 continuation reports.
// Two maximum messages leave bounded room for a full response and queued
// control/keepalive reports. Keep aligned with fido_report_relay::QUEUE_CAPACITY.
const CTAPHID_MAX_REPORTS = 1 + 128;
const MAX_QUEUE = 2 * CTAPHID_MAX_REPORTS;
const MAX_BUFFERED = 64 * 1024;
const MAX_LEASE_MS = 30000;
const POLL_MS = 20;
const REQUEST_TIMEOUT_MS = 5000;
const ERROR = '实验性 FIDO 中继已停止；蓝牙连接不受影响。';
const WAITING = '实验性 USB 通道尚未就绪；辅助程序配对和蓝牙仍可使用。';
type RecordValue = Record<string, unknown>;
type Report = {sequence: number; data: string};
type Availability = {relay_id: string; helper_connection_id: string; deadline: number; nextLease: number};
type OfferRenewal = {lease_sequence: number; sentAt: number};
type Offer = Availability & {renewal: OfferRenewal | null};
type Gates = {paired: boolean; nativeReady: boolean; backendAvailable: boolean; backendLauncherReady?: boolean};
type Socket = Pick<WebSocket, 'readyState' | 'bufferedAmount' | 'send'>;
type Renewal = OfferRenewal & {phase: 'helper' | 'backend'; native_sequence: number};
type Attempt = Availability & {
  phase: 'opening' | 'waiting' | 'ready';
  controller: AbortController;
  deadlineTimer: ReturnType<typeof setTimeout> | null;
  requestTimer: ReturnType<typeof setTimeout> | null;
  renewalTimer: ReturnType<typeof setTimeout> | null;
  acknowledgedLease: number;
  pollTimer: ReturnType<typeof setTimeout> | null;
  queue: Report[];
  incoming: number;
  outgoing: number;
  exchange: number;
  nextNativeLease: number;
  renewAt: number;
  renewal: Renewal | null;
  busy: boolean;
};
function record(value: unknown): value is RecordValue { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function exact(value: RecordValue, keys: string[]): boolean { return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function id(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(value); }
function remaining(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= MAX_LEASE_MS; }
function sequence(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value < Number.MAX_SAFE_INTEGER; }
export function validFidoReport(value: unknown): value is Report {
  if (!record(value) || !exact(value, ['sequence', 'data']) || !sequence(value.sequence)
    || typeof value.data !== 'string' || value.data.length !== 88 || !/^[A-Za-z0-9+/]{86}==$/.test(value.data)) return false;
  try { const bytes = atob(value.data); return bytes.length === 64 && btoa(bytes) === value.data; } catch { return false; }
}

/** One instance per paired socket attempt. Closing it cannot close the BLE socket. */
export class FidoRelay {
  private gates: Gates = {paired: false, nativeReady: false, backendAvailable: false};
  private available: Offer | null = null;
  private offerRenewTimer: ReturnType<typeof setTimeout> | null = null;
  private offerRequestTimer: ReturnType<typeof setTimeout> | null = null;
  private availabilityTimer: ReturnType<typeof setTimeout> | null = null;
  private active: Attempt | null = null;
  private connectionId: string | null = null;
  private seen = new Set<string>();
  private closed = false;
  private closing = 0;
  private status: string | null = null;

  constructor(private readonly options: {
    socket: Socket;
    session_id: string;
    generation: number;
    live: () => boolean;
    onError: (message: string) => void;
    onStatus?: (message: string) => void;
  }) {}

  update(gates: Gates): void {
    if (this.closed) return;
    const wasNative = this.gates.nativeReady;
    this.gates = gates;
    if (!gates.paired || !this.options.live() || (wasNative && !gates.nativeReady)) this.clearAvailability();
    if (this.active && !this.allowed()) this.cancelAttempt();
    this.start();
  }

  /** Returns true only for experimental frames, leaving other protocols alone. */
  receive(value: unknown): boolean {
    if (!record(value) || typeof value.type !== 'string' || !value.type.startsWith('fido_')) return false;
    if (this.closed || !this.options.live()) return true;
    if (value.type === 'fido_available') {
      if (!this.gates.paired) return true;
      if (!exact(value, ['type', 'experimental_fido', 'version', 'relay_id', 'helper_connection_id', 'remaining_ms'])
        || value.experimental_fido !== true || value.version !== VERSION || !id(value.relay_id)
        || !id(value.helper_connection_id) || !remaining(value.remaining_ms)
        || (this.connectionId !== null && this.connectionId !== value.helper_connection_id)) {
        this.fail(); return true;
      }
      // A relay can never be restarted after an uncertain open/exchange. A fresh
      // explicit local attachment must supply a new ID, even on this same socket.
      if (this.seen.has(value.relay_id)) return true;
      if (this.seen.size >= 32) { this.close(); this.options.onError(ERROR); return true; }
      this.seen.add(value.relay_id);
      this.connectionId = value.helper_connection_id;
      this.cancelAttempt();
      this.clearAvailability();
      this.available = {relay_id: value.relay_id, helper_connection_id: value.helper_connection_id, deadline: Date.now() + value.remaining_ms, nextLease: 1, renewal: null};
      this.armOfferDeadline(this.available);
      this.start();
      return true;
    }
    const attempt = this.active;
    const expectedId = attempt?.relay_id ?? this.available?.relay_id;
    // Old attachment frames can arrive while cancellation is still completing,
    // including before a replacement relay has begun its own open request.
    if (expectedId && typeof value.relay_id === 'string' && value.relay_id !== expectedId && this.seen.has(value.relay_id)) return true;
    if (!attempt) {
      if (this.available) {
        const offer = this.available;
        if (value.type === 'fido_close' && exact(value, ['type', 'version', 'relay_id']) && value.version === VERSION && value.relay_id === offer.relay_id) this.clearAvailability();
        else if (this.waitingAllowed() && Date.now() < offer.deadline && value.type === 'fido_renewed'
          && exact(value, ['type', 'version', 'relay_id', 'lease_sequence', 'remaining_ms'])
          && value.version === VERSION && value.relay_id === offer.relay_id && offer.renewal
          && value.lease_sequence === offer.renewal.lease_sequence && remaining(value.remaining_ms)) {
          const deadline = offer.renewal.sentAt + value.remaining_ms;
          if (deadline <= Date.now()) { this.fail(); return true; }
          offer.deadline = deadline;
          offer.renewal = null;
          if (this.offerRequestTimer !== null) clearTimeout(this.offerRequestTimer);
          this.offerRequestTimer = null;
          this.armOfferDeadline(offer);
          this.start();
        } else this.fail();
      }
      return true;
    }
    if (!this.current(attempt)) { this.fail(); return true; }
    if (value.version !== VERSION || value.relay_id !== attempt.relay_id) { this.fail(); return true; }
    if (value.type === 'fido_ready' && exact(value, ['type', 'version', 'relay_id']) && attempt.phase === 'waiting') {
      attempt.phase = 'ready';
      this.clearRequestTimer(attempt);
      void this.exchange(attempt);
    } else if (value.type === 'fido_report' && exact(value, ['type', 'version', 'relay_id', 'sequence', 'data']) && attempt.phase === 'ready'
      && validFidoReport({sequence: value.sequence, data: value.data}) && value.sequence === attempt.incoming && attempt.queue.length < MAX_QUEUE) {
      attempt.incoming++;
      attempt.queue.push({sequence: value.sequence as number, data: value.data as string});
    } else if (value.type === 'fido_renewed' && exact(value, ['type', 'version', 'relay_id', 'lease_sequence', 'remaining_ms'])
      && attempt.phase === 'ready' && attempt.renewal?.phase === 'helper'
      && value.lease_sequence === attempt.renewal.lease_sequence && remaining(value.remaining_ms)) {
      const renewal = attempt.renewal;
      // ACK durations start no later than our send time. Never credit time spent
      // in transit, nor extend the browser lease before both peers acknowledge.
      const helperDeadline = renewal.sentAt + value.remaining_ms;
      if (helperDeadline <= Date.now()) { this.fail(); return true; }
      renewal.phase = 'backend';
      this.armRenewalTimer(attempt);
      void this.renewBackend(attempt, renewal, helperDeadline);
    } else if (value.type === 'fido_close' && exact(value, ['type', 'version', 'relay_id'])) {
      this.cancelAttempt();
    } else {
      this.fail();
    }
    return true;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearAvailability();
    this.cancelAttempt();
  }

  invalidFrame(): void { if (this.active || this.available) this.fail(); }

  private clearOfferTimers(): void {
    if (this.availabilityTimer !== null) clearTimeout(this.availabilityTimer);
    if (this.offerRenewTimer !== null) clearTimeout(this.offerRenewTimer);
    if (this.offerRequestTimer !== null) clearTimeout(this.offerRequestTimer);
    this.availabilityTimer = this.offerRenewTimer = this.offerRequestTimer = null;
  }
  private clearAvailability(): void {
    this.clearOfferTimers();
    const available = this.available;
    this.available = null;
    this.setStatus('');
    if (available) this.send({type: 'fido_close', version: VERSION, relay_id: available.relay_id});
  }
  private setStatus(message: string): void {
    if (this.status === message) return;
    this.status = message;
    this.options.onStatus?.(message);
  }
  private waitingAllowed(): boolean {
    return !this.closed && this.options.live() && this.gates.paired && this.gates.nativeReady
      && this.options.socket.readyState === 1;
  }
  private armOfferDeadline(offer: Offer): void {
    if (this.availabilityTimer !== null) clearTimeout(this.availabilityTimer);
    this.availabilityTimer = setTimeout(() => {
      if (this.available === offer) this.clearAvailability();
    }, Math.max(0, offer.deadline - Date.now()));
  }
  private keepOfferAlive(offer: Offer): void {
    if (!this.waitingAllowed() || offer.renewal || this.offerRenewTimer !== null) return;
    this.offerRenewTimer = setTimeout(() => {
      this.offerRenewTimer = null;
      if (this.available !== offer) return;
      if (!this.waitingAllowed() || Date.now() >= offer.deadline) { this.clearAvailability(); return; }
      if (!sequence(offer.nextLease) || offer.nextLease === 0) { this.fail(); return; }
      const renewal = {lease_sequence: offer.nextLease++, sentAt: Date.now()};
      offer.renewal = renewal;
      this.offerRequestTimer = setTimeout(() => {
        if (this.available === offer && offer.renewal === renewal) this.fail();
      }, REQUEST_TIMEOUT_MS);
      if (!this.send({type: 'fido_renew', version: VERSION, relay_id: offer.relay_id,
        lease_sequence: renewal.lease_sequence, remaining_ms: MAX_LEASE_MS})) this.fail();
    }, Math.max(0, this.nextRenewal(offer.deadline) - Date.now()));
  }
  private allowed(): boolean {
    return !this.closed && this.options.live() && this.gates.paired && this.gates.nativeReady
      && (this.gates.backendAvailable || this.gates.backendLauncherReady === true)
      && this.options.socket.readyState === 1;
  }
  private current(attempt: Attempt): boolean { return this.active === attempt && this.allowed() && Date.now() < attempt.deadline; }
  private binding(attempt: Availability) {
    return {session_id: this.options.session_id, generation: this.options.generation, relay_id: attempt.relay_id, helper_connection_id: attempt.helper_connection_id};
  }
  private fail(): void { this.clearAvailability(); this.cancelAttempt(); this.options.onError(ERROR); }
  private send(value: RecordValue): boolean {
    const socket = this.options.socket;
    const raw = JSON.stringify(value);
    if (socket.readyState !== 1 || !Number.isFinite(socket.bufferedAmount) || socket.bufferedAmount < 0
      || socket.bufferedAmount + raw.length > MAX_BUFFERED) return false;
    try { socket.send(raw); return true; } catch { return false; }
  }
  private clearRequestTimer(attempt: Attempt): void {
    if (attempt.requestTimer !== null) clearTimeout(attempt.requestTimer);
    attempt.requestTimer = null;
  }
  private armRequestTimer(attempt: Attempt): void {
    this.clearRequestTimer(attempt);
    attempt.requestTimer = setTimeout(() => { if (this.active === attempt) this.fail(); }, REQUEST_TIMEOUT_MS);
  }
  private clearRenewalTimer(attempt: Attempt): void {
    if (attempt.renewalTimer !== null) clearTimeout(attempt.renewalTimer);
    attempt.renewalTimer = null;
  }
  private armRenewalTimer(attempt: Attempt): void {
    this.clearRenewalTimer(attempt);
    attempt.renewalTimer = setTimeout(() => { if (this.active === attempt) this.fail(); }, REQUEST_TIMEOUT_MS);
  }
  private armDeadline(attempt: Attempt): void {
    if (attempt.deadlineTimer !== null) clearTimeout(attempt.deadlineTimer);
    attempt.deadlineTimer = setTimeout(() => { if (this.active === attempt) this.fail(); }, Math.max(0, attempt.deadline - Date.now()));
  }
  private cancelAttempt(): void {
    const attempt = this.active;
    if (!attempt) return;
    this.active = null;
    attempt.controller.abort();
    this.clearRequestTimer(attempt);
    this.clearRenewalTimer(attempt);
    if (attempt.deadlineTimer !== null) clearTimeout(attempt.deadlineTimer);
    if (attempt.pollTimer !== null) clearTimeout(attempt.pollTimer);
    attempt.renewal = null;
    attempt.queue = [];
    this.send({type: 'fido_close', version: VERSION, relay_id: attempt.relay_id});
    this.closing++;
    // Independent cancellation survives the report request's abort, but a lost
    // response cannot block every future explicit attachment indefinitely. This
    // deadline does not imply remote cancellation: backend ownership/lease CAS
    // still decides whether a fresh open is allowed. Never replay this mutation.
    const controller = new AbortController();
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      this.closing--;
      this.start();
    };
    const timer = setTimeout(() => { controller.abort(); finish(); }, REQUEST_TIMEOUT_MS);
    void request('/api/helper/fido/cancel', 'POST', this.binding(attempt), {keepalive: true, signal: controller.signal})
      .catch(() => {}).finally(finish);
  }
  private start(): void {
    // Pairing and BLE/native readiness do not prove that an experimental USB
    // route exists. Keep this informational state separate from transport errors.
    this.setStatus(!this.closed && this.options.live() && this.gates.paired && this.available
      && !this.gates.backendAvailable && this.gates.backendLauncherReady !== true ? WAITING : '');
    if (this.available) this.keepOfferAlive(this.available);
    if (!this.allowed() || this.active || this.closing || !this.available || this.available.renewal) return;
    const available = this.available;
    this.clearOfferTimers();
    this.available = null;
    if (Date.now() >= available.deadline || !sequence(this.options.generation)) return;
    const attempt: Attempt = {...available, phase: 'opening', controller: new AbortController(), deadlineTimer: null, requestTimer: null, renewalTimer: null, acknowledgedLease: 0,
      pollTimer: null, queue: [], incoming: 0, outgoing: 0, exchange: 0, nextNativeLease: 1,
      renewAt: this.nextRenewal(available.deadline), renewal: null, busy: false};
    this.active = attempt;
    this.armDeadline(attempt);
    this.armRequestTimer(attempt);
    void this.open(attempt);
  }
  private async open(attempt: Attempt): Promise<void> {
    const sentAt = Date.now();
    try {
      const value: unknown = await request('/api/helper/fido/open', 'POST', this.binding(attempt), {signal: attempt.controller.signal});
      if (!this.current(attempt)) return;
      if (!record(value) || !exact(value, ['version', 'relay_id', 'remaining_ms']) || value.version !== VERSION
        || value.relay_id !== attempt.relay_id || !remaining(value.remaining_ms)) { this.fail(); return; }
      attempt.deadline = Math.min(attempt.deadline, sentAt + value.remaining_ms);
      attempt.renewAt = Math.min(attempt.renewAt, this.nextRenewal(attempt.deadline));
      const remainingMs = attempt.deadline - Date.now();
      if (remainingMs <= 0) { this.fail(); return; }
      this.armDeadline(attempt);
      attempt.phase = 'waiting';
      this.armRequestTimer(attempt);
      if (!this.send({type: 'fido_open', version: VERSION, relay_id: attempt.relay_id, remaining_ms: remainingMs})) this.fail();
    } catch { if (this.active === attempt) this.fail(); }
  }
  private async exchange(attempt: Attempt): Promise<void> {
    if (!this.current(attempt) || attempt.phase !== 'ready' || attempt.busy) return;
    if (!attempt.renewal && Date.now() >= attempt.renewAt) this.renewHelper(attempt);
    if (!this.current(attempt)) return;
    if (!sequence(attempt.exchange)) { this.fail(); return; }
    attempt.busy = true;
    const exchangeSequence = attempt.exchange++;
    const acknowledgedLease = attempt.acknowledgedLease;
    const reports = attempt.queue.splice(0, MAX_BATCH);
    const sentAt = Date.now();
    this.armRequestTimer(attempt);
    try {
      const value: unknown = await request('/api/helper/fido/exchange', 'POST', {...this.binding(attempt), exchange_sequence: exchangeSequence, reports}, {signal: attempt.controller.signal});
      if (!this.current(attempt)) return;
      if (!record(value) || !exact(value, ['version', 'relay_id', 'exchange_sequence', 'reports', 'remaining_ms'])
        || value.version !== VERSION || value.relay_id !== attempt.relay_id || value.exchange_sequence !== exchangeSequence
        || !remaining(value.remaining_ms) || !Array.isArray(value.reports) || value.reports.length > MAX_BATCH
        || !value.reports.every((report, index) => validFidoReport(report) && report.sequence === attempt.outgoing + index)) { this.fail(); return; }
      // This response may have been produced before a concurrently completed
      // renewal. Only the matching acknowledged lease can constrain its expiry;
      // stale exchange responses must not undo a newer two-peer renewal ACK.
      if (acknowledgedLease === attempt.acknowledgedLease) {
        attempt.deadline = Math.min(attempt.deadline, sentAt + value.remaining_ms);
        attempt.renewAt = Math.min(attempt.renewAt, this.nextRenewal(attempt.deadline));
      }
      if (Date.now() >= attempt.deadline) { this.fail(); return; }
      this.armDeadline(attempt);
      for (const report of value.reports as Report[]) {
        if (!this.send({type: 'fido_report', version: VERSION, relay_id: attempt.relay_id, ...report})) { this.fail(); return; }
        attempt.outgoing++;
      }
      this.clearRequestTimer(attempt);
      this.scheduleExchange(attempt);
    } catch { if (this.active === attempt) this.fail(); }
    finally { attempt.busy = false; }
  }

  private nextRenewal(deadline: number): number {
    const now = Date.now();
    return now + Math.floor((deadline - now) / 2);
  }
  private scheduleExchange(attempt: Attempt): void {
    attempt.pollTimer = setTimeout(() => { attempt.pollTimer = null; void this.exchange(attempt); }, POLL_MS);
  }
  private renewHelper(attempt: Attempt): void {
    if (!sequence(attempt.nextLease) || attempt.nextLease === 0
      || !sequence(attempt.nextNativeLease) || attempt.nextNativeLease === 0) { this.fail(); return; }
    const renewal: Renewal = {phase: 'helper', lease_sequence: attempt.nextLease++, native_sequence: attempt.nextNativeLease++, sentAt: Date.now()};
    attempt.renewal = renewal;
    this.armRenewalTimer(attempt);
    if (!this.send({type: 'fido_renew', version: VERSION, relay_id: attempt.relay_id,
      lease_sequence: renewal.lease_sequence, remaining_ms: MAX_LEASE_MS})) this.fail();
  }
  private async renewBackend(attempt: Attempt, renewal: Renewal, helperDeadline: number): Promise<void> {
    const sentAt = Date.now();
    const remainingMs = helperDeadline - sentAt;
    if (!remaining(remainingMs)) { this.fail(); return; }
    try {
      const value: unknown = await request('/api/helper/fido/renew', 'POST', {...this.binding(attempt),
        lease_sequence: renewal.native_sequence, remaining_ms: remainingMs}, {signal: attempt.controller.signal});
      if (!this.current(attempt) || attempt.renewal !== renewal) return;
      if (!record(value) || !exact(value, ['version', 'relay_id', 'lease_sequence', 'remaining_ms'])
        || value.version !== VERSION || value.relay_id !== attempt.relay_id || value.lease_sequence !== renewal.native_sequence
        || !remaining(value.remaining_ms)) { this.fail(); return; }
      const deadline = Math.min(helperDeadline, sentAt + value.remaining_ms);
      if (Date.now() >= deadline) { this.fail(); return; }
      attempt.deadline = deadline;
      attempt.acknowledgedLease = renewal.native_sequence;
      attempt.renewAt = this.nextRenewal(deadline);
      attempt.renewal = null;
      this.clearRenewalTimer(attempt);
      this.armDeadline(attempt);
    } catch { if (this.active === attempt) this.fail(); }
  }
}
