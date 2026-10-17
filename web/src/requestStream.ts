import { describeEngineConnection } from './engineConnection';
import { browserApiPath, profileViewerHeaders } from './profiles';
import { localNavigationIdentity, navigationGeneration, validateLocalNavigationEvent, type LocalNavigationEvent } from './localNavigation';

/** Trusted outer-page request stream. Lifecycle events never authorize a decision. */
export interface RequestCandidate {
  key_id: string;
  key_name?: string;
  attachment?: string;
  provider_label?: string;
  model_aaguid?: string;
  credential_id?: string | null;
  user_name?: string | null;
  display_name?: string | null;
  user_handle?: string | null;
  attestation_effective?: string;
  attestation_aaguid?: string;
  remaining_ms?: number;
}
export interface PendingRequest {
  id: string;
  kind?: string;
  stage?: string;
  busy?: boolean;
  origin?: string;
  rp_id?: string;
  uv?: string;
  attestation_requested?: string;
  request_excludes_hybrid?: boolean;
  selected_key_id?: string | null;
  selected_credential_id?: string | null;
  remaining_ms?: number;
  candidates?: RequestCandidate[];
}
export interface RequestSnapshot {
  connected: boolean;
  control_connected?: boolean;
  native_qr_mode?: boolean;
  mode_switching?: boolean;
  mode_error?: string | null;
  mode_generation?: number;
  browser_mode?: 'native' | 'software';
  cursor: string;
  requests: PendingRequest[];
  resync?: boolean;
}
export interface StreamSession { vnc_authenticated: boolean; csrf_token: string }
export type ConnectionState = 'connecting' | 'connected' | 'offline' | 'disconnected';
export interface ApprovalTicket { generation: number; epoch: number }
const MAX_EVENT_SIZE = 2 * 1024 * 1024;

export function validateSnapshot(value: unknown): RequestSnapshot {
  const snapshot = value as RequestSnapshot | null;
  if (!snapshot || !Array.isArray(snapshot.requests) || typeof snapshot.connected !== 'boolean'
      || [snapshot.control_connected, snapshot.native_qr_mode, snapshot.mode_switching].some(value => value !== undefined && typeof value !== 'boolean')
      || (snapshot.mode_generation !== undefined && !navigationGeneration(snapshot.mode_generation))
      || (snapshot.browser_mode !== undefined && !['native', 'software'].includes(snapshot.browser_mode))
      || (snapshot.mode_error !== undefined && snapshot.mode_error !== null && (typeof snapshot.mode_error !== 'string' || !['native_mode_timeout', 'native_mode_api_error', 'proxy_mode_timeout', 'proxy_mode_api_error', 'browser_mode_error', 'extension_upgrade_required'].includes(snapshot.mode_error)))
      || typeof snapshot.cursor !== 'string' || !snapshot.cursor || /[\r\n\0]/.test(snapshot.cursor)) {
    throw new Error('验证事件格式无效');
  }
  return snapshot;
}
export function requestIdentity(pending: PendingRequest): string {
  // Countdown ticks alone must not clear a user's selection or password.
  return JSON.stringify(pending, (key, value: unknown) => key === 'remaining_ms' ? undefined : value);
}
export function statusCode(error: unknown): number | undefined {
  return typeof error === 'object' && error !== null && 'status' in error
    && typeof error.status === 'number' ? error.status : undefined;
}
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '请求失败，请检查连接。';
}

interface ConsumerOptions {
  current: () => boolean;
  signal: AbortSignal;
  onActivity: () => void;
  onSnapshot: (snapshot: RequestSnapshot) => void;
  onLocalNavigation?: (event: LocalNavigationEvent) => void;
  onLocalNavigationClear?: (generation: number) => void;
}
export async function consumeRequestEvents(response: Response, options: ConsumerOptions): Promise<void> {
  if (!response.body?.getReader) throw new Error('浏览器不支持验证事件流');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let event = '';
  let data: string[] = [];
  let eventLength = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  options.signal.addEventListener('abort', cancel, {once: true});
  const line = (value: string) => {
    if (!value) {
      if (event === 'locked') throw Object.assign(new Error('浏览器会话已锁定'), {status: 401});
      if (event === 'snapshot' && data.length) options.onSnapshot(validateSnapshot(JSON.parse(data.join('\n'))));
      if ((event === 'local_navigation' || event === 'local_navigation_clear') && data.length) {
        // These are live-only hints, never cursor/history entries or approval
        // requests. Malformed hints cannot authorize any local navigation.
        let value: unknown;
        try { value = JSON.parse(data.join('\n')); } catch { value = null; }
        if (event === 'local_navigation') {
          const hint = validateLocalNavigationEvent(value);
          if (hint) options.onLocalNavigation?.(hint);
        } else if (value && typeof value === 'object' && 'mode_generation' in value && navigationGeneration(value.mode_generation)) {
          options.onLocalNavigationClear?.(value.mode_generation);
        }
      }
      event = ''; data = []; eventLength = 0;
      return;
    }
    if (value.startsWith(':')) return;
    const separator = value.indexOf(':');
    const field = separator < 0 ? value : value.slice(0, separator);
    let content = separator < 0 ? '' : value.slice(separator + 1);
    if (content.startsWith(' ')) content = content.slice(1);
    if (field === 'event') event = content;
    if (field === 'data') {
      eventLength += content.length;
      if (eventLength > MAX_EVENT_SIZE) throw new Error('验证事件过大');
      data.push(content);
    }
    // SSE id and lifecycle data are untrusted: only a full snapshot sets the cursor.
  };
  try {
    options.onActivity();
    while (options.current() && !options.signal.aborted) {
      const {done, value} = await reader.read();
      if (!options.current() || options.signal.aborted) return;
      if (done) throw new Error('验证事件连接已关闭');
      options.onActivity();
      buffer += decoder.decode(value, {stream: true});
      let start = 0;
      for (let index = 0; index < buffer.length; index += 1) {
        if (buffer[index] !== '\r' && buffer[index] !== '\n') continue;
        if (buffer[index] === '\r' && index === buffer.length - 1) break;
        line(buffer.slice(start, index));
        if (buffer[index] === '\r' && buffer[index + 1] === '\n') index += 1;
        start = index + 1;
      }
      buffer = buffer.slice(start);
      if (buffer.length > MAX_EVENT_SIZE) throw new Error('验证事件过大');
    }
  } finally {
    options.signal.removeEventListener('abort', cancel);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

interface StreamOptions {
  refreshStatus: () => Promise<StreamSession>;
  onSnapshot: (snapshot: RequestSnapshot | null) => void;
  onConnection: (state: ConnectionState, message: string) => void;
  onUnauthorized: () => void;
  onLocalNavigation?: (event: LocalNavigationEvent | null) => void;
  fetch?: typeof fetch;
}
/**
 * Generation identifies the stream lifecycle; epoch invalidates approval tickets
 * within that lifecycle. A connection gap revokes tickets before reconnecting.
 */
export class RequestStream {
  private generation = 0;
  private epoch = 0;
  private controller: AbortController | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private watchdog: ReturnType<typeof setTimeout> | null = null;
  private failures = 0;
  private navigationMode: number | null = null;
  private navigationInstance: string | null = null;
  ready = false;
  cursor = '';
  constructor(private readonly options: StreamOptions) {}
  ticket(): ApprovalTicket { return {generation: this.generation, epoch: this.epoch}; }
  accepts(ticket: ApprovalTicket): boolean {
    return this.ready && ticket.generation === this.generation && ticket.epoch === this.epoch;
  }
  private invalidate() {
    this.epoch += 1;
    this.ready = false;
    this.options.onSnapshot(null);
  }
  private invalidateNavigation() {
    this.navigationMode = null;
    this.navigationInstance = null;
    this.options.onLocalNavigation?.(null);
  }
  stop() {
    this.generation += 1;
    this.invalidate();
    this.invalidateNavigation();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.watchdog) clearTimeout(this.watchdog);
    this.reconnectTimer = null;
    this.watchdog = null;
    this.controller?.abort();
    this.controller = null;
    this.options.onConnection('disconnected', '验证事件已断开');
  }
  start() {
    this.stop();
    this.failures = 0;
    void this.connect(this.generation);
  }
  applySnapshot(value: unknown) {
    const snapshot = validateSnapshot(value);
    const navigationMode = snapshot.control_connected === true && !snapshot.mode_switching && !snapshot.mode_error
      && navigationGeneration(snapshot.mode_generation) ? snapshot.mode_generation : null;
    const navigationInstance = navigationMode === null ? null : snapshot.cursor.slice(0, snapshot.cursor.lastIndexOf(':'));
    if (snapshot.resync || navigationMode !== this.navigationMode || navigationInstance !== this.navigationInstance) this.options.onLocalNavigation?.(null);
    this.navigationMode = navigationMode;
    this.navigationInstance = navigationInstance;
    this.cursor = snapshot.cursor;
    if (snapshot.resync || !snapshot.connected || snapshot.mode_error) this.invalidate();
    this.ready = snapshot.connected && !snapshot.mode_error;
    const connection = describeEngineConnection(snapshot);
    this.options.onConnection(connection.state, connection.message);
    this.options.onSnapshot(snapshot);
  }
  applyRecoverySnapshot(value: unknown, ticket: ApprovalTicket, expectedCursor: string) {
    // A recovery response must not overwrite a newer snapshot from the event stream.
    if (this.accepts(ticket) && this.cursor === expectedCursor) this.applySnapshot(value);
  }
  private async connect(generation: number) {
    const current = () => generation === this.generation;
    if (!current()) return;
    this.reconnectTimer = null;
    this.invalidate();
    this.invalidateNavigation();
    this.options.onConnection('connecting', this.failures ? '验证事件重连中…' : '验证事件连接中…');
    const controller = new AbortController();
    this.controller = controller;
    const alive = () => {
      if (this.watchdog) clearTimeout(this.watchdog);
      this.watchdog = setTimeout(() => {
        if (!current()) return;
        this.invalidate();
        this.invalidateNavigation();
        this.options.onConnection('disconnected', '验证事件已断开，正在重连…');
        controller.abort();
      }, 45000);
    };
    try {
      // Revalidate the browser session and use its current CSRF token on each attempt.
      const session = await this.options.refreshStatus();
      if (!current()) return;
      if (!session.vnc_authenticated) { this.stop(); this.options.onUnauthorized(); return; }
      const headers: Record<string, string> = {'Accept': 'text/event-stream', 'X-CSRF-Token': session.csrf_token, ...profileViewerHeaders()};
      if (this.cursor) headers['Last-Event-ID'] = this.cursor;
      const response = await (this.options.fetch ?? fetch)(browserApiPath('/api/requests/events'), {
        method: 'GET', headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      });
      if (!current()) { await response.body?.cancel().catch(() => {}); return; }
      if (!response.ok) throw Object.assign(new Error(`验证事件连接失败（${response.status}）`), {status: response.status});
      if (!response.headers.get('Content-Type')?.toLowerCase().startsWith('text/event-stream')) throw new Error('验证事件响应格式无效');
      await consumeRequestEvents(response, {current, signal: controller.signal, onActivity: alive, onSnapshot: snapshot => {
        if (!current() || controller.signal.aborted) return;
        this.applySnapshot(snapshot);
        this.failures = 0;
      }, onLocalNavigation: event => {
        if (current() && !controller.signal.aborted && event.mode_generation === this.navigationMode
            && localNavigationIdentity(event.id)?.instance === this.navigationInstance) this.options.onLocalNavigation?.(event);
      }, onLocalNavigationClear: mode => {
        if (current() && !controller.signal.aborted && mode === this.navigationMode) this.options.onLocalNavigation?.(null);
      }});
      if (current()) throw new Error('验证事件连接已关闭');
    } catch (error) {
      if (!current()) return;
      this.invalidate();
      this.invalidateNavigation();
      this.options.onConnection('disconnected', '验证事件已断开，正在重连…');
      if (statusCode(error) === 401) { this.stop(); this.options.onUnauthorized(); return; }
      this.failures += 1;
      this.reconnectTimer = setTimeout(() => { void this.connect(generation); }, Math.min(500 * 2 ** Math.min(this.failures - 1, 5), 15000));
    } finally {
      if (this.controller === controller) {
        if (this.watchdog) clearTimeout(this.watchdog);
        this.watchdog = null;
        this.controller = null;
      }
      controller.abort();
    }
  }
}
