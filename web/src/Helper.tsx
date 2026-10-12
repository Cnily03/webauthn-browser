import { useEffect, useRef, useState } from 'react';
import { Alert, Button, IconButton, InputAdornment, Stack, TextField } from '@mui/material';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutlineOutlined';
import DownloadOutlinedIcon from '@mui/icons-material/DownloadOutlined';
import WarningAmberOutlinedIcon from '@mui/icons-material/WarningAmberOutlined';
import { PendingHelperTransport, type PendingHelperSocket } from './pendingHelperTransport';
import { request } from './api';
import { FidoRelay } from './FidoRelay';
import { compactControlFontSx, compactControlSx, monospaceFontFamily, monospaceInputSx } from './controlTypography';
export interface HelperSession { session_id: string; token: string; expires_in_ms: number; helper_url: string; generation: number; message?: string }
export function HelperDownloadLink() {
  return <IconButton component="a" href="/downloads" target="_blank" rel="noopener noreferrer" size="small" aria-label="下载" title="下载" sx={{flexShrink: 0, width: 32, height: 32}}><DownloadOutlinedIcon fontSize="small" /></IconButton>;
}
export const DEFAULT_HELPER_ADDRESS = 'ws://127.0.0.1:10233';
export function bridgeAddress(address: string): string {
  let url: URL;
  try { url = new URL(address.includes('://') ? address : `http://${address}`); }
  catch { throw new Error('地址无效'); }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) || !['127.0.0.1', 'localhost'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || !url.port || Number(url.port) < 1024 || Number(url.port) > 65535) throw new Error('地址无效');
  url.protocol = ['https:', 'wss:'].includes(url.protocol) ? 'wss:' : 'ws:';
  url.pathname = '/';
  return url.href;
}
type ConnectionState = 'connecting' | 'approval' | 'paired';
const statusIconSx = {width: '20px', height: '20px', flexShrink: 0};
const connectingIconSx = {...statusIconSx, animation: 'helper-status-spin 1s linear infinite',
  '@keyframes helper-status-spin': {from: {transform: 'rotate(0deg)'}, to: {transform: 'rotate(360deg)'}},
  '@media (prefers-reduced-motion: reduce)': {animation: 'none'},
};
function ConnectionControls({address, onAddress, onConnect, state = 'connecting'}: {
  address: string; onAddress: (value: string) => void; onConnect: () => void; state?: ConnectionState;
}) {
  let invalid = false;
  try { bridgeAddress(address); } catch { invalid = true; }
  return <Stack direction="row" spacing={1} className="helper-controls" sx={{alignItems: 'center', minWidth: 0}}>
    <HelperDownloadLink />
    <TextField label="辅助程序连接地址" size="small" placeholder={DEFAULT_HELPER_ADDRESS} sx={[compactControlSx, monospaceInputSx]} fullWidth value={address} onChange={event => onAddress(event.target.value)}
      slotProps={{htmlInput: {'aria-invalid': invalid, spellCheck: false, autoCapitalize: 'none', autoComplete: 'off', style: {fontFamily: monospaceFontFamily, fontSize: '12px'}}, inputLabel: {sx: compactControlFontSx}, input: {sx: compactControlFontSx, startAdornment: <InputAdornment position="start" className="helper-status-adornment" sx={{...statusIconSx, minWidth: '20px', maxHeight: 'none', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', mr: 1}}>{invalid
        ? <WarningAmberOutlinedIcon color="warning" fontSize="small" sx={statusIconSx} titleAccess="地址无效" />
        : state === 'paired'
        ? <CheckCircleOutlineIcon color="success" fontSize="small" sx={statusIconSx} titleAccess="助手与原生引擎已连接" />
        : <AutorenewIcon color="inherit" fontSize="small" role="progressbar" sx={connectingIconSx} titleAccess={state === 'approval' ? '等待助手批准配对' : '正在连接助手与原生引擎'} />}</InputAdornment>}}} />
    <Button size="small" onClick={onConnect} sx={{flexShrink: 0, minWidth: 0, height: 32, ...compactControlFontSx}}>连接</Button>
  </Stack>;
}
export function HelperSetup({address, onAddress, onConnect}: {address: string; onAddress: (value: string) => void; onConnect: (address?: string) => void}) {
  const latest = useRef({address, onAddress, onConnect}); latest.current = {address, onAddress, onConnect};
  const sampledAddress = useRef(address);
  const active = useRef(true);
  const connect = () => {
    if (!active.current) return;
    const value = latest.current.address; sampledAddress.current = value;
    // Even an invalid new address cancels any older acquisition intent.
    latest.current.onConnect(value);
  };
  const connectRef = useRef(connect); connectRef.current = connect;
  useEffect(() => {
    active.current = true;
    const timer = setInterval(() => { if (sampledAddress.current !== latest.current.address) connectRef.current(); }, 200);
    const stop = () => { active.current = false; clearInterval(timer); };
    window.addEventListener('pagehide', stop);
    return () => { stop(); window.removeEventListener('pagehide', stop); };
  }, []);
  return <Stack spacing={1}>
    <ConnectionControls address={address} onAddress={value => { latest.current.address = value; latest.current.onAddress(value); }} onConnect={connect} />
  </Stack>;
}
// This wrapper survives backend acquisition and session replacement. Its socket
// is handed to HelperPanel rather than discarded as a diagnostic probe.
export function HelperConnection({session, address, onAddress, onConnect, onClose}: {
  session: HelperSession | null; address: string; onAddress: (value: string) => void;
  onConnect: (address?: string) => boolean | void; onClose: () => void;
}) {
  const [transport] = useState(() => new PendingHelperTransport());
  const latestAddress = useRef(address); latestAddress.current = address;
  const lifecycle = useRef(0);
  const mounted = useRef(false);
  const begin = (value: string) => {
    try { transport.start(bridgeAddress(value)); } catch { transport.stop(); }
  };
  useEffect(() => {
    mounted.current = true;
    const stop = () => { mounted.current = false; lifecycle.current++; transport.stop(); };
    window.addEventListener('pagehide', stop);
    return () => { stop(); window.removeEventListener('pagehide', stop); };
  }, [transport]);
  useEffect(() => {
    const generation = ++lifecycle.current;
    queueMicrotask(() => {
      if (mounted.current && generation === lifecycle.current && !session) begin(latestAddress.current);
    });
    return () => { lifecycle.current++; };
  }, [session?.session_id, transport]);
  const connect = (value = latestAddress.current) => {
    if (!mounted.current) return;
    lifecycle.current++; // Supersede a queued mount-time connection as well.
    begin(value); return onConnect(value);
  };
  return session
    ? <HelperPanel key={session.session_id} session={session} initialAddress={address} onAddress={onAddress}
      onRestart={onConnect} onClose={onClose} takeTransport={url => transport.take(url)} />
    : <HelperSetup address={address} onAddress={onAddress} onConnect={connect} />;
}
const UUIDS = new Set(['0000fff9-0000-1000-8000-00805f9b34fb', '0000fde2-0000-1000-8000-00805f9b34fb']);
export function parseAdvertisement(raw: unknown): {uuid: string; data: string} | null {
  if (typeof raw !== 'string' || raw.length > 8192 || new TextEncoder().encode(raw).length > 8192) return null;
  try {
    const item = JSON.parse(raw);
    if (item.type !== 'advertisement' || typeof item.uuid !== 'string' || !UUIDS.has(item.uuid.toLowerCase())
      || typeof item.data !== 'string' || !item.data.length || item.data.length > 88
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(item.data)) return null;
    const bytes = atob(item.data);
    if (!bytes.length || bytes.length > 64 || btoa(bytes) !== item.data) return null;
    return {uuid: item.uuid.toLowerCase(), data: item.data};
  } catch { return null; }
}
export function HelperPanel({session, onClose, initialAddress = DEFAULT_HELPER_ADDRESS, onAddress, onPaired, onRestart, takeTransport}: {
  session: HelperSession; onClose: () => void; initialAddress?: string; onAddress?: (value: string) => void; onPaired?: () => void; onRestart?: (address?: string) => boolean | void; takeTransport?: (url: string) => PendingHelperSocket | null;
}) {
  const [address, setAddress] = useState(initialAddress);
  const [state, setState] = useState<ConnectionState>('connecting');
  const [error, setError] = useState('');
  const addressRef = useRef(initialAddress);
  const callbacks = useRef({onClose, onAddress, onPaired, onRestart}); callbacks.current = {onClose, onAddress, onPaired, onRestart};
  const lifecycle = useRef(0);
  const expires = useRef(Date.now() + session.expires_in_ms);
  const reconnect = useRef<(() => void) | null>(null);
  useEffect(() => {
    const generation = ++lifecycle.current;
    let active = true;
    let ended = false;
    let terminated = false;
    let epoch = 0;
    let controlEpoch = 0;
    let targetAddress = addressRef.current;
    let socket: WebSocket | null = null;
    const warming = new PendingHelperTransport();
    let paired = false;
    let nativeReady = false;
    let experimentalFidoAvailable = false;
    let experimentalFidoLauncherReady = false;
    let fido: FidoRelay | null = null;
    const updateFido = () => fido?.update({paired, nativeReady, backendAvailable: experimentalFidoAvailable, backendLauncherReady: experimentalFidoLauncherReady});
    let pairNotified = false;
    let currentToken = session.token;
    let tokenSent = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let restartTimer: ReturnType<typeof setTimeout> | null = null;
    let restartNotified = false;
    let connectTimer: ReturnType<typeof setTimeout> | null = null;
    let refresh: AbortController | null = null;
    let forwarding = new AbortController();
    let busy = false;
    let queue: {uuid: string; data: string}[] = [];
    let polling = false;
    let renewing = false;
    let lastRenewed = Date.now();
    let renewalController = new AbortController();
    let statusController = new AbortController();
    const live = () => active && !ended && generation === lifecycle.current && Date.now() < expires.current;
    const notifyPaired = () => {
      if (!live() || !paired || !nativeReady || pairNotified) return;
      pairNotified = true;
      callbacks.current.onPaired?.();
    };
    const clearTransport = () => {
      epoch++; controlEpoch++;
      // Invalidate and close the old local transport synchronously, before any
      // request disposal or token acquisition for the replacement.
      if (socket) {
        socket.onopen = null; socket.onmessage = null; socket.onerror = null; socket.onclose = null;
        socket.close(); socket = null;
      }
      warming.stop();
      fido?.close(); fido = null;
      renewalController.abort(); statusController.abort();
      renewalController = new AbortController(); statusController = new AbortController();
      polling = false; renewing = false; nativeReady = false;
      experimentalFidoAvailable = false; experimentalFidoLauncherReady = false;
      if (retryTimer) clearTimeout(retryTimer); retryTimer = null;
      if (connectTimer) clearTimeout(connectTimer); connectTimer = null;
      refresh?.abort(); refresh = null;
      paired = false;
      forwarding.abort(); forwarding = new AbortController();
      queue = []; busy = false;
    };
    let stopped = false;
    const stopBackend = () => {
      if (stopped) return; stopped = true;
      void request('/api/helper/stop', 'POST', {session_id: session.session_id}, {keepalive: true}).catch(() => {});
    };
    const currentLifecycle = () => active && generation === lifecycle.current;
    const notifyRestart = () => {
      if (!currentLifecycle() || restartNotified) return;
      restartNotified = true;
      if (restartTimer) clearTimeout(restartTimer); restartTimer = null;
      const accepted = callbacks.current.onRestart?.(addressRef.current);
      // A busy parent has not taken ownership yet. Retry the handoff, never the
      // expired session, until its serialized mode operation can accept it.
      if (accepted === false && currentLifecycle()) {
        restartNotified = false;
        restartTimer = setTimeout(notifyRestart, 1000);
      }
    };
    // A bad/expired owner-bound lease cannot reuse its token. Tear it down once,
    // then let the parent replace it using the same serialized global-mode flow.
    const replaceSession = (delay = 1000) => {
      if (ended) return;
      ended = true; clearTransport(); statusController.abort(); renewalController.abort(); stopBackend();
      if (active) { setState('connecting'); setError(''); }
      if (delay === 0) notifyRestart(); else restartTimer = setTimeout(notifyRestart, delay);
    };
    const terminate = () => {
      terminated = true; clearInterval(addressTimer);
      ended = true;
      if (restartTimer) clearTimeout(restartTimer); restartTimer = null;
      restartNotified = true;
      clearTransport(); statusController.abort(); renewalController.abort(); stopBackend();
      callbacks.current.onClose();
    };
    const schedule = (delay = 1000) => {
      if (!live()) return;
      clearTransport(); setState('connecting'); setError(''); poll();
      if (delay === 0) { void connect(); return; }
      retryTimer = setTimeout(() => { retryTimer = null; void connect(); }, delay);
    };
    const connect = async () => {
      if (!live() || socket || refresh) return;
      let url: string;
      try { url = bridgeAddress(targetAddress); }
      catch { setState('connecting'); setError(''); return; }
      const attempt = ++epoch;
      const current = () => live() && epoch === attempt;
      let pending: PendingHelperSocket | null | undefined;
      if (tokenSent) {
        // Establish the real socket now; a stalled token rotation must not gate
        // transport attempts, and its previous token is never sent again.
        warming.start(url);
        const controller = new AbortController(); refresh = controller;
        try {
          const updated = await request<{session_id: string; token: string; remaining_ms: number}>('/api/helper/refresh', 'POST',
            {session_id: session.session_id, previous_token: currentToken}, {signal: controller.signal});
          if (!current()) return;
          if (updated.session_id !== session.session_id || typeof updated.token !== 'string' || !updated.token || updated.token.length > 1024
            || updated.token === currentToken || !Number.isFinite(updated.remaining_ms) || updated.remaining_ms <= 0) {
            replaceSession(); return;
          }
          currentToken = updated.token; tokenSent = false;
          expires.current = Math.min(expires.current, Date.now() + updated.remaining_ms);
          pending = warming.take(url);
        } catch (error) {
          if (!current()) return;
          if (typeof error === 'object' && error && 'status' in error && [401, 403, 409].includes(Number(error.status))) {
            replaceSession(); return;
          }
          schedule(); return;
        } finally { if (refresh === controller) refresh = null; }
      }
      if (!current()) return;
      setError(''); setState('connecting');
      const drain = async () => {
        if (busy || !current()) return;
        busy = true;
        try {
          while (current() && queue.length) {
            const advertisement = queue.shift()!;
            await request('/api/helper/advertisement', 'POST', {session_id: session.session_id, ...advertisement}, {signal: forwarding.signal});
          }
        } catch (error) {
          if (current()) replaceSession();
        } finally { if (current()) busy = false; }
      };
      try {
        pending ??= takeTransport?.(url);
        if (pending?.retryAt !== undefined && pending.retryAt > Date.now()) {
          // Capability/token handoff can occur between physical attempts. Keep
          // that exact remaining retry window instead of opening early.
          retryTimer = setTimeout(() => { retryTimer = null; void connect(); }, pending.retryAt - Date.now());
          return;
        }
        const startedAt = pending?.startedAt ?? Date.now();
        const ws = pending?.socket ?? new WebSocket(url); socket = ws;
        let opened = pending?.opened ?? false;
        const relay = new FidoRelay({socket: ws, session_id: session.session_id, generation: session.generation,
          live: current, onError: () => { if (current()) setError('USB 中继已停止，请重新连接助手。'); }});
        fido = relay; updateFido();
        ws.onopen = () => {
          if (!current() || tokenSent) return;
          opened = true;
          if (connectTimer) clearTimeout(connectTimer); connectTimer = null;
          // Mark as spent before send: a thrown send cannot prove the helper did not receive it.
          tokenSent = true;
          try { ws.send(JSON.stringify({type: 'pair', token: currentToken, session_id: session.session_id})); setState('approval'); }
          catch { schedule(); }
        };
        ws.onmessage = event => {
          if (!current() || !tokenSent) return;
          if (typeof event.data !== 'string' || event.data.length > 8192 || new TextEncoder().encode(event.data).length > 8192) { relay.invalidFrame(); return; }
          const advertisement = parseAdvertisement(event.data);
          if (advertisement && paired && nativeReady) {
            if (queue.length < 8) { queue.push(advertisement); void drain(); }
            return;
          }
          try {
            const value = JSON.parse(event.data);
            if (relay.receive(value)) return;
            if (value.type !== 'status' || typeof value.state !== 'string' || typeof value.message !== 'string') return;
            // Every ended transport retries with a fresh one-use token. The
            // helper still owns exact-Origin consent; no frame grants approval.
            if (['closed', 'rejected', 'denied', 'revoked', 'expired', 'lease_expired'].includes(value.state)) { schedule(); return; }
            if (value.state === 'paired') { paired = true; setState(nativeReady ? 'paired' : 'connecting'); setError(''); notifyPaired(); updateFido(); }
            if (paired && value.state === 'scanning') setError('');
          } catch { relay.invalidFrame(); /* BLE remains available after malformed experimental traffic. */ }
        };
        const failed = () => { if (current()) schedule(opened ? 1000 : Math.max(0, 1000 - (Date.now() - startedAt))); };
        ws.onerror = failed;
        ws.onclose = failed;
        // Bound only transport establishment. An open socket may wait for
        // human approval indefinitely within its backend lease. The elapsed
        // second is already the retry delay, so replace a timed-out attempt now.
        if (opened) ws.onopen(new Event('open'));
        else connectTimer = setTimeout(() => { if (current() && !opened) schedule(0); }, Math.max(0, 1000 - (Date.now() - startedAt)));
      } catch { if (current()) schedule(); }
    };
    const restartTransport = () => {
      if (!currentLifecycle() || terminated) return;
      targetAddress = addressRef.current;
      if (ended) { restartNotified = false; notifyRestart(); return; }
      if (!live()) { replaceSession(0); return; }
      // A cancelled token rotation may already have committed remotely. Retire
      // that exact owner lease instead of reusing an uncertain one-use token.
      if (refresh) { replaceSession(0); return; }
      schedule(0);
    };
    reconnect.current = restartTransport;
    // Periodic sampling, not debounce: continued typing cannot postpone the
    // next observation, and explicit Connect bypasses the sampling interval.
    const addressTimer = setInterval(() => {
      if (currentLifecycle() && targetAddress !== addressRef.current) restartTransport();
    }, 200);
    const pagehide = () => terminate();
    window.addEventListener('pagehide', pagehide);
    const poll = () => {
      if (!live()) { if (active && !ended) replaceSession(); return; }
      const requestEpoch = controlEpoch;
      const currentControl = () => live() && requestEpoch === controlEpoch;
      if (session.generation !== undefined && !renewing && Date.now() - lastRenewed >= 45000) {
        renewing = true;
        void request<{remaining_ms: number; generation: number}>('/api/browser/mode/renew', 'POST', {session_id: session.session_id, expected_generation: session.generation}, {signal: renewalController.signal})
          .then(value => {
            if (!currentControl()) return;
            if (value.generation !== session.generation || !Number.isFinite(value.remaining_ms) || value.remaining_ms <= 0) { replaceSession(); return; }
            expires.current = Date.now() + value.remaining_ms; lastRenewed = Date.now();
          }).catch(error => {
            if (!currentControl()) return;
            if (typeof error === 'object' && error && 'status' in error && [401, 403, 409].includes(Number(error.status))) replaceSession();
          }).finally(() => { if (currentControl()) renewing = false; });
      }
      if (polling) return;
      polling = true;
      void request<{active: boolean; generation?: number; remaining_ms?: number; state?: string; experimental_fido_available?: boolean; experimental_fido_launcher_ready?: boolean}>('/api/helper/status', 'GET', undefined, {signal: statusController.signal})
        .then(value => {
          if (!currentControl()) return;
          if (!value.active || value.generation !== session.generation) { replaceSession(); return; }
          nativeReady = value.state === 'native';
          experimentalFidoAvailable = value.experimental_fido_available === true;
          experimentalFidoLauncherReady = value.experimental_fido_launcher_ready === true;
          updateFido();
          if (paired) setState(nativeReady ? 'paired' : 'connecting');
          notifyPaired();
          if (typeof value.remaining_ms === 'number' && Number.isFinite(value.remaining_ms)) expires.current = Math.min(expires.current, Date.now() + value.remaining_ms);
        }).catch(error => {
          if (!currentControl()) return;
          nativeReady = false; experimentalFidoAvailable = false; experimentalFidoLauncherReady = false; updateFido();
          if (paired) setState('connecting');
          if (typeof error === 'object' && error && 'status' in error && [401, 403, 409].includes(Number(error.status))) replaceSession();
        }).finally(() => { if (currentControl()) polling = false; });
    };
    const timer = setInterval(poll, 1000);
    queueMicrotask(() => { if (live()) { poll(); void connect(); } });
    return () => {
      active = false; if (restartTimer) clearTimeout(restartTimer); restartTimer = null; statusController.abort(); renewalController.abort(); clearInterval(timer); clearInterval(addressTimer); window.removeEventListener('pagehide', pagehide); clearTransport(); reconnect.current = null;
      // Defer lease release so StrictMode effect replay can retain the same session.
      queueMicrotask(() => { if (generation === lifecycle.current) stopBackend(); });
    };
  }, [session.session_id, session.generation]);
  const editAddress = (value: string) => {
    addressRef.current = value; setAddress(value); callbacks.current.onAddress?.(value);
  };
  return <Stack role="region" aria-label="原生中继 · 本机助手" spacing={1}>
    <ConnectionControls address={address} onAddress={editAddress} onConnect={() => reconnect.current?.()} state={state} />
    {error && <Alert severity="error" sx={{py: 0, overflowWrap: 'anywhere'}}>{error}</Alert>}
  </Stack>;
}
