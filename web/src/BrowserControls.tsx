import { useEffect, useRef, useState } from 'react';
import { compactControlFontSx, compactControlSx } from './controlTypography';
import { Alert, Box, Button, FormControl, IconButton, InputLabel, MenuItem, Paper, Select, Stack, Tooltip, Typography } from '@mui/material';
import DragIndicatorIcon from '@mui/icons-material/DragIndicator';
import KeyboardDoubleArrowLeftIcon from '@mui/icons-material/KeyboardDoubleArrowLeft';
import KeyboardDoubleArrowRightIcon from '@mui/icons-material/KeyboardDoubleArrowRight';
import RefreshIcon from '@mui/icons-material/Refresh';
import KeyboardOutlinedIcon from '@mui/icons-material/KeyboardOutlined';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import FullscreenExitIcon from '@mui/icons-material/FullscreenExit';
import VerifiedUserOutlinedIcon from '@mui/icons-material/VerifiedUserOutlined';
import type { AuthConnection } from './AuthRequests';
import { HelperConnection, DEFAULT_HELPER_ADDRESS, bridgeAddress, type HelperSession } from './Helper';
import { request } from './api';
import { errorMessage, statusCode } from './requestStream';
import { useFloatingBar } from './floatingBar';
import { readBrowserControlPreferences, saveBrowserMode, saveHelperAddress, type BrowserMode } from './browserControlPreferences';

type HelperLease = Pick<HelperSession, 'session_id'> & {generation?: number};
const OPERATION_WAIT_MS = 1000;
// Interrupt the wait, never a mutation: a late response may contain the only
// capability that can release a committed native lease.
function bounded<T>(promise: Promise<T>, controller: AbortController): Promise<T> {
  return new Promise((resolve, reject) => {
    const interrupted = () => { clearTimeout(timer); reject(new Error('连接状态仍在确认中。')); };
    const timer = setTimeout(() => controller.abort(), OPERATION_WAIT_MS);
    controller.signal.addEventListener('abort', interrupted, {once: true});
    if (controller.signal.aborted) interrupted();
    promise.then(resolve, reject).finally(() => {
      clearTimeout(timer); controller.signal.removeEventListener('abort', interrupted);
    });
  });
}
interface ModeStatus { mode: BrowserMode; state: string; generation: number; active: boolean; owned: boolean; control_connected: boolean }
interface Props {
  hidden?: boolean;
  authConnection: AuthConnection;
  connected: boolean;
  reconnecting: boolean;
  onReconnect: () => void;
  onCtrlAltDelete: () => void;
  onFullscreen: () => void;
  onUnauthorized: () => void;
  onModeChange?: () => void;
}
function validateMode(value: ModeStatus) {
  if (!value || !['native', 'software'].includes(value.mode) || !Number.isSafeInteger(value.generation) || value.generation < 0 || typeof value.active !== 'boolean') throw new Error('验证模式状态无效，请重新加载页面。');
  return value;
}
function validateSession(value: HelperSession) {
  if (!value || typeof value.session_id !== 'string' || !value.session_id || typeof value.token !== 'string' || !value.token || value.token.length > 1024 || !Number.isFinite(value.expires_in_ms) || value.expires_in_ms <= 0 || !Number.isSafeInteger(value.generation)) throw new Error('原生中继配对响应无效，请重新连接。');
  return value;
}
export function BrowserControls({hidden = false, authConnection, connected, reconnecting, onReconnect, onCtrlAltDelete, onFullscreen, onUnauthorized, onModeChange}: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [modeMenuOpen, setModeMenuOpen] = useState(false);
  const [preferences] = useState(() => readBrowserControlPreferences(DEFAULT_HELPER_ADDRESS));
  const [mode, setMode] = useState<BrowserMode>(preferences.mode);
  const [address, setAddress] = useState(preferences.address);
  const [session, setSession] = useState<HelperSession | null>(null);
  const [error, setError] = useState('');
  const [fullscreen, setFullscreen] = useState(Boolean(document.fullscreenElement));
  const desired = useRef<BrowserMode>(preferences.mode);
  const sessionRef = useRef<HelperSession | null>(null);
  const sessionIntent = useRef<number | null>(null);
  const addressRef = useRef(address);
  const addressError = useRef('');
  const activeOperation = useRef<AbortController | null>(null);
  const initialRead = useRef<AbortController | null>(null);
  const retired = useRef(new Map<string, HelperLease>());
  const stopping = useRef(new Map<string, Promise<unknown>>());
  const acquisitions = useRef(new Set<{intent: number; generation: number}>());
  const uncertainGenerations = useRef(new Set<number>());
  const intent = useRef(0);
  const lifecycle = useRef(0);
  const mounted = useRef(false);
  const running = useRef(false);
  const pending = useRef(false);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearRetry = () => { if (retryTimer.current) clearTimeout(retryTimer.current); retryTimer.current = null; };
  const placement = useFloatingBar(true, `${collapsed}:${mode}:${Boolean(error)}:${hidden}`);
  useEffect(() => {
    if (!hidden) return;
    setModeMenuOpen(false);
    const focused = document.activeElement;
    if (focused instanceof HTMLElement && placement.paperRef.current?.contains(focused)) focused.blur();
  }, [hidden, placement.paperRef]);
  const unauthorized = useRef(onUnauthorized); unauthorized.current = onUnauthorized;
  const stop = (value: HelperLease) => {
    let result = stopping.current.get(value.session_id);
    if (!result) {
      result = request('/api/helper/stop', 'POST', {session_id: value.session_id}, {keepalive: true});
      stopping.current.set(value.session_id, result);
      const clear = () => { if (stopping.current.get(value.session_id) === result) stopping.current.delete(value.session_id); };
      void result.then(clear, clear);
    }
    return result;
  };
  const cleanup = (value: HelperLease) => stop(value).catch(() => {});
  const releaseKnownLeases = () => {
    const leases = new Map(retired.current);
    if (sessionRef.current) leases.set(sessionRef.current.session_id, sessionRef.current);
    retired.current.clear(); sessionRef.current = null; sessionIntent.current = null;
    for (const lease of leases.values()) void cleanup(lease);
  };
  const retain = (value: HelperLease) => {
    if (value && typeof value.session_id === 'string' && value.session_id) retired.current.set(value.session_id, value);
  };
  const apply = async () => {
    pending.current = true;
    if (running.current) return;
    running.current = true;
    const life = lifecycle.current;
    try {
      while (pending.current && mounted.current && life === lifecycle.current) {
        pending.current = false;
        const operation = intent.current;
        const nextMode = desired.current;
        const controller = new AbortController();
        activeOperation.current = controller;
        let retryable = nextMode === 'native';
        const currentIntent = () => mounted.current && life === lifecycle.current && operation === intent.current;
        const readMode = () => bounded(request<ModeStatus>('/api/browser/mode', 'GET', undefined, {signal: controller.signal}), controller).then(validateMode);
        try {
          // Fresh CAS state prevents a stale tab or response from changing another native lease.
          const current = await readMode();
          if (!currentIntent()) continue;
          for (const generation of uncertainGenerations.current) {
            if (generation < current.generation || (generation === current.generation && !current.active)) uncertainGenerations.current.delete(generation);
          }
          let ownedSession: HelperLease | null = sessionRef.current;
          // Only discard the capability when authoritative status proves its lease is gone.
          if (ownedSession && (!current.active || current.generation !== ownedSession.generation)) {
            sessionRef.current = null; sessionIntent.current = null; setSession(null); ownedSession = null;
          }
          for (const [id, lease] of retired.current) {
            if (!current.active || (Number.isSafeInteger(lease.generation) && current.generation !== lease.generation)) {
              retired.current.delete(id);
              // This exact old ID is harmless even if a newer lease already exists.
              void cleanup(lease);
            } else if (!ownedSession) ownedSession = lease;
          }
          if (current.active && !ownedSession) {
            if (uncertainGenerations.current.has(current.generation)) {
              // Status cannot recover a lost capability. Wait for the exact response
              // or server lease expiry without adopting cookie-level ownership.
              throw new Error('连接状态仍在确认中。');
            }
            retryable = false; throw new Error('另一页面正在使用原生中继。请先在该页面切回软件模拟，或等待连接授权到期。');
          }
          if (ownedSession) {
            if (ownedSession === sessionRef.current && nextMode === 'native' && sessionIntent.current === operation && !addressError.current) { setError(''); continue; }
            try { await bounded(stop(ownedSession), controller); }
            catch (failure) {
              if (!currentIntent() || controller.signal.aborted) throw failure;
              // Panel teardown may have committed the same owner-bound stop first.
              // A failed/lost response never discards the only remaining capability.
              const confirmed = await readMode();
              if (confirmed.active && (!Number.isSafeInteger(ownedSession.generation) || confirmed.generation === ownedSession.generation)) throw failure;
            }
            retired.current.delete(ownedSession.session_id);
            if (sessionRef.current === ownedSession) { sessionRef.current = null; sessionIntent.current = null; setSession(null); }
            if (!currentIntent()) continue;
            pending.current = true; continue;
          }
          if (nextMode === 'native' && addressError.current) { setError(''); continue; }
          if (current.state === 'switching') { await bounded(new Promise(resolve => setTimeout(resolve, 1000)), controller); pending.current = true; continue; }
          if (nextMode === 'software' && current.mode === 'software' && current.state === 'software' && current.control_connected && !current.active) { setError(''); continue; }
          if (nextMode === 'native' && [...acquisitions.current].some(item => item.intent === operation && item.generation === current.generation)) {
            // Do not multiply one hung request on automatic retries. A newer intent
            // may make its own CAS attempt after a fresh read proves the mode idle.
            throw new Error('连接状态仍在确认中。');
          }
          const acquisition = {intent: operation, generation: current.generation};
          if (nextMode === 'native') { acquisitions.current.add(acquisition); uncertainGenerations.current.add(current.generation + 1); }
          let awaiting = true;
          const mutation = request<ModeStatus & HelperSession>('/api/browser/mode', 'POST', {mode: nextMode, expected_generation: current.generation});
          void mutation.then(value => {
            acquisitions.current.delete(acquisition);
            // Retain before delivering to the await: interruption can win the same
            // microtask turn, but must never lose an already-delivered capability.
            if (nextMode === 'native' && value && typeof value.session_id === 'string' && value.session_id) {
              uncertainGenerations.current.delete(value.generation);
              if (mounted.current && life === lifecycle.current) retain(value);
              else void cleanup(value);
            }
            if (!awaiting && mounted.current && life === lifecycle.current) void apply();
          }, failure => {
            acquisitions.current.delete(acquisition);
            if ([400, 401, 403, 409].includes(statusCode(failure) ?? 0) && ![...acquisitions.current].some(item => item.generation === current.generation)) uncertainGenerations.current.delete(current.generation + 1);
            if (!awaiting && mounted.current && life === lifecycle.current) void apply();
          });
          let value: ModeStatus & HelperSession;
          try { value = await bounded(mutation, controller); }
          finally { awaiting = false; }
          if (!currentIntent()) {
            if (nextMode === 'native' && value && typeof value.session_id === 'string' && value.session_id) {
              if (mounted.current && life === lifecycle.current) retain(value); else void cleanup(value);
            }
            continue;
          }
          if (nextMode === 'native') retain(value);
          validateMode(value);
          if (nextMode === 'native') {
            validateSession(value);
            retired.current.delete(value.session_id); uncertainGenerations.current.delete(value.generation);
            sessionRef.current = value; sessionIntent.current = operation; setSession(value);
          } else { sessionRef.current = null; sessionIntent.current = null; setSession(null); }
          setError('');
        } catch (failure) {
          if (!currentIntent()) continue;
          if (statusCode(failure) === 401) { unauthorized.current(); setError(errorMessage(failure)); continue; }
          if (retryable || uncertainGenerations.current.size || retired.current.size) {
            setError(''); clearRetry();
            retryTimer.current = setTimeout(() => {
              retryTimer.current = null;
              if (mounted.current && life === lifecycle.current && operation === intent.current) void apply();
            }, 1000);
          } else setError(errorMessage(failure));
        } finally {
          if (activeOperation.current === controller) activeOperation.current = null;
        }
      }
    } finally {
      running.current = false;
      // StrictMode/unmount may end an earlier lifecycle while a later explicit intent waits.
      if (pending.current && mounted.current) void apply();
    }
  };
  useEffect(() => {
    const generation = ++lifecycle.current;
    mounted.current = true;
    const operation = intent.current;
    const controller = new AbortController(); initialRead.current = controller;
    queueMicrotask(() => {
      if (!mounted.current || generation !== lifecycle.current || operation !== intent.current) return;
      if (desired.current === 'native') {
        try { bridgeAddress(addressRef.current); addressError.current = ''; }
        catch (failure) { addressError.current = errorMessage(failure); }
        void apply(); return;
      }
      void request<ModeStatus>('/api/browser/mode', 'GET', undefined, {signal: controller.signal}).then(value => {
        if (!mounted.current || generation !== lifecycle.current || operation !== intent.current) return;
        const snapshot = validateMode(value);
        if (snapshot.active) setError('原生中继已由另一页面管理。请在原页面操作连接。');
      }).catch(failure => {
        if (!mounted.current || generation !== lifecycle.current || operation !== intent.current) return;
        if (statusCode(failure) === 401) unauthorized.current();
        setError(errorMessage(failure));
      });
    });
    const hide = () => { clearRetry(); activeOperation.current?.abort(); mounted.current = false; lifecycle.current++; intent.current++; pending.current = false; controller.abort(); setSession(null); releaseKnownLeases(); };
    const changeFullscreen = () => setFullscreen(Boolean(document.fullscreenElement));
    window.addEventListener('pagehide', hide); document.addEventListener('fullscreenchange', changeFullscreen);
    return () => {
      clearRetry(); activeOperation.current?.abort(); mounted.current = false; controller.abort(); window.removeEventListener('pagehide', hide); document.removeEventListener('fullscreenchange', changeFullscreen);
      queueMicrotask(() => { if (generation === lifecycle.current && !mounted.current) releaseKnownLeases(); });
    };
  }, []);
  const selectMode = (value: BrowserMode) => {
    if (desired.current === value) return;
    onModeChange?.();
    saveBrowserMode(value);
    clearRetry(); intent.current++; initialRead.current?.abort(); activeOperation.current?.abort(); desired.current = value; setMode(value); setError('');
    if (value === 'native') {
      try { bridgeAddress(addressRef.current); addressError.current = ''; }
      catch (failure) { addressError.current = errorMessage(failure); }
    }
    // Removing the panel immediately closes transport and aborts forwarding.
    if (value === 'software') setSession(null);
    void apply();
  };
  const updateAddress = (value: string) => { addressRef.current = value; setAddress(value); saveHelperAddress(value); };
  const start = (value = addressRef.current) => {
    updateAddress(value);
    try { bridgeAddress(value); addressError.current = ''; }
    catch (failure) { addressError.current = errorMessage(failure); }
    // Every sampled address or explicit Connect is a new intent, even during
    // a pending request. Read waits end now; mutation capabilities are retained.
    clearRetry(); intent.current++; initialRead.current?.abort(); activeOperation.current?.abort();
    saveBrowserMode('native'); desired.current = 'native'; setMode('native'); setError(''); setSession(null);
    void apply();
    return true;
  };
  const secondaryHidden = collapsed || mode !== 'native';
  return <><Paper ref={placement.paperRef} variant="outlined" component="section" id="browser-controls" className="browser-controls" aria-label="浏览器控制栏" hidden={hidden} inert={hidden || undefined} aria-hidden={hidden || undefined}
    sx={{position: 'fixed', zIndex: theme => theme.zIndex.appBar, left: 16, bottom: 16, maxWidth: 'calc(100vw - 16px)', width: collapsed ? 'auto' : {xs: 'calc(100vw - 32px)', sm: 'auto'}, boxSizing: 'border-box', height: mode === 'software' || collapsed ? 50 : 'auto', py: '8px', px: '12px'}}
    style={placement.position ? {left: placement.position.x, top: placement.position.y, right: 'auto', bottom: 'auto'} : undefined}>
    <Stack spacing={1.5} useFlexGap>
      <Stack className="browser-control-toolbar" direction="row" sx={{alignItems: 'center', gap: 1, height: 32, minHeight: 32, flexWrap: 'nowrap'}}>
      <Stack direction="row" sx={{alignItems: 'center', flexShrink: 0, height: 32, '& .MuiIconButton-root': {width: 32, height: 32}}}>
        <Tooltip title="移动控制栏"><IconButton size="small" aria-label="移动控制栏" aria-description="使用方向键移动，按住 Shift 微调。" sx={{cursor: 'move', touchAction: 'none'}} {...placement.handleProps}><DragIndicatorIcon fontSize="small" /></IconButton></Tooltip>
        <Tooltip title={collapsed ? '展开控制栏' : '收起控制栏'}><IconButton size="small" aria-label={collapsed ? '展开控制栏' : '收起控制栏'} aria-expanded={!collapsed} aria-controls="browser-control-content browser-control-secondary-content" onClick={() => setCollapsed(value => !value)}>{collapsed ? <KeyboardDoubleArrowRightIcon fontSize="small" /> : <KeyboardDoubleArrowLeftIcon fontSize="small" />}</IconButton></Tooltip>
      </Stack>
      <Stack id="browser-control-content" hidden={collapsed} sx={{display: collapsed ? 'none' : 'flex', height: 32, minWidth: 0, flex: '1 1 auto'}}>
        <Box className="browser-control-scroll" role="group" aria-label="浏览器操作" tabIndex={0} sx={{height: 44, minHeight: 44, my: '-6px', py: '6px', boxSizing: 'border-box', overflowX: 'auto', overflowY: 'hidden', scrollbarWidth: 'none', '&::-webkit-scrollbar': {display: 'none'}}}>
        <Stack className="browser-control-main-row" direction="row" sx={{alignItems: 'center', gap: .5, height: 32, width: 'max-content', minWidth: '100%', flexWrap: 'nowrap', '& .MuiIconButton-root': {width: 32, height: 32}}}>
          <FormControl size="small" sx={{...compactControlSx, minWidth: 96, flexShrink: 0}}><InputLabel id="browser-mode-label" sx={compactControlFontSx}>模式</InputLabel><Select size="small" sx={compactControlFontSx} labelId="browser-mode-label" label="模式" value={mode} open={!hidden && modeMenuOpen} onOpen={() => setModeMenuOpen(true)} onClose={() => setModeMenuOpen(false)} MenuProps={{disableRestoreFocus: hidden}} onChange={event => selectMode(event.target.value as BrowserMode)}><MenuItem value="native" sx={{...compactControlFontSx, minHeight: 32, py: '7px'}}>原生中继</MenuItem><MenuItem value="software" sx={{...compactControlFontSx, minHeight: 32, py: '7px'}}>软件模拟</MenuItem></Select></FormControl>
          <Tooltip title={authConnection.message}><Stack id="request-connection" direction="row" className="connection auth-connection" data-state={authConnection.state} role="status" aria-live="polite" aria-label={authConnection.message} tabIndex={0} sx={{alignItems: 'center', gap: .65, ml: .5, flexShrink: 0, whiteSpace: 'nowrap'}}><VerifiedUserOutlinedIcon aria-hidden="true" sx={{fontSize: 18, color: authConnection.state === 'connected' ? 'success.main' : 'text.secondary'}} /><Typography className="connection-label" variant="caption" sx={{display: {xs: 'none', sm: 'inline'}}}>{authConnection.message}</Typography></Stack></Tooltip>
          <Tooltip title={reconnecting ? '正在处理浏览器' : '重启浏览器并恢复标签页'}><span><IconButton aria-label="重新连接" size="small" disabled={reconnecting} onClick={onReconnect}><RefreshIcon fontSize="small" /></IconButton></span></Tooltip>
          <Tooltip title="向远程桌面发送 Ctrl+Alt+Delete"><span><IconButton aria-label="Ctrl+Alt+Delete" className="ctrl-alt-delete" size="small" disabled={reconnecting || !connected} onClick={onCtrlAltDelete}><KeyboardOutlinedIcon fontSize="small" /></IconButton></span></Tooltip>
          <Tooltip title={fullscreen ? '退出全屏' : '全屏'}><IconButton aria-label={fullscreen ? '退出全屏' : '全屏'} size="small" onClick={onFullscreen}>{fullscreen ? <FullscreenExitIcon fontSize="small" /> : <FullscreenIcon fontSize="small" />}</IconButton></Tooltip>
        </Stack>
        </Box>
      </Stack>
      </Stack>
      <Stack id="browser-control-secondary-content" hidden={secondaryHidden} spacing={1.5} useFlexGap sx={{display: secondaryHidden ? 'none' : 'flex', minWidth: 0}}>
        {mode === 'native' && <Box className="browser-control-native-row"><HelperConnection session={session} address={address} onAddress={updateAddress} onConnect={start} onClose={() => { if (sessionRef.current !== session) return; sessionRef.current = null; sessionIntent.current = null; setSession(null); }} /></Box>}
        {mode === 'native' && error && <Alert severity="error" action={<Button size="small" onClick={() => void apply()}>重试</Button>} sx={{py: 0, maxWidth: 460, overflowWrap: 'anywhere'}}>{error}</Alert>}
      </Stack>
    </Stack>
  </Paper>
    {!hidden && mode === 'software' && error && <Alert className="browser-control-error" severity="error" action={<Button size="small" onClick={() => void apply()}>重试</Button>} sx={{position: 'fixed', zIndex: theme => theme.zIndex.appBar + 1, left: 16, bottom: 74, maxWidth: 'min(460px, calc(100vw - 32px))', boxSizing: 'border-box', py: 0, overflowWrap: 'anywhere'}}>{error}</Alert>}
  </>;
}
