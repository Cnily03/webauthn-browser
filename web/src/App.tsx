import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Paper, Stack, TextField, Typography } from '@mui/material';
import { ApiError, browserTransportUrl, request, setCsrfToken } from './api';
import { profileDestination, retainProfileSelection, profileResourcePath, type PublicBrowserProfile, type ProfileViewer, type NavigateProfile } from './profiles';
import type { AppStatus } from './types';
import Settings from './Settings';
import Downloads from './Downloads';
import { AppNotificationContext, useAppNotification, type Notify } from './AppNotifications';
import { useGuardedNavigation, type NavigationGuard } from './useGuardedNavigation';
import { AuthRequests, type AuthConnection } from './AuthRequests';
import { NavigationBar } from './NavigationBar';
import { BrowserControls } from './BrowserControls';
import { ClipboardSync } from './ClipboardSync';
import { installRemoteCursorGuard } from './remoteCursor';

interface RfbClient {
  scaleViewport: boolean;
  resizeSession: boolean;
  clipViewport: boolean;
  viewOnly?: boolean;
  disconnect: () => void;
  sendCtrlAltDel?: () => void;
  sendKey: (keysym: number, code?: string, down?: boolean) => void;
  focus: () => void;
  addEventListener: (event: string, callback: () => void) => void;
}
type Connection = { state: 'connecting' | 'connected' | 'disconnected' | 'error'; label: string };
type BrowserAction = 'ensure' | 'restart';
type ReconnectOperation = { controller: AbortController; previousConnection: Connection; progressConnection: Connection; action: BrowserAction; requestId: string };
interface BrowserOperationMetadata {operation_scope: string; operation_sequence: string}
interface BrowserActionResult extends BrowserOperationMetadata {ok: boolean; action: BrowserAction; request_id: string; restarted: boolean; engine_ready: boolean; window_count: number}
function validOperationMetadata(value: BrowserOperationMetadata) {
  return value && typeof value.operation_scope === 'string' && value.operation_scope.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.operation_scope)
    && typeof value.operation_sequence === 'string' && /^[1-9][0-9]{0,19}$/.test(value.operation_sequence)
    && BigInt(value.operation_sequence).toString() === value.operation_sequence
    && BigInt(value.operation_sequence) <= 18446744073709551615n;
}
function waitForBrowserAdmission(signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, 1000);
    signal.addEventListener('abort', abort, {once: true});
    if (signal.aborted) { signal.removeEventListener('abort', abort); abort(); }
  });
}
function operationId() {
  // getRandomValues also works on HTTP deployments without randomUUID support.
  const bytes = crypto.getRandomValues(new Uint8Array(16)); bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
const errorMessage = (error: unknown) => error instanceof Error ? error.message : '请求失败，请重试。';
// Bound the existing-window operation, including status revalidation and
// response bodies. A successful operation then replaces the RFB transport.
const RECONNECT_TIMEOUT_MS = 60_000;

function Login({ scope, onUnlocked, notify }: { scope: 'vnc' | 'settings'; onUnlocked: () => Promise<AppStatus>; notify: Notify }) {
  const input = useRef<HTMLInputElement>(null);
  const submitting = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const setInput = useCallback((element: HTMLInputElement | null) => { if (!element && input.current) input.current.value = ''; input.current = element; }, []);
  useEffect(() => { const clear = () => { if (input.current) input.current.value = ''; }; window.addEventListener('pagehide', clear); return () => window.removeEventListener('pagehide', clear); }, []);
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    setError('');
    try { const result = request('/api/login', 'POST', { scope, password: input.current?.value || '' }); if (input.current) input.current.value = ''; await result; await onUnlocked(); notify(''); }
    catch (err) { setError(errorMessage(err)); input.current?.focus(); }
    finally { if (input.current) input.current.value = ''; submitting.current = false; setBusy(false); }
  };
  return <Box className="login-page"><Paper variant="outlined" className="login-card"><Stack spacing={3}><Box><Typography variant="overline" color="text.secondary">WebAuthn Browser</Typography><Typography variant="h1">{scope === 'settings' ? '解锁设置' : '解锁浏览器'}</Typography><Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>{scope === 'settings' ? '输入设置密码以管理安全选项和虚拟验证器。' : '输入浏览器访问密码以连接远程桌面。'}</Typography></Box><Box component="form" onSubmit={submit}><Stack spacing={2.5}><TextField inputRef={setInput} autoFocus label="密码" name="password" type="password" autoComplete="current-password" disabled={busy} />{error && <Alert severity="error">{error}</Alert>}<Button type="submit" variant="contained" disabled={busy} fullWidth>{busy ? '正在解锁…' : '解锁'}</Button></Stack></Box></Stack></Paper></Box>;
}

// Reuse an in-flight module load across StrictMode mounts and RFB replacements.
// Failed loads are evicted so an explicit retry can recover after auth/network loss.
const remoteModules = new Map<string, Promise<any>>();
function loadRemoteDesktop(path: string) {
  let pending = remoteModules.get(path);
  if (!pending) {
    pending = import(/* @vite-ignore */ path).catch(error => { remoteModules.delete(path); throw error; });
    remoteModules.set(path, pending);
  }
  return pending;
}

function BrowserView({ navigationEpoch, connection, status, refreshStatus, onUnauthorized, notify, onConnection, onAuthConnection, clientRef, viewOnly = false, profiled = false, onTransportDisconnect }: { viewOnly?: boolean; profiled?: boolean; onTransportDisconnect?: () => void; navigationEpoch: string; connection: Connection; status: AppStatus; refreshStatus: () => Promise<AppStatus>; onUnauthorized: () => void; notify: Notify; onConnection: (connection: Connection) => void; onAuthConnection: (connection: AuthConnection) => void; clientRef: React.MutableRefObject<RfbClient | null> }) {
  const screen = useRef<HTMLDivElement>(null);
  const [clipboardConnected, setClipboardConnected] = useState(false);
  const readOnly = useRef(viewOnly); readOnly.current = viewOnly;
  useEffect(() => { if (clientRef.current) clientRef.current.viewOnly = viewOnly; }, [viewOnly, clientRef]);
  useEffect(() => {
    let disposed = false;
    let client: RfbClient | null = null;
    const transport = new AbortController();
    const cursor = screen.current ? installRemoteCursorGuard(screen.current) : null;
    const disconnect = () => { if (disposed) return; disposed = true; transport.abort(); if (clientRef.current === client) clientRef.current = null; try { client?.disconnect(); } finally { cursor?.dispose(); } };
    const current = () => !disposed && clientRef.current === client;
    const connect = async () => {
      onConnection({ state: 'connecting', label: '正在连接浏览器…' });
      try {
        // This runtime URL is served by the same origin. noVNC exclusively owns
        // the child DOM of this ref; the rest of the application is React/MUI.
        const modulePath = profiled ? profileResourcePath('/novnc/core/rfb.js') : '/novnc/core/rfb.js';
        const { default: RFB } = await loadRemoteDesktop(modulePath);
        if (disposed || !screen.current) return;
        const url = await browserTransportUrl('/ws', 'vnc', transport.signal);
        if (disposed || !screen.current) return;
        client = new RFB(screen.current, url.href) as RfbClient;
        clientRef.current = client;
        cursor?.refresh();
        client.scaleViewport = true;
        client.resizeSession = !profiled;
        client.viewOnly = readOnly.current;
        client.clipViewport = false;
        client.addEventListener('connect', () => { if (!current()) return; setClipboardConnected(true); onConnection({ state: 'connected', label: '浏览器已连接' }); });
        client.addEventListener('disconnect', () => {
          if (!current()) return;
          setClipboardConnected(false);
          onConnection({ state: 'disconnected', label: '连接已断开' });
          onTransportDisconnect?.();
          void refreshStatus().then(latest => { if (current() && !latest.vnc_authenticated) onUnauthorized(); }).catch(() => { /* The reconnect control remains available after a network error. */ });
        });
        client.addEventListener('securityfailure', () => { if (!current()) return; setClipboardConnected(false); onConnection({ state: 'error', label: '连接验证失败' }); notify('远程桌面连接验证失败，请重新连接或检查服务配置。', true); });
        client.addEventListener('credentialsrequired', () => { if (!current()) return; setClipboardConnected(false); onConnection({ state: 'error', label: '远程桌面需要额外验证' }); notify('内部 VNC 服务要求额外凭据，请检查服务配置。访问密码由本应用处理。', true); });
      } catch (error) { if (disposed) return; onConnection({ state: 'error', label: '暂时无法连接' }); notify(errorMessage(error), true); }
    };
    void connect();
    window.addEventListener('pagehide', disconnect);
    return () => { window.removeEventListener('pagehide', disconnect); disconnect(); };
  }, [clientRef, refreshStatus, onUnauthorized, notify, onConnection, profiled, onTransportDisconnect]);
  return <><Box component="section" className="desktop" aria-label="浏览器远程桌面"><Box ref={screen} className="vnc-screen" aria-label="Chromium 远程桌面" />{!clipboardConnected && <Box className="vnc-placeholder" role="status" aria-live="polite"><Typography variant="body2" color="inherit">{connection.label}</Typography></Box>}</Box><Stack spacing={1} className="request-status"><ClipboardSync connected={clipboardConnected && !viewOnly} copyAgain={() => { const client = clientRef.current; if (!client) return; client.focus(); client.sendKey(0xffe3, 'ControlLeft', true); try { client.sendKey(0x63, 'KeyC'); } finally { client.sendKey(0xffe3, 'ControlLeft', false); } }} />{!viewOnly && <AuthRequests navigationEpoch={navigationEpoch} onConnectionChange={onAuthConnection} status={status} refreshStatus={refreshStatus} onUnauthorized={onUnauthorized} notify={notify} />}</Stack></>;
}

export interface ProfileAccess extends PublicBrowserProfile { viewer: ProfileViewer | null; onDisconnected: () => void; onLocked: (reason?: 'unauthorized' | 'unavailable' | 'logout') => void }
export default function App({profile, multiProfile = true, navigateDocument = (path: string) => window.location.assign(path), onLocationChange, browserDestination, navigateProfile}: {profile?: ProfileAccess | null; multiProfile?: boolean; navigateDocument?: (path: string) => void; onLocationChange?: (url: string) => void; browserDestination?: string; navigateProfile?: NavigateProfile} = {}) {
  const canControl = profile === undefined || Boolean(profile?.viewer?.owner && !profile.viewer.expired);
  const profileLocked = profile?.onLocked;
  const navigationGuard = useRef<NavigationGuard | null>(null);
  const registerNavigationGuard = useCallback((guard: NavigationGuard | null) => { navigationGuard.current = guard; }, []);
  const guardNavigation = useCallback<NavigationGuard>(action => { if (navigationGuard.current) return navigationGuard.current(action); action(); return true; }, []);
  const navigation = useGuardedNavigation(guardNavigation);
  useEffect(() => { onLocationChange?.(navigation.url); }, [navigation.url, onLocationChange]);
  const path = new URL(navigation.url).pathname.replace(/\/$/, '');
  const isSettings = path === '/settings';
  const isSettingsRef = useRef(isSettings); isSettingsRef.current = isSettings;
  const isDownloads = path === '/downloads';
  const isBrowser = !isSettings && !isDownloads;
  const browserHome = isDownloads ? '/' : browserDestination ?? (profile ? profileDestination(profile, multiProfile) : '/');
  useEffect(() => {
    if (profile && isBrowser && (multiProfile || profile.name === 'default')) {
      navigation.replace(profileDestination(profile, multiProfile));
      retainProfileSelection(profile, multiProfile);
    }
  }, [navigation.url, navigation.replace, profile?.name, isBrowser, multiProfile]);
  useEffect(() => { if (isDownloads) navigation.replace('/downloads'); }, [isDownloads, navigation.url, navigation.replace]);
  const scope = isSettings ? 'settings' : 'vnc';
  const [status, setStatus] = useState<AppStatus | null>(null);
  const statusRef = useRef<AppStatus | null>(null);
  const [initialError, setInitialError] = useState('');
  const [initializing, setInitializing] = useState(true);
  const [suspended, setSuspended] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [connection, setConnection] = useState<Connection>({ state: 'connecting', label: '正在连接浏览器…' });
  const connectionRef = useRef(connection);
  const onConnection = useCallback((next: Connection) => { connectionRef.current = next; setConnection(next); }, []);
  const [authConnection, setAuthConnection] = useState<AuthConnection>({ state: 'connecting', message: '验证事件连接中…' });
  const [desktopVersion, setDesktopVersion] = useState(0);
  const [navigationEpoch, setNavigationEpoch] = useState(0);
  const invalidateLocalNavigation = useCallback(() => setNavigationEpoch(value => value + 1), []);
  const clientRef = useRef<RfbClient | null>(null);
  const [working, setWorking] = useState<'logout' | 'reconnect' | null>(null);
  const workingRef = useRef<'logout' | 'reconnect' | null>(null);
  const reconnectOperation = useRef<ReconnectOperation | null>(null);
  const ensured = useRef(false);
  const sessionGeneration = useRef(0);
  const statusRequestSequence = useRef(0);
  const initializationSequence = useRef(0);
  const pageLifecycleSequence = useRef(0);
  const mounted = useRef(true);
  const notification = useAppNotification();
  const inheritedNotify = useContext(AppNotificationContext);
  const notify = inheritedNotify ?? notification.notify;

  const cancelReconnect = useCallback(() => {
    const operation = reconnectOperation.current;
    if (!operation) return;
    // Revoke ownership before aborting: a late completion must not clear a
    // newer operation or publish a stale authenticated status/CSRF token.
    reconnectOperation.current = null;
    operation.controller.abort();
    if (workingRef.current === 'reconnect') workingRef.current = null;
    if (!mounted.current) return;
    if (connectionRef.current === operation.progressConnection) onConnection(operation.previousConnection);
    setWorking(null);
  }, [onConnection]);
  const refreshStatus = useCallback(async (signal?: AbortSignal, settingsOnly = false) => {
    const generation = sessionGeneration.current;
    const sequence = ++statusRequestSequence.current;
    const response = await request<AppStatus>('/api/status', 'GET', undefined, {...(signal ? {signal} : {}), ...(settingsOnly ? {scope: 'global' as const} : {})});
    // Global admin authorization must not depend on a disabled/revoked browser
    // profile, nor replace that profile's browser status with the default's.
    const latest = settingsOnly && profile && statusRef.current ? {...statusRef.current, csrf_token: response.csrf_token,
      settings_authenticated: response.settings_authenticated, settings_password_enabled: response.settings_password_enabled} : response;
    if (mounted.current && !signal?.aborted && generation === sessionGeneration.current && sequence === statusRequestSequence.current) {
      const previous = statusRef.current;
      setCsrfToken(latest.csrf_token);
      statusRef.current = latest;
      setStatus(latest);
      // A newer locked snapshot revokes every older in-flight status request.
      if ((previous?.vnc_authenticated && !latest.vnc_authenticated) || (previous?.settings_authenticated && !latest.settings_authenticated)) {
        sessionGeneration.current += 1;
        cancelReconnect();
      }
      return latest;
    }
    // Never publish a stale authenticated response or restore its CSRF token.
    return statusRef.current || { csrf_token: '', vnc_authenticated: false, settings_authenticated: false, vnc_password_enabled: false, settings_password_enabled: false };
  }, [cancelReconnect, Boolean(profile)]);
  const refreshSettingsStatus = useCallback(() => refreshStatus(undefined, true), [refreshStatus]);
  const lockScope = useCallback((lockedScope: 'vnc' | 'settings') => {
    cancelReconnect();
    sessionGeneration.current += 1;
    if (!statusRef.current) return;
    const locked = { ...statusRef.current, [`${lockedScope}_authenticated`]: false };
    statusRef.current = locked;
    setStatus(locked);
    if (lockedScope === 'vnc') setDesktopVersion(value => value + 1);
  }, [cancelReconnect]);
  const onVncUnauthorized = useCallback(() => { lockScope('vnc'); profileLocked?.('unauthorized'); }, [lockScope, profileLocked]);
  const onSettingsUnauthorized = useCallback(() => lockScope('settings'), [lockScope]);
  const onUnauthorized = isSettings ? onSettingsUnauthorized : onVncUnauthorized;
  const initialize = useCallback(async () => {
    const generation = sessionGeneration.current;
    const sequence = ++initializationSequence.current;
    setInitializing(true);
    setInitialError('');
    try { await refreshStatus(undefined, isSettingsRef.current); }
    catch (error) { if (mounted.current && generation === sessionGeneration.current && sequence === initializationSequence.current) setInitialError(errorMessage(error)); }
    // A successful locked snapshot can revoke the auth generation; that must
    // still settle this initialization and reveal Login instead of a spinner.
    finally { if (mounted.current && sequence === initializationSequence.current) setInitializing(false); }
  }, [refreshStatus]);
  useEffect(() => { mounted.current = true; void initialize(); return () => { mounted.current = false; cancelReconnect(); sessionGeneration.current += 1; initializationSequence.current += 1; pageLifecycleSequence.current += 1; }; }, [initialize, cancelReconnect]);
  useEffect(() => cancelReconnect, [navigation.url, cancelReconnect]);
  useEffect(() => {
    const hide = () => { cancelReconnect(); ensured.current = false; pageLifecycleSequence.current += 1; sessionGeneration.current += 1; setSuspended(true); };
    const show = (event: PageTransitionEvent) => {
      if (!event.persisted) return;
      const sequence = ++pageLifecycleSequence.current;
      setSuspended(true);
      void refreshStatus(undefined, isSettingsRef.current).then(() => { if (!mounted.current || sequence !== pageLifecycleSequence.current) return; setInitialError(''); setDesktopVersion(value => value + 1); setSuspended(false); }).catch(error => { if (!mounted.current || sequence !== pageLifecycleSequence.current) return; setInitialError(errorMessage(error)); setSuspended(false); });
    };
    window.addEventListener('pagehide', hide); window.addEventListener('pageshow', show);
    return () => { window.removeEventListener('pagehide', hide); window.removeEventListener('pageshow', show); };
  }, [refreshStatus, cancelReconnect]);
  const navigate = (event: React.MouseEvent<HTMLAnchorElement>, destination: '/' | '/settings' | '/downloads') => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.currentTarget.target === '_blank') return;
    event.preventDefault();
    const targetPath = destination === '/' ? browserHome : destination;
    if (isDownloads && destination === '/' && profile !== undefined) {guardNavigation(() => navigateDocument('/')); return;}
    if ((profile === null && destination === '/') || (profile && (!profile.viewer || browserDestination) && destination === '/')) { guardNavigation(() => {
      if (browserDestination === '/') navigateDocument('/');
      else if (profile && navigateProfile) void navigateProfile(profile).catch(failure => notify(errorMessage(failure), true));
      else navigateDocument(targetPath);
    }); return; }
    const currentUrl = new URL(navigation.url);
    const targetUrl = new URL(targetPath, currentUrl);
    if (currentUrl.pathname.replace(/\/$/, '') === targetUrl.pathname.replace(/\/$/, '') && currentUrl.search === targetUrl.search) return;
    const target = event.currentTarget;
    navigation.navigate(targetPath, () => target.focus());
  };
  const authenticated = Boolean(status?.[`${scope}_authenticated`]);
  const passwordEnabled = Boolean(status?.[`${scope}_password_enabled`]);
  const logout = async () => {
    if (workingRef.current === 'logout') return;
    cancelReconnect();
    workingRef.current = 'logout';
    setWorking('logout');
    sessionGeneration.current += 1;
    if (scope === 'vnc') profileLocked?.('logout');
    if (statusRef.current) { const locked = { ...statusRef.current, [`${scope}_authenticated`]: false }; statusRef.current = locked; setStatus(locked); }
    try { await request('/api/logout', 'POST', { scope }); await (scope === 'settings' ? refreshSettingsStatus() : refreshStatus()); notify('会话已锁定。'); }
    catch (error) { notify(errorMessage(error), true); if (error instanceof ApiError && error.status === 401) onUnauthorized(); }
    finally { workingRef.current = null; if (mounted.current) setWorking(null); }
  };
  const browserAction = useCallback(async (action: BrowserAction) => {
    if (workingRef.current || !mounted.current || !statusRef.current?.vnc_authenticated || !canControl) return;
    const operation: ReconnectOperation = {
      controller: new AbortController(), previousConnection: connectionRef.current,
      progressConnection: { state: 'connecting', label: action === 'restart' ? '正在重启浏览器…' : '正在准备浏览器窗口…' },
      action, requestId: operationId(),
    };
    reconnectOperation.current = operation;
    workingRef.current = 'reconnect';
    setWorking('reconnect');
    const generation = sessionGeneration.current;
    const { signal } = operation.controller;
    const current = () => mounted.current && reconnectOperation.current === operation && generation === sessionGeneration.current;
    // Keep the current transport usable until the existing-window operation
    // succeeds and authorization is revalidated. Failure does not drop it.
    if (connectionRef.current.state !== 'connected') onConnection(operation.progressConnection);
    let interrupted!: () => void;
    const interruption = new Promise<never>((_, reject) => {
      interrupted = () => reject(signal.reason);
      signal.addEventListener('abort', interrupted, { once: true });
    });
    const timeout = setTimeout(() => operation.controller.abort(new Error('重新连接等待超时，请检查服务状态后重试。')), RECONNECT_TIMEOUT_MS);
    try {
      // Race explicitly as well as aborting fetch, so an unresponsive transport
      // cannot strand the controls. Only a definitely unadmitted initial ensure
      // may retry; uncertain responses and manual restarts are never replayed.
      await Promise.race([interruption, (async () => {
        let result: BrowserActionResult;
        while (true) {
          const metadata = await request<BrowserOperationMetadata>('/api/browser/reconnect', 'GET', undefined, { signal });
          if (!current() || signal.aborted) return;
          if (!validOperationMetadata(metadata)) throw new Error('浏览器操作信息无效，请重试。');
          // Sample at admission, including after a definite-rejection retry. A
          // new ensure/restart must not reuse a previous desktop's dimensions;
          // ordinary window resizing never submits a lifecycle operation.
          const viewport = profile ? {
            width: Math.min(7680, Math.max(320, Math.floor(window.innerWidth))),
            height: Math.min(4320, Math.max(240, Math.floor(window.innerHeight))),
          } : undefined;
          // Preserve the public u64 counter as a string, including above 2^53.
          const intent = {action, request_id: operation.requestId, operation_scope: metadata.operation_scope, operation_sequence: metadata.operation_sequence, ...(viewport ? {viewport} : {})};
          try {
            result = await request<BrowserActionResult>('/api/browser/reconnect', 'POST', intent, { signal });
          } catch (error) {
            if (!current() || signal.aborted) return;
            if (action !== 'ensure' || !(error instanceof ApiError) || error.status !== 409
                || !['stale_browser_intent', 'browser_operation_busy'].includes(error.code || '')) throw error;
            await waitForBrowserAdmission(signal);
            if (!current() || signal.aborted) return;
            operation.requestId = operationId();
            continue;
          }
          if (!current() || signal.aborted) return;
          if (result?.operation_scope !== intent.operation_scope || result?.operation_sequence !== intent.operation_sequence) throw new Error('浏览器操作响应不匹配，请重试。');
          break;
        }
        if (!current() || signal.aborted) return;
        if (result.ok !== true || result.action !== action || result.request_id !== operation.requestId || result.window_count !== 1
            || result.restarted !== (action === 'restart') || typeof result.engine_ready !== 'boolean') throw new Error('浏览器操作响应不匹配，请重试。');
        const latest = await refreshStatus(signal);
        if (!current() || signal.aborted) return;
        if (!latest.vnc_authenticated) { onVncUnauthorized(); return; }
        // After the backend restart, replace RFB even if its old client still
        // reports connected. The native controls stay mounted and reconcile
        // their actual lease separately; this key only replaces the remote view.
        if (action === 'restart' || ['disconnected', 'error'].includes(connectionRef.current.state)) setDesktopVersion(value => value + 1);
        notify(action === 'restart' && !result.engine_ready ? '浏览器已重启，验证引擎连接中。' : '');
      })()]);
    } catch (error) {
      if (!current()) return;
      if (connectionRef.current.state !== 'connected') onConnection({ state: 'error', label: '恢复失败，请重试' });
      notify(errorMessage(error), true);
      if (error instanceof ApiError && error.status === 401) onVncUnauthorized();
    } finally {
      clearTimeout(timeout);
      signal.removeEventListener('abort', interrupted);
      if (reconnectOperation.current === operation) {
        reconnectOperation.current = null;
        workingRef.current = null;
        if (mounted.current) setWorking(null);
      }
    }
  }, [refreshStatus, onVncUnauthorized, onConnection, notify, canControl, Boolean(profile)]);
  useEffect(() => { if (!canControl) cancelReconnect(); }, [canControl, cancelReconnect]);
  useEffect(() => {
    if (!status?.vnc_authenticated || !canControl) { ensured.current = false; return; }
    if (initializing || suspended || initialError) return;
    let current = true;

    // StrictMode cancels its first effect before this microtask runs. Only the
    // surviving authenticated lifecycle sends the initial non-destructive ensure.
    queueMicrotask(() => {
      if (!current || ensured.current || !mounted.current) return;
      ensured.current = true;
      void browserAction('ensure');
    });
    return () => { current = false; };
  }, [status?.vnc_authenticated, initializing, suspended, initialError, browserAction, canControl]);
  const fullscreen = async () => {
    try { if (document.fullscreenElement) await document.exitFullscreen(); else if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen(); else notify('当前浏览器不支持全屏。', true); }
    catch (error) { notify(errorMessage(error), true); }
  };
  const collapsedHeader = isBrowser && collapsed;
  return <Box className={isSettings ? 'app settings-route' : isDownloads ? 'app downloads-route' : 'app browser-route'}>
    <NavigationBar collapsible={isBrowser} collapsed={collapsedHeader} onToggle={() => setCollapsed(value => !value)}>
      <Stack component="nav" direction="row" spacing={.5} aria-label="主导航"><Button component="a" href={!isDownloads && profile && !profile.effective_enabled && !browserDestination ? undefined : browserHome} disabled={Boolean(!isDownloads && profile && !profile.effective_enabled && !browserDestination)} onClick={event => navigate(event, '/')} color="inherit" className={isBrowser ? 'current-route' : ''} aria-current={isBrowser ? 'page' : undefined}>浏览器</Button><Button component="a" href="/settings" onClick={event => navigate(event, '/settings')} color="inherit" className={isSettings ? 'current-route' : ''} aria-current={isSettings ? 'page' : undefined}>设置</Button><Button component="a" href="/downloads" onClick={event => navigate(event, '/downloads')} color="inherit" className={isDownloads ? 'current-route' : ''} aria-current={isDownloads ? 'page' : undefined}>下载</Button>{!isDownloads && authenticated && passwordEnabled && <Button color="inherit" onClick={() => void logout()} disabled={working === 'logout'} className="lock-button">锁定会话</Button>}</Stack>
    </NavigationBar>
    {status?.vnc_authenticated && !suspended && canControl && <BrowserControls onModeChange={invalidateLocalNavigation} hidden={!isBrowser || initializing || Boolean(initialError)} authConnection={authConnection} connected={connection.state === 'connected'} reconnecting={working === 'reconnect'} onReconnect={() => void browserAction('restart')} onCtrlAltDelete={() => clientRef.current?.sendCtrlAltDel?.()} onFullscreen={() => void fullscreen()} onUnauthorized={onVncUnauthorized} />}
    {profile?.viewer && status?.vnc_authenticated && !suspended && !initializing && !initialError && working !== 'logout' && <Box hidden={!isBrowser} inert={!isBrowser || undefined} aria-hidden={!isBrowser || undefined} sx={{display: isBrowser ? undefined : 'none'}}>
      <BrowserView key={`${profile.viewer.viewer_id}:${desktopVersion}`} profiled viewOnly={!canControl} onTransportDisconnect={profile?.onDisconnected} navigationEpoch={`${navigationEpoch}:${navigation.url}`} connection={connection} status={status} refreshStatus={refreshStatus} onUnauthorized={onVncUnauthorized} notify={notify} onConnection={onConnection} onAuthConnection={setAuthConnection} clientRef={clientRef} />
    </Box>}
    <Box component="main" id="app">
      {isDownloads ? <Downloads /> : initializing || suspended || working === 'logout' ? <Stack direction="row" className="page-loading" role="status" sx={{ alignItems: "center", justifyContent: "center", gap: 2 }}><CircularProgress size={22} /><Typography variant="body2">{working === 'logout' ? '正在锁定会话…' : '正在连接…'}</Typography></Stack> : initialError || !status ? <Box className="page-error"><Paper variant="outlined"><Typography variant="h2">暂时无法连接服务</Typography><Typography variant="body2" color="text.secondary">{initialError || '请检查服务是否已启动，然后重试。'}</Typography><Button variant="contained" onClick={() => void initialize()}>重试</Button></Paper></Box> : !authenticated ? <Login key={scope} scope={scope} onUnlocked={scope === 'settings' ? refreshSettingsStatus : refreshStatus} notify={notify} /> : isSettings ? <Settings status={status} refreshStatus={refreshSettingsStatus} onUnauthorized={onSettingsUnauthorized} notify={notify} registerNavigationGuard={registerNavigationGuard} navigation={navigation} /> : profile !== undefined ? null : <BrowserView key={desktopVersion} navigationEpoch={`${navigationEpoch}:${navigation.url}`} connection={connection} status={status} refreshStatus={refreshStatus} onUnauthorized={onVncUnauthorized} notify={notify} onConnection={onConnection} onAuthConnection={setAuthConnection} clientRef={clientRef} />}
    </Box>
    {!inheritedNotify && notification.snackbar}
  </Box>;
}
