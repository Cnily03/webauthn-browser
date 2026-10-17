import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Paper, Stack, TextField, Typography } from '@mui/material';
import App from './App';
import { AppNotificationContext, useAppNotification } from './AppNotifications';
import { ApiError, request, setCsrfToken } from './api';
import { bindBrowserProfile, canonicalProfileName, browserProfileName, clearProfileNavigation, prepareProfileNavigation, profileDestination, readProfileChooser, retainProfileSelection, rememberProfile, savedProfiles, setSavedProfileStatus, validProfileName, type PublicBrowserProfile, type PublicProfileConfiguration, type ProfileStatus, type NavigateProfile } from './profiles';
import type { AppStatus } from './types';
import { useProfileViewer } from './useProfileViewer';
import { NavigationBar, ProfileNavigationContext } from './NavigationBar';

function validateConfiguration(value: PublicProfileConfiguration) {
  if (!value || typeof value.multi_profile !== 'boolean' || !Array.isArray(value.profiles) || value.profiles.length > 16
    || value.profiles.some(profile => !profile || typeof profile.name !== 'string' || !validProfileName(profile.name) || typeof profile.effective_enabled !== 'boolean'
      || typeof profile.password_enabled !== 'boolean' || !Number.isSafeInteger(profile.idle_timeout_seconds) || profile.idle_timeout_seconds < 1)) throw new Error('浏览器配置列表无效。');
  if (new Set(value.profiles.map(profile => canonicalProfileName(profile.name))).size !== value.profiles.length) throw new Error('浏览器配置列表无效。');
  return {multi_profile: value.multi_profile, profiles: value.profiles.map(({name, enabled, effective_enabled, password_enabled, password_required, idle_timeout_seconds}) => ({name: canonicalProfileName(name), enabled, effective_enabled, password_enabled, password_required, idle_timeout_seconds}))};
}
function ProfileEntryNavigation({profile, multiProfile = true, navigateDocument, navigateProfile}: {profile: PublicBrowserProfile | null; multiProfile?: boolean; navigateDocument: (path: string) => void; navigateProfile: NavigateProfile}) {
  const notify = useContext(AppNotificationContext);
  const navigate = (event: React.MouseEvent<HTMLAnchorElement>, destination: string | undefined) => {
    if (!destination || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.currentTarget.target === '_blank') return;
    event.preventDefault();
    if (profile && destination.startsWith('/profile/')) void navigateProfile(profile).catch(failure => notify?.(failure instanceof Error ? failure.message : '切换配置失败。', true));
    else navigateDocument(destination);
  };
  const pages = [
    {label: '浏览器', path: profile ? profile.effective_enabled ? profileDestination(profile, multiProfile) : undefined : '/', current: true},
    {label: '设置', path: '/settings', current: false},
    {label: '下载', path: '/downloads', current: false},
  ];
  return <NavigationBar><Stack component="nav" direction="row" spacing={.5} aria-label="主导航">
    {pages.map(page => <Button component="a" key={page.label} href={page.path} disabled={!page.path} onClick={event => navigate(event, page.path)} color="inherit"
      className={page.current ? 'current-route' : ''} aria-current={page.current ? 'page' : undefined}>{page.label}</Button>)}
  </Stack></NavigationBar>;
}
function ProfileDesktop({profile, multiProfile, authenticated, onLocked, navigateDocument, onLocationChange, browserDestination, navigateProfile}: {profile: PublicBrowserProfile; multiProfile: boolean; authenticated: boolean; onLocked: (reason?: 'unauthorized' | 'unavailable' | 'logout') => void; navigateDocument: (path: string) => void; onLocationChange: (url: string) => void; browserDestination?: string; navigateProfile: NavigateProfile}) {
  const lease = useProfileViewer(onLocked, authenticated && profile.effective_enabled);
  const entered = useRef(false);
  if (lease.viewer) entered.current = true;
  return <>
    {entered.current ? <App profile={{...profile, viewer: authenticated ? lease.viewer : null, onDisconnected: lease.disconnected, onLocked}}
      multiProfile={multiProfile} navigateDocument={navigateDocument} onLocationChange={onLocationChange} browserDestination={browserDestination} navigateProfile={navigateProfile} />
      : <><ProfileEntryNavigation profile={profile} multiProfile={multiProfile} navigateDocument={navigateDocument} navigateProfile={navigateProfile} /><Stack role="status" className="page-loading" direction="row" spacing={2} sx={{alignItems: 'center', justifyContent: 'center'}}>
        {lease.busy ? <><CircularProgress size={22} /><Typography variant="body2">正在连接浏览器…</Typography></>
          : <Alert severity="error" action={<Button onClick={lease.acquire}>重试</Button>}>{lease.error || '浏览器控制连接失败。'}</Alert>}
      </Stack></>}
    {authenticated && lease.viewer && !lease.viewer.owner && <Paper variant="outlined" sx={{position: 'fixed', right: 16, bottom: 16, px: 1.5, py: 1, zIndex: theme => theme.zIndex.snackbar}}>
      <Stack direction="row" spacing={1} sx={{alignItems: 'center'}}><Typography variant="body2">只读</Typography>
        {profile.effective_enabled && lease.viewer.expired && lease.canAcquire && <Button size="small" onClick={lease.acquire} disabled={lease.busy}>接管控制</Button>}
      </Stack>
    </Paper>}
  </>;
}

const defaultNavigateDocument = (path: string) => window.location.assign(path);
const defaultReplaceDocument = (path: string) => window.location.replace(path);
export default function ProfileApp({navigateDocument = defaultNavigateDocument, replaceDocument = defaultReplaceDocument}: {navigateDocument?: (path: string) => void; replaceDocument?: (path: string) => void} = {}) {
  const {notify, snackbar} = useAppNotification();
  const notifyError = useCallback((message: string) => notify(message, true), [notify]);
  const [configuration, setConfiguration] = useState<PublicProfileConfiguration | null>(null);
  const [selected, setSelected] = useState<PublicBrowserProfile | null>(null);
  const selectedRef = useRef(selected); selectedRef.current = selected;
  const [authenticated, setAuthenticated] = useState(false);
  const [profileStatuses, setProfileStatuses] = useState<Record<string, ProfileStatus>>(() => Object.fromEntries(savedProfiles().filter(profile => profile.status === 'auth_invalid').map(profile => [profile.name, 'auth_invalid'])));
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [version, setVersion] = useState(0);
  const name = useRef<HTMLInputElement | null>(null);
  const password = useRef<HTMLInputElement | null>(null);
  const passwordRef = useCallback((element: HTMLInputElement | null) => {
    if (!element && password.current) password.current.value = '';
    password.current = element;
  }, []);
  const lifecycle = useRef(0);
  const authGeneration = useRef(0);
  const navigationSequence = useRef(0);
  const submitting = useRef(false);
  const mounted = useRef(true);
  const route = useRef(window.location.pathname.replace(/\/$/, '') || '/').current;
  const [currentPath, setCurrentPath] = useState(route);
  const currentPathRef = useRef(currentPath); currentPathRef.current = currentPath;
  const onLocationChange = useCallback((url: string) => setCurrentPath(new URL(url).pathname.replace(/\/$/, '') || '/'), []);
  const [explicitChooser] = useState(() => route === '/login' || readProfileChooser());
  const fixedName = (route === '/profile' || route.startsWith('/profile/')) ? (() => {try {return decodeURIComponent(route.slice('/profile/'.length));} catch {return '';}})() : null;
  const settingsOnly = route === '/settings';
  const downloadsOnly = route === '/downloads';
  useState(() => {clearProfileNavigation(); return null;});
  const clearPassword = () => { if (password.current) password.current.value = ''; };
  const markFailed = useCallback((name: string, status: 'auth_invalid' | 'unavailable' = 'auth_invalid', persist = true) => {
    if (savedProfiles().some(profile => profile.name === name)) {
      if (persist && status === 'auth_invalid') setSavedProfileStatus(name, status);
      setProfileStatuses(previous => previous[name] === status ? previous : {...previous, [name]: status});
    }
  }, []);
  const clearFailure = useCallback((name: string) => {
    setSavedProfileStatus(name, 'unknown');
    setProfileStatuses(previous => {const next = {...previous}; delete next[name]; return next;});
  }, []);
  const markUnavailable = useCallback((name: string) => {
    markFailed(name, 'unavailable');
    setConfiguration(previous => previous ? {...previous, profiles: previous.profiles.filter(profile => profile.name !== name)} : previous);
    setSelected(previous => previous?.name === name ? {...previous, effective_enabled: false} : previous);
    if (selectedRef.current?.name === name) {authGeneration.current++; setAuthenticated(false);}
  }, [markFailed]);
  const onLocked = useCallback((reason: 'unauthorized' | 'unavailable' | 'logout' = 'unauthorized') => {
    const generation = ++authGeneration.current;
    const epoch = lifecycle.current;
    const profile = selectedRef.current;
    if (profile) {
      if (reason === 'logout') clearFailure(profile.name);
      else if (reason === 'unavailable') markUnavailable(profile.name);
      else {
        markFailed(profile.name, 'auth_invalid', false);
        // A disabled name can reject viewer access just like an expired cookie.
        // Refresh availability without letting a late response replace a new login.
        void request<PublicProfileConfiguration>('/api/profiles/public').then(validateConfiguration).then(value => {
          if (!mounted.current || lifecycle.current !== epoch || authGeneration.current !== generation) return;
          setConfiguration(value);
          const latest = value.profiles.find(candidate => candidate.name === profile.name);
          // Availability changes preserve the prior remembered-auth hint.
          if (!latest?.effective_enabled) markUnavailable(profile.name);
          else setSavedProfileStatus(profile.name, 'auth_invalid');
          if (!value.multi_profile && !['/', '/settings', '/downloads'].includes(currentPathRef.current)) replaceDocument('/');
        }).catch(() => { /* Retain the safe locked state when discovery is unavailable. */ });
      }
    }
    setAuthenticated(false); setBusy(false); setError('');
  }, [markFailed, markUnavailable, clearFailure, replaceDocument]);
  const navigateProfile = useCallback<NavigateProfile>(async profile => {
    const operation = ++navigationSequence.current;
    const epoch = lifecycle.current;
    let authorizationGeneration = authGeneration.current;
    const current = () => mounted.current && lifecycle.current === epoch && navigationSequence.current === operation && authGeneration.current === authorizationGeneration;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const value = validateConfiguration(await request<PublicProfileConfiguration>('/api/profiles/public', 'GET', undefined, {signal: controller.signal}));
      if (!current()) return;
      setConfiguration(value);
      const previous = selectedRef.current;
      if (previous) {
        const currentProfile = value.profiles.find(candidate => candidate.name === previous.name);
        setSelected(currentProfile ?? {...previous, effective_enabled: false});
        if (!currentProfile?.effective_enabled) {markFailed(previous.name, 'unavailable'); authorizationGeneration = ++authGeneration.current; setAuthenticated(false);}
      }
      const latest = value.profiles.find(candidate => candidate.name === (value.multi_profile ? canonicalProfileName(profile.name) : 'default'));
      if (!latest?.effective_enabled) {
        markFailed(profile.name, 'unavailable');
        if (selectedRef.current?.name === profile.name) {authorizationGeneration = ++authGeneration.current; setAuthenticated(false);}
        throw new Error('浏览器配置不存在或已停用。');
      }
      // Validate the target's cookie without using the current viewer's
      // capability. Invalid access opens that profile's normal password gate.
      try {
        const status = await request<AppStatus>(`/p/${encodeURIComponent(latest.name)}/api/status`, 'GET', undefined, {signal: controller.signal});
        if (!current()) return;
        if (status.vnc_authenticated) clearFailure(latest.name);
        else markFailed(latest.name);
      } catch (failure) {
        if (!current()) return;
        if (failure instanceof ApiError && failure.status === 401) markFailed(latest.name);
        else if (failure instanceof ApiError && failure.status === 404) {
          markUnavailable(latest.name); authorizationGeneration = authGeneration.current; throw new Error('浏览器配置不存在或已停用。');
        } else throw failure;
      }
      const path = prepareProfileNavigation(latest, value.multi_profile);
      navigateDocument(path);
    } catch (failure) {
      if (!current()) return;
      throw failure;
    } finally { clearTimeout(timeout); }
  }, [navigateDocument, markFailed, markUnavailable, clearFailure]);
  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    setLoading(true); setAuthenticated(false); setError('');
    let attemptedProfileName: string | null = null;
    const bootstrap = async () => {
      const value = validateConfiguration(await request<PublicProfileConfiguration>('/api/profiles/public', 'GET', undefined, {signal: controller.signal}));
      if (controller.signal.aborted) return;
      setConfiguration(value);
      if (settingsOnly || downloadsOnly) return;
      // Single-profile mode has one public Browser entry. Ignore every legacy
      // name/identity before lookup, then authorize the unchanged default data.
      if (!value.multi_profile && route !== '/') {
        window.history.replaceState(null, '', '/');
        setCurrentPath('/');
      }
      if (value.multi_profile && fixedName !== null && !validProfileName(fixedName)) throw new Error('配置名称无效。');
      const resumeDefault = route === '/' && !explicitChooser && savedProfiles().some(profile => profile.name === 'default');
      const target = !value.multi_profile ? value.profiles.find(profile => profile.name === 'default')
        : fixedName !== null ? value.profiles.find(profile => profile.name.toLowerCase() === fixedName.toLowerCase())
        : resumeDefault ? value.profiles.find(profile => profile.name === 'default') : undefined;
      if (!target) {
        const hint = savedProfiles().find(profile => profile.name.toLowerCase() === (fixedName || '').toLowerCase());
        if (hint) markFailed(hint.name, 'unavailable');
        if (fixedName !== null || !value.multi_profile) throw new Error('浏览器配置不存在或已停用。');
        return;
      }
      if (!target.effective_enabled) {setSelected(target); markFailed(target.name, 'unavailable'); throw new Error('浏览器配置已停用。');}
      if (browserProfileName() && browserProfileName() !== target.name) { replaceDocument('/'); return; }
      setSelected(target); bindBrowserProfile(target.name);
      attemptedProfileName = target.name;
      const status = await request<AppStatus>('/api/status', 'GET', undefined, {signal: controller.signal});
      if (controller.signal.aborted) return;
      setCsrfToken(status.csrf_token);
      if (status.vnc_authenticated) {rememberProfile(target); clearFailure(target.name); retainProfileSelection(target, value.multi_profile); authGeneration.current++; setAuthenticated(true); return;}
      if (target.password_enabled || target.password_required) markFailed(target.name);
      if (!target.password_enabled && !target.password_required) {
        await request('/api/login', 'POST', {scope: 'vnc', password: ''}, {signal: controller.signal});
        if (controller.signal.aborted) return;
        rememberProfile(target); clearFailure(target.name); retainProfileSelection(target, value.multi_profile); authGeneration.current++; setAuthenticated(true);
      }
    };
    void bootstrap().catch(failure => {if (!controller.signal.aborted) {
      if (attemptedProfileName && failure instanceof ApiError) {
        if (failure.status === 404) markUnavailable(attemptedProfileName);
        else if ([401, 403].includes(failure.status)) markFailed(attemptedProfileName);
      }
      setError(failure instanceof Error ? failure.message : '读取浏览器配置失败。');
    }})
      .finally(() => {if (!controller.signal.aborted) setLoading(false);});
    const hide = () => { mounted.current = false; lifecycle.current++; authGeneration.current++; controller.abort(); clearPassword(); submitting.current = false; setBusy(false); };
    const show = (event: PageTransitionEvent) => {
      if (!event.persisted) return;
      mounted.current = true;
      // Settings owns its global admin refresh. Revalidate only the browser
      // hint here, without replacing an already mounted Settings document.
      if (['/settings', '/downloads'].includes(currentPathRef.current)) window.dispatchEvent(new Event('browser-profiles-changed'));
      else setVersion(value => value + 1);
    };
    window.addEventListener('pagehide', hide); window.addEventListener('pageshow', show);
    return () => {mounted.current = false; lifecycle.current++; authGeneration.current++; controller.abort(); clearPassword(); window.removeEventListener('pagehide', hide); window.removeEventListener('pageshow', show);};
  }, [fixedName, settingsOnly, version, explicitChooser, route, markFailed, markUnavailable, clearFailure, downloadsOnly, replaceDocument]);
  useEffect(() => {
    let current = true;
    let sequence = 0;
    let inFlight = false;
    const changed = () => {
      if (!mounted.current) return;
      inFlight = true;
      const operation = ++sequence;
      const generation = authGeneration.current;
      void request<PublicProfileConfiguration>('/api/profiles/public').then(validateConfiguration).then(value => {
        if (!current || !mounted.current || operation !== sequence || generation !== authGeneration.current) return;
        setConfiguration(value);
        const profile = selectedRef.current;
        if (!value.multi_profile && !['/settings', '/downloads'].includes(currentPathRef.current) && profile && profile.name !== 'default') {
          authGeneration.current++; setAuthenticated(false); replaceDocument('/'); return;
        }
        if (profile) {
          const latest = value.profiles.find(candidate => candidate.name === profile.name);
          setSelected(latest ?? {...profile, effective_enabled: false});
          if (!latest?.effective_enabled) { markFailed(profile.name, 'unavailable'); authGeneration.current++; setAuthenticated(false); setError('浏览器配置不存在或已停用。'); }
          else {
            // Configuration edits revoke the selected browser identity without
            // replacing an independently mounted global page.
            void request<AppStatus>(`/p/${encodeURIComponent(latest.name)}/api/status`).then(status => {
              if (!current || !mounted.current || operation !== sequence || generation !== authGeneration.current) return;
              if (!status.vnc_authenticated) {
                if (latest.password_enabled || latest.password_required) markFailed(latest.name);
                authGeneration.current++; setAuthenticated(false);
              }
            }).catch(failure => {
              if (current && operation === sequence && generation === authGeneration.current && failure instanceof ApiError) {
                if (failure.status === 404) markUnavailable(latest.name);
                else if ([401, 403].includes(failure.status)) onLocked();
              }
            });
          }
        }
      }).catch(() => { /* Authenticated status still decides access after a failed refresh. */ }).finally(() => {if (operation === sequence) inFlight = false;});
    };
    window.addEventListener('browser-profiles-changed', changed);
    // Default can retain a valid viewer when another document turns multi mode
    // off. Recheck just that named Browser alias; this is never user activity.
    const watchDefaultAlias = authenticated && selected?.name === 'default' && currentPath.startsWith('/profile/');
    const refreshAlias = () => {if (mounted.current && !inFlight) changed();};
    const timer = watchDefaultAlias ? setInterval(refreshAlias, 10000) : undefined;
    if (watchDefaultAlias) window.addEventListener('focus', refreshAlias);
    return () => { current = false; clearInterval(timer); window.removeEventListener('focus', refreshAlias); window.removeEventListener('browser-profiles-changed', changed); };
  }, [selected?.name, authenticated, currentPath, markFailed, markUnavailable, onLocked, replaceDocument]);
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (submitting.current || !configuration) return;
    const entered = selected?.name || name.current?.value || '';
    if (!validProfileName(entered)) {setError('配置名称无效。'); return;}
    const target = configuration.profiles.find(profile => (selected ? profile.name === selected.name : profile.name.toLowerCase() === entered.toLowerCase()) && profile.effective_enabled);
    if (!target) {clearPassword(); setError('浏览器配置不存在或已停用。'); return;}
    const secret = password.current?.value || '';
    if (selected && (target.password_required || target.password_enabled) && !secret) {setError('请输入密码。'); password.current?.focus(); return;}
    const epoch = lifecycle.current;
    const current = () => mounted.current && lifecycle.current === epoch;
    submitting.current = true; setBusy(true); setError('');
    clearPassword();
    try {
      // A named selection uses a fresh document and a name-scoped credential;
      // only this login request uses the explicitly selected scoped endpoint.
      const prefix = `/p/${encodeURIComponent(target.name)}`;
      const status = await request<AppStatus>(`${prefix}/api/status`);
      if (!current()) return;
      setCsrfToken(status.csrf_token);
      if (status.vnc_authenticated) {
        rememberProfile(target); clearFailure(target.name);
        if (!selected) await navigateProfile(target); else {retainProfileSelection(target, configuration.multi_profile); authGeneration.current++; setAuthenticated(true);}
        return;
      }
      if (target.password_required || target.password_enabled) markFailed(target.name);
      if ((target.password_required || target.password_enabled) && !secret) { setError('请输入密码。'); password.current?.focus(); return; }
      const login = request(`${prefix}/api/login`, 'POST', {scope: 'vnc', password: secret});
      clearPassword(); await login;
      if (!current()) return;
      rememberProfile(target); clearFailure(target.name);
      if (!selected) { await navigateProfile(target); return; }
      retainProfileSelection(target, configuration.multi_profile);
      authGeneration.current++; setAuthenticated(true);
    } catch (failure) {
      if (current()) {
        if (failure instanceof ApiError) {
          if (failure.status === 404) markUnavailable(target.name);
          else if ([401, 403].includes(failure.status)) markFailed(target.name);
        }
        setError(failure instanceof Error ? failure.message : '登录失败。');
      }
    } finally {if (current()) {clearPassword(); submitting.current = false; setBusy(false);}}
  };
  const navigationStatuses: Record<string, ProfileStatus> = {...profileStatuses};
  for (const profile of configuration?.profiles ?? []) {
    if (profile.effective_enabled && navigationStatuses[profile.name] === 'unavailable') {
      navigationStatuses[profile.name] = savedProfiles().find(saved => saved.name === profile.name)?.status ?? 'unknown';
    }
  }
  return <AppNotificationContext value={notify}><ProfileNavigationContext value={configuration?.multi_profile ? {profiles: configuration.profiles, activeProfileName: authenticated ? selected?.name ?? null : null, profileStatuses: navigationStatuses, navigateDocument, navigateProfile, notifyError} : null}><Box className="profile-shell">
    {settingsOnly || downloadsOnly ? <App profile={null} multiProfile={configuration?.multi_profile ?? true} navigateDocument={navigateDocument} /> : loading ? <><ProfileEntryNavigation profile={selected} multiProfile={configuration?.multi_profile ?? true} navigateDocument={navigateDocument} navigateProfile={navigateProfile} /><Stack role="status" className="page-loading" direction="row" spacing={2} sx={{alignItems: 'center', justifyContent: 'center'}}><CircularProgress size={22} /><Typography variant="body2">正在读取配置…</Typography></Stack></>
      : selected && (authenticated || ['/settings', '/downloads'].includes(currentPath) || ['/settings', '/downloads'].includes(window.location.pathname.replace(/\/$/, ''))) ? <ProfileDesktop key={selected.name} profile={selected} multiProfile={configuration?.multi_profile ?? true} authenticated={authenticated} onLocked={onLocked} navigateDocument={navigateDocument} onLocationChange={onLocationChange} navigateProfile={navigateProfile}
            browserDestination={configuration && !configuration.multi_profile && selected.name !== 'default' ? '/' : undefined} />
      : <><ProfileEntryNavigation profile={selected} multiProfile={configuration?.multi_profile ?? true} navigateDocument={navigateDocument} navigateProfile={navigateProfile} /><Box className="login-page"><Paper variant="outlined" className="login-card"><Box component="form" onSubmit={submit}><Stack spacing={2.5}>
        <Typography variant="overline" color="text.secondary">WebAuthn Browser</Typography><Typography variant="h1">解锁浏览器</Typography>
        {configuration?.multi_profile && <TextField label="配置名称" inputRef={name} defaultValue={selected?.name || fixedName || ''} disabled={Boolean(selected) || fixedName !== null || busy} autoFocus={fixedName === null} autoComplete="username" />}
        <TextField label="密码" inputRef={passwordRef} type="password" autoComplete="current-password" disabled={busy} autoFocus={fixedName !== null || !configuration?.multi_profile}
          required={Boolean(selected?.password_enabled || selected?.password_required)} />
        {error && <Alert severity="error">{error}</Alert>}
        {configuration ? <Button type="submit" variant="contained" disabled={busy || (configuration.multi_profile && fixedName !== null && !selected?.effective_enabled)}>{busy ? '正在解锁…' : '解锁'}</Button>
          : <Button onClick={() => setVersion(value => value + 1)}>重试</Button>}
      </Stack></Box></Paper></Box></>}
  </Box>{snackbar}</ProfileNavigationContext></AppNotificationContext>;
}
