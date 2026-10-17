import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, request, setCsrfToken } from './api';
import { browserProfileName, setProfileViewer, viewerHeaders, type ProfileViewer, type PublicProfileConfiguration } from './profiles';

type ViewerStatus = Omit<ProfileViewer, 'viewer_token'>;
function validStatus(value: ViewerStatus) {
  return value && typeof value.viewer_id === 'string' && Boolean(value.viewer_id) && value.viewer_id.length <= 256
    && typeof value.owner === 'boolean' && Number.isSafeInteger(value.generation) && value.generation >= 0
    && typeof value.expired === 'boolean' && Number.isFinite(value.idle_remaining_ms) && value.idle_remaining_ms! >= 0
    && Number.isSafeInteger(value.idle_timeout_seconds) && value.idle_timeout_seconds > 0;
}
export function genuineViewerActivity(event: Pick<Event, 'type' | 'isTrusted'>) {
  return event.isTrusted && ['pointerdown', 'pointermove', 'keydown', 'wheel'].includes(event.type);
}

export function useProfileViewer(onUnauthorized: (reason?: 'unauthorized' | 'unavailable') => void, enabled = true) {
  const [viewer, setViewer] = useState<ProfileViewer | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [canAcquire, setCanAcquire] = useState(false);
  const [wake, setWake] = useState(0);
  const unauthorized = useRef(onUnauthorized); unauthorized.current = onUnauthorized;
  const acquireRef = useRef<() => void>(() => {});
  const disconnectRef = useRef<() => void>(() => {});
  const acquire = useCallback(() => acquireRef.current(), []);
  const disconnected = useCallback(() => disconnectRef.current(), []);

  useEffect(() => {
    if (!enabled) {
      setViewer(null); setBusy(false); setCanAcquire(false); setError('');
      acquireRef.current = () => {}; disconnectRef.current = () => {};
      return;
    }
    let active = true;
    let cap: ProfileViewer | null = null;
    let acquiring = false;
    let accessCheck = 0;
    let checkingAccess = false;
    let recheckAccess = false;
    const profileName = browserProfileName() || 'default';
    let polling = false;
    let activityPending = false;
    let lastActivity = -Infinity;
    const controllers = new Set<AbortController>();
    const released = new Set<string>();
    const release = (value: ProfileViewer) => {
      if (released.has(value.viewer_token)) return;
      released.add(value.viewer_token);
      void request('/api/viewer/release', 'POST', {}, {keepalive: true, headers: viewerHeaders(value)}).catch(() => {});
    };
    const publish = (next: ProfileViewer) => { cap = next; setProfileViewer(next); setViewer(next); setCanAcquire(true); };
    const loseControl = (value: ProfileViewer) => {
      if (!active || cap !== value) return;
      publish({...value, owner: false, expired: true, idle_remaining_ms: 0});
      setCanAcquire(false);
    };
    const failed = (failure: unknown, value?: ProfileViewer) => {
      if (!active || (value && cap !== value)) return;
      if (failure instanceof ApiError && [401, 404].includes(failure.status)) {
        if (cap) {const previous = cap; cap = null; setProfileViewer(null, previous.viewer_token); release(previous);}
        setViewer(null); setCanAcquire(false);
        unauthorized.current(failure.status === 404 ? 'unavailable' : 'unauthorized'); return;
      }
      if (value && failure instanceof ApiError && [403, 409].includes(failure.status)) { loseControl(value); void verifyReacquire(); }
      setError(failure instanceof Error ? failure.message : '浏览器控制连接失败。');
    };
    const verifyReacquire = async () => {
      if (!active || checkingAccess) return;
      checkingAccess = true; recheckAccess = true;
      const check = ++accessCheck;
      const expected = cap;
      const controller = new AbortController(); controllers.add(controller);
      const current = () => active && check === accessCheck && cap === expected;
      try {
        // A transport loss can be administrative deletion. Hide takeover until
        // both current name availability and its cookie authority are confirmed.
        const catalog = await request<PublicProfileConfiguration>('/api/profiles/public', 'GET', undefined, {signal: controller.signal});
        if (!current()) return;
        if (!Array.isArray(catalog?.profiles)) throw new Error('浏览器配置列表无效。');
        if (!catalog.profiles.some(profile => profile.name === profileName && profile.effective_enabled === true)) {
          unauthorized.current('unavailable'); return;
        }
        const status = await request<{vnc_authenticated: boolean; csrf_token: string}>('/api/status', 'GET', undefined, {signal: controller.signal});
        if (!current()) return;
        if (status.vnc_authenticated !== true) { unauthorized.current('unauthorized'); return; }
        // A gateway restart rotates the cookie-bound CSRF token. The initial
        // disconnect refresh may have failed while it was offline; install the
        // revalidated token before enabling an explicit new viewer acquisition.
        if (typeof status.csrf_token !== 'string' || !status.csrf_token) throw new Error('浏览器连接授权无效。');
        setCsrfToken(status.csrf_token);
        recheckAccess = false; setCanAcquire(true);
      } catch (failure) {
        if (current() && !controller.signal.aborted) failed(failure);
      } finally { checkingAccess = false; controllers.delete(controller); }
    };
    const acquireViewer = async () => {
      if (!active || acquiring) return;
      accessCheck += 1; acquiring = true; setBusy(true); setCanAcquire(false); setError('');
      const previous = cap;
      try {
        // Keep the response observable after teardown: it contains the only
        // capability that can release an acquisition committed by the server.
        const result = await request<ProfileViewer>('/api/viewer/acquire', 'POST', {}, {headers: viewerHeaders(previous)});
        if (!validStatus(result)) throw new Error('浏览器控制授权无效。');
        if (result.viewer_token === undefined && previous?.viewer_id === result.viewer_id) result.viewer_token = previous.viewer_token;
        if (typeof result.viewer_token !== 'string' || !result.viewer_token || result.viewer_token.length > 1024 || /[\r\n]/.test(result.viewer_token)) throw new Error('浏览器控制授权无效。');
        if (!active) { release(result); return; }
        if (previous && previous.viewer_token !== result.viewer_token) release(previous);
        publish(result);
      } catch (failure) { failed(failure); }
      finally { acquiring = false; if (active) setBusy(false); }
    };
    acquireRef.current = () => { void acquireViewer(); };
    disconnectRef.current = () => { if (cap) { const previous = cap; loseControl(previous); release(previous); setProfileViewer(null, previous.viewer_token); cap = null; void verifyReacquire(); } };
    const readStatus = async () => {
      if (active && !cap && recheckAccess) { void verifyReacquire(); return; }
      if (!active || !cap || acquiring || polling) return;
      const value = cap;
      const controller = new AbortController(); controllers.add(controller); polling = true;
      try {
        const result = await request<ViewerStatus>('/api/viewer/status', 'GET', undefined, {signal: controller.signal, headers: viewerHeaders(value)});
        if (!active || cap !== value) return;
        if (!validStatus(result) || result.viewer_id !== value.viewer_id) throw new Error('浏览器控制状态无效。');
        publish({...value, ...result}); setError('');
      } catch (failure) { if (!controller.signal.aborted) failed(failure, value); }
      finally { controllers.delete(controller); polling = false; }
    };
    const activity = (event: Event) => {
      if (!active || !cap?.owner || cap.expired || !genuineViewerActivity(event) || activityPending || Date.now() - lastActivity < Math.min(1000, cap.idle_timeout_seconds * 250)) return;
      const value = cap;
      lastActivity = Date.now(); activityPending = true;
      const controller = new AbortController(); controllers.add(controller);
      void request('/api/viewer/activity', 'POST', {}, {signal: controller.signal, headers: viewerHeaders(value)})
        .catch(failure => { if (!controller.signal.aborted) failed(failure, value); })
        .finally(() => { controllers.delete(controller); activityPending = false; });
    };
    const activityEvents = ['pointerdown', 'pointermove', 'keydown', 'wheel'];
    for (const name of activityEvents) window.addEventListener(name, activity, {capture: true, passive: true});
    const timer = setInterval(() => { void readStatus(); }, 1000);
    const stop = () => {
      if (!active) return;
      active = false; accessCheck += 1; setCanAcquire(false); clearInterval(timer);
      for (const controller of controllers) controller.abort();
      for (const name of activityEvents) window.removeEventListener(name, activity, true);
      if (cap) { setProfileViewer(null, cap.viewer_token); release(cap); }
    };
    const hide = () => { stop(); setViewer(null); };
    const show = (event: PageTransitionEvent) => { if (event.persisted) setWake(value => value + 1); };
    window.addEventListener('pagehide', hide); window.addEventListener('pageshow', show);
    queueMicrotask(() => { if (active) void acquireViewer(); });
    return () => { stop(); window.removeEventListener('pagehide', hide); window.removeEventListener('pageshow', show); };
  }, [wake, enabled]);
  return {viewer, error, busy, canAcquire, acquire, disconnected};
}
