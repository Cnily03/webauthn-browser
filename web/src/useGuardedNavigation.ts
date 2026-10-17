import { useCallback, useEffect, useRef, useState } from 'react';
import { clearProfileNavigation } from './profiles';

export type NavigationGuard = (action: () => void) => boolean;
const stateKey = '__webauthnBrowserNavigation';
interface Entry { url: string; index: number }
interface Traversal { from: Entry; to: Entry; phase: 'restoring' | 'waiting' | 'replaying'; approved: boolean }
function index() {
  const value = window.history.state?.[stateKey];
  return Number.isSafeInteger(value) ? value as number : null;
}
function stateWithIndex(value: number) {
  return { ...(window.history.state && typeof window.history.state === 'object' ? window.history.state : {}), [stateKey]: value };
}

// Keep the accepted page mounted while a traversal is awaiting confirmation.
// Restore and replay real entries instead of overwriting them with replaceState.
export function useGuardedNavigation(guard: NavigationGuard, enabled = true) {
  const [url, setUrl] = useState(() => {clearProfileNavigation(); return window.location.href;});
  const accepted = useRef<Entry>({url: window.location.href, index: index() ?? 0});
  const observed = useRef<Entry>(accepted.current);
  const pending = useRef<Traversal | null>(null);
  const latestGuard = useRef(guard);
  latestGuard.current = guard;
  const publish = useCallback((entry: Entry) => { accepted.current = entry; setUrl(entry.url); }, []);
  useEffect(() => {
    if (!enabled) return;
    const initial = {url: window.location.href, index: index() ?? 0};
    window.history.replaceState(stateWithIndex(initial.index), '', initial.url);
    accepted.current = initial; observed.current = initial; pending.current = null;
    const changed = (event: PopStateEvent | HashChangeEvent) => {
      // A queued hashchange can arrive after a newer traversal has completed.
      if (event instanceof HashChangeEvent && event.newURL && event.newURL !== window.location.href) return;
      clearProfileNavigation();
      let nextIndex = index();
      if (nextIndex === null) {
        // Native fragment navigation creates an entry without our state. Stamp
        // that new entry without changing its URL or the previous entry.
        nextIndex = accepted.current.index + 1;
        window.history.replaceState(stateWithIndex(nextIndex), '', window.location.href);
      }
      const next = {url: window.location.href, index: nextIndex};
      if (next.url === observed.current.url && next.index === observed.current.index) return;
      observed.current = next;
      const traversal = pending.current;
      if (traversal?.phase === 'restoring') {
        if (next.index !== traversal.from.index) { window.history.go(traversal.from.index - next.index); return; }
        traversal.phase = 'waiting';
        if (traversal.approved) { traversal.phase = 'replaying'; window.history.go(traversal.to.index - next.index); }
        return;
      }
      if (traversal?.phase === 'replaying' && next.index === traversal.to.index && next.url === traversal.to.url) {
        pending.current = null; publish(next); return;
      }
      if (next.url === accepted.current.url && next.index === accepted.current.index) return;
      const attempt: Traversal = {from: accepted.current, to: next, phase: 'restoring', approved: false};
      pending.current = attempt;
      let synchronous = true;
      const apply = () => {
        if (pending.current !== attempt) return;
        if (synchronous) { pending.current = null; publish(next); return; }
        // Approval can precede the compensating traversal. Replay only after
        // the browser has restored the accepted entry, preserving real history.
        attempt.approved = true;
        if (attempt.phase === 'waiting') { attempt.phase = 'replaying'; window.history.go(attempt.to.index - attempt.from.index); }
      };
      const allowed = latestGuard.current(apply);
      synchronous = false;
      if (!allowed && pending.current === attempt) window.history.go(attempt.from.index - next.index);
    };
    window.addEventListener('popstate', changed); window.addEventListener('hashchange', changed);
    return () => {
      pending.current = null;
      window.removeEventListener('popstate', changed); window.removeEventListener('hashchange', changed);
    };
  }, [enabled, publish]);
  const navigate = useCallback((destination: string, after?: () => void) => {
    if (!enabled || (pending.current && pending.current.phase !== 'waiting')) return;
    const nextUrl = new URL(destination, accepted.current.url).href;
    if (nextUrl === accepted.current.url) return;
    pending.current = null;
    latestGuard.current(() => {
      const next = {url: nextUrl, index: accepted.current.index + 1};
      window.history.pushState({[stateKey]: next.index}, '', next.url);
      observed.current = next; publish(next); after?.();
    });
  }, [enabled, publish]);
  // Canonical aliases replace the accepted entry rather than growing history.
  const replace = useCallback((destination: string) => {
    if (!enabled || pending.current) return;
    const next = {url: new URL(destination, accepted.current.url).href, index: accepted.current.index};
    if (next.url === accepted.current.url) return;
    window.history.replaceState(stateWithIndex(next.index), '', next.url);
    observed.current = next; publish(next);
  }, [enabled, publish]);
  return {url, navigate, replace};
}
