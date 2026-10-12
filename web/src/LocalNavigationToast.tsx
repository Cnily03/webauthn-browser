import { forwardRef, useCallback, useEffect, useRef, useState } from 'react';
import { Button, Grow, Snackbar, type GrowProps } from '@mui/material';
import { localNavigationIdentity, validateLocalNavigationEvent, type LocalNavigationEvent } from './localNavigation';

interface Notice { id: string; url: string; remaining: number; deadline: number; entered: boolean; hovered: boolean; focused: boolean }
// One counter per public backend instance, shared across route/auth remounts.
// Memory does not grow with navigation traffic and counters are never evicted
// to admit an old event. No URL, token or preference is saved.
const highWaterMarks = new Map<string, bigint>();
const DISPLAY_MS = 5000;
// Snackbar chains onEnter/onExited but filters other event-named slot props.
// Pass a non-event completion prop through its stable, built-in Grow wrapper.
type NoticeTransitionProps = {appear: boolean; entered: () => void};
const NoticeTransition = forwardRef<unknown, GrowProps & {entered: () => void}>(function NoticeTransition({entered, ...props}, ref) {
  return <Grow {...props} ref={ref} onEntered={entered} />;
});

export function useLocalNavigationToast() {
  const [notice, setNotice] = useState<Notice | null>(null);
  const active = useRef<Notice | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mounted = useRef(true);
  const clear = useCallback(() => {
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
    active.current = null;
    if (mounted.current) setNotice(null);
  }, []);
  const arm = useCallback((shown: Notice) => {
    if (active.current !== shown || !mounted.current || !shown.entered) return;
    shown.deadline = performance.now() + shown.remaining;
    timer.current = setTimeout(() => { if (active.current === shown) clear(); }, shown.remaining);
  }, [clear]);
  const receive = useCallback((value: LocalNavigationEvent | null) => {
    if (!mounted.current) return;
    if (value === null) { clear(); return; }
    const event = validateLocalNavigationEvent(value);
    if (!event) return;
    const identity = localNavigationIdentity(event.id)!;
    if (identity.sequence <= (highWaterMarks.get(identity.instance) ?? 0n)) return;
    highWaterMarks.set(identity.instance, identity.sequence);
    clear();
    // remaining_ms validates delivery freshness, not the interaction lifetime.
    // Every newly entered prompt gets five fully visible, unpaused seconds.
    const next = {id: event.id, url: event.url, remaining: DISPLAY_MS, deadline: 0, entered: false, hovered: false, focused: false};
    active.current = next;
    setNotice(next);
  }, [clear]);
  useEffect(() => {
    mounted.current = true;
    window.addEventListener('pagehide', clear);
    return () => { mounted.current = false; window.removeEventListener('pagehide', clear); clear(); };
  }, [clear]);

  const pause = (shown: Notice, reason: 'hovered' | 'focused', value: boolean) => {
    if (active.current !== shown) return;
    // Hover and focus overlap: resume only when both end. Before entrance
    // completes, record the pause without consuming any fully visible time.
    const wasPaused = shown.hovered || shown.focused;
    shown[reason] = value;
    const paused = shown.hovered || shown.focused;
    if (!shown.entered) return;
    if (paused === wasPaused) return;
    if (paused) {
      shown.remaining = Math.max(0, shown.deadline - performance.now());
      if (timer.current !== null) clearTimeout(timer.current);
      timer.current = null;
    } else arm(shown);
  };
  const dismiss = (shown: Notice) => { if (active.current === shown) clear(); };
  const open = (shown: Notice) => {
    if (active.current !== shown || !mounted.current) return;
    const url = shown.url;
    clear();
    // Keep this call synchronous inside the actual button activation. Receiving
    // an event never opens, prefetches, probes, or requests the target URL.
    window.open(url, '_blank', 'noopener,noreferrer');
  };
  return {receive, toast: notice && <Snackbar key={notice.id} open anchorOrigin={{vertical: 'bottom', horizontal: 'right'}}
    slots={{transition: NoticeTransition}} slotProps={{transition: {appear: true, entered: () => {
      if (active.current !== notice || notice.entered) return;
      notice.entered = true;
      if (!notice.hovered && !notice.focused) arm(notice);
    }} as NoticeTransitionProps}}
    onMouseEnter={() => pause(notice, 'hovered', true)} onMouseLeave={() => pause(notice, 'hovered', false)}
    onFocusCapture={() => pause(notice, 'focused', true)} onBlurCapture={event => {
      if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) pause(notice, 'focused', false);
    }}
    sx={{'& .MuiSnackbarContent-root': {flexWrap: 'nowrap', minWidth: 0, maxWidth: 'min(640px, calc(100vw - 32px))'},
      '& .MuiSnackbarContent-message': {minWidth: 0, flex: '1 1 auto', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis'},
      '& .MuiSnackbarContent-action': {flexShrink: 0, flexWrap: 'nowrap', gap: .5, marginLeft: 1, marginRight: 0, paddingLeft: 0}}}
    message={`在本机浏览器打开 ${notice.url}`} onClose={(_, reason) => { if (reason !== 'clickaway') dismiss(notice); }}
    action={<><Button color="inherit" size="small" sx={{minWidth: 0, flexShrink: 0}} onClick={() => open(notice)}>打开</Button>
      <Button color="inherit" size="small" sx={{minWidth: 0, flexShrink: 0}} onClick={() => dismiss(notice)}>取消</Button></>} />};
}
