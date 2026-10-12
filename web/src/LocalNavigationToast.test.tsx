import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useLocalNavigationToast } from './LocalNavigationToast';
import { validateLocalNavigationEvent, type LocalNavigationEvent } from './localNavigation';
import { renderMaterial } from './test-render';
import theme from './theme';
const ENTER_MS = theme.transitions.duration.enteringScreen;

let serial = 0;
const event = (values: Partial<LocalNavigationEvent> = {}): LocalNavigationEvent => ({id: `component:${++serial}`, url: 'http://localhost:1234/callback?code=test-only%2Bvalue#fragment', remaining_ms: 5000, mode_generation: 7, ...values});
let receive!: ReturnType<typeof useLocalNavigationToast>['receive'];
function Harness() { const toast = useLocalNavigationToast(); receive = toast.receive; return toast.toast; }
beforeEach(() => { vi.useFakeTimers(); vi.spyOn(window, 'open').mockImplementation(() => null); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

describe('ephemeral local navigation toast', () => {
  it('opens the exact URL only once from its lower-right action, with no target link or automatic request', () => {
    const fetcher = vi.spyOn(globalThis, 'fetch');
    const shown = event(); const {container} = renderMaterial(<Harness />);
    act(() => receive(shown));
    expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    expect(container.querySelector('.MuiSnackbar-anchorOriginBottomRight')).not.toBeNull();
    expect(screen.getByText(/^在本机浏览器打开 http/)).toHaveTextContent(`在本机浏览器打开 ${shown.url}`);
    expect(document.querySelector('a, link[rel="prefetch"], iframe')).toBeNull();
    expect(window.open).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled();
    const button = screen.getByRole('button', {name: '打开'});
    fireEvent.click(button); fireEvent.click(button);
    expect(window.open).toHaveBeenCalledExactlyOnceWith(shown.url, '_blank', 'noopener,noreferrer');
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    act(() => receive(shown)); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
  });
  it.each([1000, 4000, 5000])('shows each fresh delivery for five full seconds after entering, even with remaining_ms=%d', remaining => {
    renderMaterial(<Harness />); act(() => receive(event({remaining_ms: remaining})));
    const button = screen.getByRole('button', {name: '打开'});
    act(() => vi.advanceTimersByTime(ENTER_MS)); act(() => vi.advanceTimersByTime(4999));
    expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); fireEvent.click(button);
    expect(window.open).not.toHaveBeenCalled();
  });
  it('does not extend duplicate expiry and never replays a decided ID on remount', () => {
    const shown = event(); const first = renderMaterial(<Harness />); act(() => receive(shown));
    act(() => vi.advanceTimersByTime(ENTER_MS)); act(() => vi.advanceTimersByTime(4000)); act(() => receive({...shown, remaining_ms: 5000}));
    act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    first.unmount(); renderMaterial(<Harness />); act(() => receive(shown));
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
  it('a newer event replaces the previous action and old callbacks cannot open either URL', () => {
    renderMaterial(<Harness />); act(() => receive(event())); const old = screen.getByRole('button', {name: '打开'});
    fireEvent.mouseEnter(old.closest('.MuiSnackbar-root')!); act(() => vi.advanceTimersByTime(10000));
    const next = event({url: 'https://127.0.0.1/a?keep=%23#keep'}); act(() => receive(next)); fireEvent.click(old);
    expect(window.open).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', {name: '打开'}));
    expect(window.open).toHaveBeenCalledExactlyOnceWith(next.url, '_blank', 'noopener,noreferrer');
  });
  it.each(['clear', 'pagehide', 'unmount'] as const)('invalidates the pending action on %s and releases its timer', boundary => {
    const view = renderMaterial(<Harness />); const shown = event(); act(() => receive(shown));
    const button = screen.getByRole('button', {name: '打开'});
    fireEvent.mouseEnter(button.closest('.MuiSnackbar-root')!); act(() => vi.advanceTimersByTime(10000));
    expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    if (boundary === 'clear') act(() => receive(null));
    if (boundary === 'pagehide') act(() => window.dispatchEvent(new Event('pagehide')));
    if (boundary === 'unmount') view.unmount();
    fireEvent.click(button); act(() => vi.advanceTimersByTime(10000));
    expect(window.open).not.toHaveBeenCalled(); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
  });
  it('keeps accepting after 4096 events and rejects older counters without accumulating an ID ledger', () => {
    renderMaterial(<Harness />);
    act(() => {for (let sequence = 1; sequence <= 4100; sequence++) receive(event({id: `long-running:${sequence}`}));});
    const target = 'https://localhost/latest?query=preserved#fragment';
    act(() => receive(event({id: 'long-running:4101', url: target})));
    act(() => receive(event({id: 'long-running:2000', url: 'http://localhost/stale'})));
    fireEvent.click(screen.getByRole('button', {name: '打开'})); expect(window.open).toHaveBeenCalledExactlyOnceWith(target, '_blank', 'noopener,noreferrer');
  });
  it('compares u64 counters exactly beyond JavaScript Number precision across remounts', () => {
    const first = renderMaterial(<Harness />); act(() => receive(event({id: 'wide-counter:9007199254740993'}))); first.unmount();
    renderMaterial(<Harness />); act(() => receive(event({id: 'wide-counter:9007199254740992'})));
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
    act(() => receive(event({id: 'wide-counter:9007199254740994'}))); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
  });
  it('keeps a hover during entrance paused and starts all five seconds only after leaving', () => {
    renderMaterial(<Harness />); act(() => receive(event({remaining_ms: 1000})));
    const toast = screen.getByText(/^在本机浏览器打开 http/).closest('.MuiSnackbar-root')!;
    fireEvent.mouseEnter(toast); act(() => vi.advanceTimersByTime(10000));
    expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible(); fireEvent.mouseLeave(toast);
    act(() => vi.advanceTimersByTime(4999)); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    act(() => vi.advanceTimersByTime(1)); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull();
  });
  it('keeps a hovered prompt actionable beyond five seconds and opens its original query and fragment', () => {
    renderMaterial(<Harness />); const shown = event(); act(() => receive(shown));
    const toast = screen.getByText(/^在本机浏览器打开 http/).closest('.MuiSnackbar-root')!;
    act(() => vi.advanceTimersByTime(2000)); fireEvent.mouseEnter(toast);
    act(() => vi.advanceTimersByTime(30000)); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', {name: '打开'})); expect(window.open).toHaveBeenCalledExactlyOnceWith(shown.url, '_blank', 'noopener,noreferrer');
  });
  it('pauses for both hover and focus, then resumes only the unused display duration after both leave', () => {
    renderMaterial(<Harness />); act(() => receive(event()));
    const toast = screen.getByText(/^在本机浏览器打开 http/).closest('.MuiSnackbar-root')!;
    const open = screen.getByRole('button', {name: '打开'}), cancel = screen.getByRole('button', {name: '取消'});
    act(() => vi.advanceTimersByTime(ENTER_MS)); act(() => vi.advanceTimersByTime(1800)); fireEvent.mouseEnter(toast); fireEvent.focus(open);
    act(() => vi.advanceTimersByTime(10000)); fireEvent.mouseLeave(toast);
    act(() => vi.advanceTimersByTime(10000)); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    fireEvent.blur(open, {relatedTarget: cancel}); fireEvent.focus(cancel);
    act(() => vi.advanceTimersByTime(10000)); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    fireEvent.blur(cancel, {relatedTarget: document.body});
    act(() => vi.advanceTimersByTime(3199)); expect(screen.getByText(/^在本机浏览器打开 http/)).toBeVisible();
    act(() => vi.advanceTimersByTime(1)); expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
  it('cancels a paused toast immediately and cannot replay its action', () => {
    renderMaterial(<Harness />); const shown = event(); act(() => receive(shown));
    const open = screen.getByRole('button', {name: '打开'});
    fireEvent.mouseEnter(open.closest('.MuiSnackbar-root')!); act(() => vi.advanceTimersByTime(10000));
    fireEvent.click(screen.getByRole('button', {name: '取消'})); fireEvent.click(open); act(() => receive(shown));
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
  it('uses one ellipsized text line and fixed nonwrapping action space without making a URL link', () => {
    renderMaterial(<Harness />); const shown = event({url: 'http://localhost:1234/' + 'long-path/'.repeat(30)}); act(() => receive(shown));
    const message = screen.getByText(`在本机浏览器打开 ${shown.url}`);
    expect(message).toHaveStyle({minWidth: '0', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden'});
    const root = message.closest('.MuiSnackbarContent-root')!; expect(getComputedStyle(root).flexWrap).toBe('nowrap'); expect(['0', '0px']).toContain(getComputedStyle(root).minWidth);
    expect(getComputedStyle(root).maxWidth).toBe('640px');
    const rules = Array.from(document.styleSheets).flatMap(sheet => Array.from(sheet.cssRules));
    expect(rules.some(rule => rule instanceof CSSStyleRule && root.matches(rule.selectorText) && rule.style.maxWidth.includes('100vw'))).toBe(true);
    const actions = root.querySelector('.MuiSnackbarContent-action')!; expect(actions).toHaveStyle({flexShrink: '0', flexWrap: 'nowrap'});
    expect(screen.getByRole('button', {name: '打开'})).toHaveStyle({minWidth: '0', flexShrink: '0'});
    expect(screen.getByRole('button', {name: '取消'})).toHaveStyle({minWidth: '0', flexShrink: '0'});
    expect(root.querySelector('a')).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
});

describe('local navigation event boundary', () => {
  it.each(['http://localhost', 'https://localhost:443/a?b=c#d', 'http://127.0.0.1:1/a', 'https://LOCALHOST:9999/%E4%B8%AD?x=%2F#%23'])('preserves a valid literal loopback target: %s', url => {
    const value = event({url}); expect(validateLocalNavigationEvent(value)).toBe(value);
  });
  it.each(['https://example.com/', 'http://localhost.example/', 'http://localhost./', 'http://127.1/', 'http://2130706433/', 'http://[::1]/', 'http://%6cocalhost/', 'http://user:pass@localhost/', 'http://localhost@evil.test/', 'javascript:alert(1)', 'file:///localhost', '//localhost/test', 'ws://localhost:1234/', 'http://localhost:65536/', 'http://localhost\\@evil.test/', ' http://localhost/', 'http://localhost/\nnext', 'http://localhost:1234/a b'])('rejects unsafe, ambiguous or nonliteral target without surfacing its URL: %s', url => {
    expect(validateLocalNavigationEvent(event({url}))).toBeNull();
  });
  it('rejects missing, stale, malformed and oversized data, including UTF-8 byte size', () => {
    for (const input of [null, {}, event({id: 'x\nheader'}), event({id: 'x'.repeat(129)}), event({id: 'overflow:18446744073709551616'}), event({id: 'leading-zero:01'}), event({id: 'zero:0'}), event({remaining_ms: 0}), event({remaining_ms: NaN}), event({remaining_ms: Infinity}), event({mode_generation: -1}), event({mode_generation: 0.5}), event({url: 'http://localhost/' + 'x'.repeat(8192)}), event({url: 'http://localhost/' + '中'.repeat(2731)})]) expect(validateLocalNavigationEvent(input)).toBeNull();
    renderMaterial(<Harness />); act(() => receive(event({url: 'https://evil.test'})));
    expect(screen.queryByText(/^在本机浏览器打开 http/)).toBeNull(); expect(window.open).not.toHaveBeenCalled();
  });
});
