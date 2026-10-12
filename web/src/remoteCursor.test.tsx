import { act, fireEvent, screen as ui, waitFor } from '@testing-library/react';
import { Button, Dialog, DialogContent, TextField } from '@mui/material';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installRemoteCursorGuard } from './remoteCursor';
import { renderMaterial } from './test-render';
import styles from './styles.css?raw';

let host: HTMLDivElement;
let canvas: HTMLCanvasElement;
let cursor: HTMLCanvasElement;
let hit: Element[];
let guard: ReturnType<typeof installRemoteCursorGuard>;
let stylesheet: HTMLStyleElement;
const move = (target: Element = canvas, x = 100, y = 100) => fireEvent.mouseMove(target, {clientX: x, clientY: y});
const active = () => expect(cursor).toHaveAttribute('data-vnc-cursor-active');
const hidden = () => {
  expect(cursor).not.toHaveAttribute('data-vnc-cursor-active');
  expect(host).toHaveAttribute('data-vnc-local-cursor');
};
function fallback() {
  const element = document.createElement('canvas');
  // Exact DOM shape of core/util/cursor.js in noVNC 1.3 and 1.6. This
  // exercises our integration contract, not real noVNC transport or pixels.
  Object.assign(element.style, {position: 'fixed', zIndex: '65535', pointerEvents: 'none', visibility: ''});
  document.body.append(element);
  return element;
}
const rect = (x: number, y: number, width: number, height: number) => ({x, y, left: x, top: y, right: x + width, bottom: y + height, width, height, toJSON() { return {}; }});

beforeEach(() => {
  vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  host = document.createElement('div'); host.className = 'vnc-screen';
  canvas = document.createElement('canvas'); canvas.tabIndex = -1; canvas.style.cursor = 'none';
  host.append(canvas); document.body.append(host);
  hit = [canvas, host, document.body];
  Object.defineProperty(document, 'elementsFromPoint', {configurable: true, value: vi.fn(() => hit)});
  vi.spyOn(canvas, 'getBoundingClientRect').mockReturnValue(rect(20, 40, 800, 600));
  stylesheet = document.createElement('style'); stylesheet.textContent = styles; document.head.append(stylesheet);
  guard = installRemoteCursorGuard(host);
  cursor = fallback();
  vi.spyOn(cursor, 'getBoundingClientRect').mockReturnValue(rect(100, 100, 20, 20));
  guard.refresh();
});
afterEach(() => {
  guard.dispose();
  host.remove(); cursor.remove(); stylesheet.remove();
  document.querySelectorAll('[data-test-cursor-fixture]').forEach(element => element.remove());
  Reflect.deleteProperty(document, 'elementsFromPoint');
});

describe('scoped noVNC fallback cursor guard', () => {
  it('starts hidden, stays in body, and only reveals over the interactive framebuffer', () => {
    hidden();
    expect(cursor.parentElement).toBe(document.body);
    move(); active();
    expect(host).not.toHaveAttribute('data-vnc-local-cursor');
    expect(cursor.style.zIndex).toBe('65535'); // noVNC still owns its inline styles
    hit = [host, document.body]; // letterbox / outside the canvas
    move(host); hidden();
    hit = [canvas, host]; move(); active();
    expect(canvas.style.cursor).toBe('none');
  });

  it('ignores other body canvases and scopes all changes to the noVNC contract', () => {
    const other = document.createElement('canvas');
    other.dataset.testCursorFixture = ''; document.body.append(other);
    guard.refresh();
    expect(other).not.toHaveAttribute('data-vnc-cursor');
    expect(document.body).not.toHaveAttribute('data-vnc-local-cursor');
    expect(document.body.style.cursor).toBe('');
    expect(styles).not.toMatch(/cursor:\s*none/);
  });

  it('never adopts a pre-existing lookalike fallback canvas', () => {
    const existing = cursor;
    guard.dispose();
    guard = installRemoteCursorGuard(host);
    cursor = fallback(); guard.refresh();
    move(); active();
    expect(existing).not.toHaveAttribute('data-vnc-cursor');
    expect(existing).not.toHaveAttribute('data-vnc-cursor-active');
    existing.remove();
  });

  it('hides at floating controls and portal menus without preventing input events', () => {
    const button = document.createElement('button');
    button.dataset.testCursorFixture = ''; document.body.append(button);
    const received = vi.fn();
    canvas.addEventListener('mousedown', received);
    move(); active();
    fireEvent.mouseDown(canvas, {clientX: 100, clientY: 100});
    expect(received).toHaveBeenCalledOnce();
    expect(received.mock.calls[0][0].defaultPrevented).toBe(false);
    hit = [button, canvas, host]; move(button); hidden();
    hit = [canvas, host]; move(); active();
  });

  it('hides a stationary cursor when a real MUI dialog portal opens, including before focus', async () => {
    move(); active();
    const view = renderMaterial(<Dialog open={false} disableAutoFocus><DialogContent><TextField label="验证器密码" /></DialogContent></Dialog>);
    view.rerender(<Dialog open disableAutoFocus><DialogContent><TextField label="验证器密码" /></DialogContent></Dialog>);
    await ui.findByRole('dialog');
    await waitFor(hidden);
    // Even an event still targeted at the old canvas cannot override modal state.
    move(); hidden();
    view.rerender(<Dialog open={false} transitionDuration={0}><DialogContent>关闭</DialogContent></Dialog>);
    await waitFor(() => expect(ui.queryByRole('dialog')).toBeNull());
    hit = [canvas, host]; move(); active();
  });

  it('reacts to hit-test and modal attribute changes with no mousemove', async () => {
    move(); active();
    const popover = document.createElement('div');
    popover.dataset.testCursorFixture = ''; document.body.append(popover);
    hit = [popover, canvas, host];
    await waitFor(hidden);
    popover.remove(); hit = [canvas, host];
    await waitFor(active);
    const dialog = document.createElement('div');
    dialog.dataset.testCursorFixture = ''; document.body.append(dialog);
    dialog.setAttribute('aria-modal', 'true');
    await waitFor(hidden);
    dialog.hidden = true;
    await waitFor(active);
  });

  it('hides for keyboard focus but restores on pointer return while the button retains focus', () => {
    const view = renderMaterial(<Button>外层操作</Button>);
    const button = ui.getByRole('button', {name: '外层操作'});
    move(); active();
    act(() => button.focus()); hidden();
    expect(button).toHaveFocus();
    hit = [canvas, host]; move(); active();
    expect(button).toHaveFocus();
    view.unmount();
  });

  it('ignores the drag proxy during hit-testing and preserves mouseup delivery', () => {
    const proxy = document.createElement('div');
    proxy.id = 'noVNC_mouse_capture_elem'; proxy.style.zIndex = '10000'; proxy.style.cursor = 'none';
    proxy.dataset.testCursorFixture = ''; document.body.append(proxy);
    const button = document.createElement('button'); button.dataset.testCursorFixture = ''; document.body.append(button);
    const release = vi.fn(); window.addEventListener('mouseup', release);
    hit = [proxy, canvas, host]; move(proxy); active();
    expect(proxy).toHaveAttribute('data-vnc-capture');
    hit = [proxy, button, canvas, host];
    // noVNC can retarget this event to canvas; the guard must still hide.
    move(canvas); hidden();
    expect(proxy).toHaveAttribute('data-vnc-local-cursor');
    cursor.style.visibility = ''; // noVNC's captured move tries to show it again
    expect(cursor).not.toHaveAttribute('data-vnc-cursor-active');
    fireEvent.mouseUp(canvas, {clientX: 100, clientY: 100});
    expect(release).toHaveBeenCalledOnce();
    window.removeEventListener('mouseup', release);
    hit = [canvas, host]; move(); active();
  });

  it('clips only the cursor image at the canvas edges and updates on fullscreen/viewport changes', () => {
    vi.mocked(cursor.getBoundingClientRect).mockReturnValue(rect(10, 30, 30, 30));
    move(); active(); expect(cursor.style.clipPath).toBe('inset(10px 0px 0px 10px)');
    vi.mocked(cursor.getBoundingClientRect).mockReturnValue(rect(810, 630, 30, 30));
    fireEvent(document, new Event('fullscreenchange'));
    expect(cursor.style.clipPath).toBe('inset(0px 20px 20px 0px)');
    hit = [host]; fireEvent(window, new Event('resize')); hidden();
    hit = [canvas, host]; move(); active();
  });

  it('handles touch gestures and cancellation without a persistent ghost cursor', () => {
    const event = (type: string, touches: {clientX: number; clientY: number}[]) => {
      const value = new Event(type, {bubbles: true});
      Object.defineProperty(value, 'touches', {value: touches}); fireEvent(canvas, value);
    };
    event('touchstart', [{clientX: 100, clientY: 100}]); active();
    event('touchmove', [{clientX: 120, clientY: 100}]); active();
    event('touchend', []); hidden();
    event('touchstart', [{clientX: 100, clientY: 100}]); active();
    fireEvent(canvas, new Event('pointercancel', {bubbles: true})); hidden();
    move(); active();
  });

  it('hides on window leave, blur, visibility changes and pagehide, then restores safely', () => {
    move(); active();
    fireEvent.mouseOut(canvas, {relatedTarget: null}); hidden();
    move(); active();
    fireEvent(host.ownerDocument.defaultView!, new Event('blur')); hidden();
    move(); hidden();
    fireEvent(host.ownerDocument.defaultView!, new Event('focus')); active();
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    fireEvent(document, new Event('visibilitychange')); hidden();
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    fireEvent(document, new Event('visibilitychange')); active();
    fireEvent(window, new PageTransitionEvent('pagehide')); hidden();
    fireEvent(window, new PageTransitionEvent('pageshow')); hidden();
    move(); active();
  });

  it('disconnects observers/listeners, restores its scoped styles and supports remount', async () => {
    move(); active();
    guard.dispose(); guard.dispose();
    expect(cursor.style.visibility).toBe('hidden');
    expect(cursor.style.clipPath).toBe('');
    expect(cursor).not.toHaveAttribute('data-vnc-cursor');
    expect(host).not.toHaveAttribute('data-vnc-local-cursor');
    move(); expect(cursor).not.toHaveAttribute('data-vnc-cursor-active');
    cursor.remove();
    guard = installRemoteCursorGuard(host);
    cursor = fallback(); guard.refresh();
    move(); active();
    host.remove();
    await waitFor(hidden);
  });
});
