/**
 * noVNC's fallback cursor is a fixed canvas appended to document.body with a
 * z-index of 65535 (core/util/cursor.js in Debian's noVNC 1.3 and upstream 1.6).
 * Source: https://github.com/novnc/noVNC/blob/v1.3.0/core/util/cursor.js
 * Drag proxy: https://github.com/novnc/noVNC/blob/v1.3.0/core/util/events.js
 * Keep that parent: noVNC removes it from body on detach. Never reach through
 * RFB's private fields, replace its cursor, or intercept its input events.
 */
export function installRemoteCursorGuard(screen: HTMLElement) {
  const document = screen.ownerDocument;
  const window = document.defaultView!;
  const existingCanvases = new Set(document.querySelectorAll('body > canvas'));
  const cursors = new Map<HTMLCanvasElement, string>();
  const captures = new Set<HTMLElement>();
  let point: { x: number; y: number } | null = null;
  let windowActive = document.hasFocus();
  let focusOutside = false;
  let disposed = false;

  const mark = (element: HTMLElement, name: string, enabled: boolean) => {
    if (element.hasAttribute(name) !== enabled) element.toggleAttribute(name, enabled);
  };
  const discover = () => {
    for (const element of document.querySelectorAll<HTMLCanvasElement>('body > canvas')) {
      // Match the fallback DOM contract, not an arbitrary canvas or MUI portal.
      if (!existingCanvases.has(element) && !cursors.has(element)
          && element.style.position === 'fixed' && element.style.pointerEvents === 'none'
          && element.style.zIndex === '65535') {
        cursors.set(element, element.style.clipPath);
        mark(element, 'data-vnc-cursor', true);
      }
    }
    // noVNC's drag proxy stays in body too. Its window listeners still deliver
    // moves and button releases when an app control is above this lower layer.
    const capture = document.getElementById('noVNC_mouse_capture_elem');
    if (capture) { captures.add(capture); mark(capture, 'data-vnc-capture', true); }
  };
  const modalActive = () => Boolean(screen.closest('[inert], [aria-hidden="true"]'))
    || Array.from(document.querySelectorAll<HTMLElement>('[aria-modal="true"], dialog[open], .MuiModal-root'))
      .some(element => !screen.contains(element)
        && !element.closest('[hidden], [inert], [aria-hidden="true"]')
        && window.getComputedStyle(element).display !== 'none'
        && window.getComputedStyle(element).visibility !== 'hidden');
  const canvasAtPoint = () => {
    if (!point || !document.elementsFromPoint) return null;
    // A noVNC drag proxy may be the event target even when the pointer is over
    // a portal. Hit-test the actual UI underneath it instead of trusting target.
    const hit = document.elementsFromPoint(point.x, point.y).find(element =>
      !element.hasAttribute('data-vnc-cursor') && element.id !== 'noVNC_mouse_capture_elem');
    return hit instanceof HTMLCanvasElement && screen.contains(hit) ? hit : null;
  };
  const refresh = () => {
    if (disposed) return;
    discover();
    const canvas = canvasAtPoint();
    const active = Boolean(screen.isConnected && windowActive && document.visibilityState !== 'hidden'
      && !focusOutside && !modalActive() && canvas);
    mark(screen, 'data-vnc-local-cursor', !active);
    for (const capture of captures) mark(capture, 'data-vnc-local-cursor', !active);
    for (const [cursor] of cursors) {
      mark(cursor, 'data-vnc-cursor-active', active);
      if (active && canvas) {
        // Clip the image itself at the framebuffer edge, including letterbox
        // margins and zoom/fullscreen changes, without changing its hotspot.
        const bounds = canvas.getBoundingClientRect();
        const rect = cursor.getBoundingClientRect();
        const clip = `inset(${Math.max(0, bounds.top - rect.top)}px ${Math.max(0, rect.right - bounds.right)}px ${Math.max(0, rect.bottom - bounds.bottom)}px ${Math.max(0, bounds.left - rect.left)}px)`;
        if (cursor.style.clipPath !== clip) cursor.style.clipPath = clip;
      }
    }
  };
  const locate = (x: number, y: number) => {
    point = {x, y};
    // Pointer return restores the cursor even if a toolbar button retains focus.
    // A modal still blocks it independently, including while focus is moving.
    focusOutside = false;
    refresh();
  };
  const pointer = (event: Event) => {
    const mouse = event as MouseEvent;
    locate(mouse.clientX, mouse.clientY);
  };
  const touch = (event: Event) => {
    const first = (event as TouchEvent).touches[0];
    if (first) locate(first.clientX, first.clientY);
    else leave();
  };
  const leave = () => { point = null; refresh(); };
  const out = (event: Event) => {
    if (!(event as MouseEvent).relatedTarget) leave();
    else refresh();
  };
  const focus = (event: Event) => {
    focusOutside = event.target instanceof Node && !screen.contains(event.target);
    refresh();
  };
  const blur = () => { windowActive = false; leave(); };
  const wake = () => { windowActive = true; refresh(); };
  const options = { capture: true, passive: true };
  const listeners: [EventTarget, string, EventListener][] = [];
  const listen = (target: EventTarget, type: string, handler: EventListener) => {
    target.addEventListener(type, handler, options);
    listeners.push([target, type, handler]);
  };
  for (const type of ['pointerover', 'pointermove', 'pointerdown', 'pointerup', 'mouseover', 'mousemove', 'mousedown', 'mouseup']) listen(window, type, pointer);
  for (const type of ['pointerout', 'mouseout']) listen(window, type, out);
  for (const type of ['pointercancel', 'touchcancel']) listen(window, type, leave);
  for (const type of ['touchstart', 'touchmove', 'touchend']) listen(window, type, touch);
  listen(document, 'focusin', focus);
  listen(document, 'focusout', refresh);
  listen(window, 'blur', event => { if (event.target === event.currentTarget) blur(); });
  listen(window, 'focus', event => { if (event.target === event.currentTarget) wake(); });
  listen(window, 'pagehide', blur);
  listen(window, 'pageshow', wake);
  for (const type of ['visibilitychange', 'fullscreenchange', 'scroll', 'transitionend', 'animationend']) listen(document, type, refresh);
  listen(window, 'resize', refresh);
  if (window.visualViewport) {
    listen(window.visualViewport, 'resize', refresh);
    listen(window.visualViewport, 'scroll', refresh);
  }
  // MutationObserver runs before paint. This is essential when an SSE request
  // opens a portal over a stationary pointer, without any new mouse event.
  // Our data attributes are deliberately excluded to avoid observer loops.
  const observer = new MutationObserver(refresh);
  observer.observe(document.body, {subtree: true, childList: true, attributes: true,
    attributeFilter: ['style', 'class', 'hidden', 'open', 'aria-hidden', 'aria-modal', 'inert']});
  const resize = new ResizeObserver(refresh);
  resize.observe(screen);
  refresh();
  return {
    refresh,
    dispose() {
      if (disposed) return;
      disposed = true;
      observer.disconnect();
      resize.disconnect();
      for (const [target, type, handler] of listeners) target.removeEventListener(type, handler, options);
      screen.removeAttribute('data-vnc-local-cursor');
      // Disconnect noVNC before disposing: it owns removing the cursor canvas.
      // For a partial/failed connection, leave any surviving remote image hidden.
      for (const [cursor, clip] of cursors) {
        cursor.style.visibility = 'hidden';
        cursor.style.clipPath = clip;
        cursor.removeAttribute('data-vnc-cursor-active');
        cursor.removeAttribute('data-vnc-cursor');
      }
      for (const capture of captures) {
        capture.removeAttribute('data-vnc-capture');
        capture.removeAttribute('data-vnc-local-cursor');
      }
    },
  };
}
