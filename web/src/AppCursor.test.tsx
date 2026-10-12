import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { renderMaterial } from './test-render';

const clients = vi.hoisted(() => [] as {canvas: HTMLCanvasElement; cursor: HTMLCanvasElement; disconnect: () => void}[]);
vi.mock('/novnc/core/rfb.js', () => ({default: class {
  canvas = document.createElement('canvas');
  cursor = document.createElement('canvas');
  constructor(host: HTMLElement) {
    this.canvas.style.cursor = 'none'; this.canvas.tabIndex = -1;
    Object.assign(this.cursor.style, {position: 'fixed', pointerEvents: 'none', zIndex: '65535'});
    host.append(this.canvas); document.body.append(this.cursor); clients.push(this);
  }
  addEventListener() {}
  disconnect() { this.canvas.remove(); this.cursor.remove(); }
  focus() { this.canvas.focus(); }
  sendKey() {}
}}));
let controller: ReadableStreamDefaultController<Uint8Array>;
let hits: Element[];
beforeEach(() => {
  clients.length = 0;
  vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  Object.defineProperty(document, 'elementsFromPoint', {configurable: true, value: vi.fn(() => hits)});
  hits = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/requests/events') return new Response(new ReadableStream<Uint8Array>({start(value) {
      controller = value;
      init?.signal?.addEventListener('abort', () => { try { value.close(); } catch {} });
      value.enqueue(new TextEncoder().encode('event: snapshot\ndata: {"requests":[],"connected":true,"cursor":"cursor:1","events":[]}\n\n'));
    }}), {headers: {'Content-Type': 'text/event-stream'}});
    if (path === '/api/browser/reconnect') {
      if (!init?.method || init.method === 'GET') return Response.json({operation_scope: '79c046fa-b06a-4e27-b369-5ac27558655a', operation_sequence: '1'});
      const action = JSON.parse(String(init.body));
      return Response.json({ok: true, ...action, restarted: action.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (path === '/api/browser/mode') return Response.json({mode: 'software', state: 'software', generation: 1, active: false, owned: false, control_connected: true});
    return Response.json({csrf_token: 'cursor-test', vnc_authenticated: true, settings_authenticated: true,
      vnc_password_enabled: true, settings_password_enabled: false});
  }));
});

afterEach(() => { Reflect.deleteProperty(document, 'elementsFromPoint'); });

async function mount() {
  const view = renderMaterial(<App />);
  await screen.findByRole('status', {name: '验证事件已连接'});
  await waitFor(() => expect(clients).toHaveLength(1));
  const client = clients[0]; hits = [client.canvas];
  fireEvent.mouseMove(client.canvas, {clientX: 100, clientY: 100});
  expect(client.cursor).toHaveAttribute('data-vnc-cursor-active');
  return {view, client};
}

describe('App remote cursor lifecycle with real MUI portals and mocked noVNC DOM', () => {
  it('hides a stationary remote cursor when software authentication arrives over SSE', async () => {
    const {view, client} = await mount();
    expect(document.querySelector('.desktop')).not.toContainElement(document.querySelector('.request-status') as HTMLElement);
    await act(async () => {
      controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: ' + JSON.stringify({
        requests: [{id: 'cursor-software-auth', kind: 'create', stage: 'verify_password',
          rp_id: 'example.com', origin: 'https://example.com', uv: 'required', remaining_ms: 60000,
          candidates: [{key_id: 'key', key_name: '测试验证器', attachment: 'cross-platform', remaining_ms: 60000}], selected_key_id: 'key'}],
        connected: true, cursor: 'cursor:2', events: [],
      }) + '\n\n'));
    });
    expect(await screen.findByRole('dialog')).toBeVisible();
    await waitFor(() => expect(client.cursor).not.toHaveAttribute('data-vnc-cursor-active'));
    // Hit testing still returns the canvas in this mock, proving modal state
    // suppresses stale/captured mouse events independently of pointer movement.
    fireEvent.mouseMove(client.canvas, {clientX: 100, clientY: 100});
    expect(client.cursor).not.toHaveAttribute('data-vnc-cursor-active');
    await act(async () => {
      controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: {"requests":[],"connected":true,"cursor":"cursor:3","events":[]}\n\n'));
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.mouseMove(client.canvas, {clientX: 100, clientY: 100});
    expect(client.cursor).toHaveAttribute('data-vnc-cursor-active');
    view.unmount();
    expect(client.cursor).not.toBeInTheDocument();
    expect(document.querySelector('[data-vnc-cursor]')).toBeNull();
  });

  it('removes the old cursor on reconnect/pagehide and installs the guard on the new canvas', async () => {
    const {view, client} = await mount();
    fireEvent.click(screen.getByRole('button', {name: '重新连接'}));
    await waitFor(() => expect(clients).toHaveLength(2));
    expect(client.cursor).not.toBeInTheDocument();
    const current = clients[1];
    expect(current.cursor).toHaveAttribute('data-vnc-cursor');
    expect(current.cursor).not.toHaveAttribute('data-vnc-cursor-active');
    hits = [current.canvas];
    fireEvent.mouseMove(current.canvas, {clientX: 100, clientY: 100});
    expect(current.cursor).toHaveAttribute('data-vnc-cursor-active');
    act(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    expect(current.cursor).not.toBeInTheDocument();
    expect(document.querySelector('[data-vnc-cursor]')).toBeNull();
    view.unmount();
  });
});
