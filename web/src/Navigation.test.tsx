import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createTheme } from '@mui/material/styles';
import App from './App';
import theme from './theme';
import { renderMaterial } from './test-render';

const clients = vi.hoisted(() => [] as { emit: (event: string) => void }[]);
vi.mock('/novnc/core/rfb.js', () => ({ default: class {
  listeners = new Map<string, () => void>();
  constructor() { clients.push(this); }
  addEventListener(name: string, callback: () => void) { this.listeners.set(name, callback); }
  emit(name: string) { this.listeners.get(name)?.(); }
  disconnect() {}
  focus() {}
  sendKey() {}
} }));
let failReconnect = false;
beforeEach(() => {
  clients.length = 0; failReconnect = false;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/browser/reconnect') {
      if (!init?.method || init.method === 'GET') return Response.json({operation_scope: '79c046fa-b06a-4e27-b369-5ac27558655a', operation_sequence: '1'});
      const action = JSON.parse(String(init.body));
      if (failReconnect && action.action === 'restart') return Response.json({error: '启动失败'}, {status: 503});
      return Response.json({ok: true, ...action, restarted: action.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (path === '/api/browser/mode') return Response.json({mode: 'software', state: 'software', generation: 1, active: false, owned: false, control_connected: true});
    if (path === '/api/requests/events') return new Response(new ReadableStream({ start(controller) {
      controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: {"requests":[],"connected":true,"cursor":"nav:1","events":[]}\n\n'));
      init?.signal?.addEventListener('abort', () => { try { controller.close(); } catch {} });
    } }), { headers: { 'Content-Type': 'text/event-stream' } });
    return new Response(JSON.stringify(path === '/api/keys' ? { keys: [] } : { csrf_token: 'navigation-test', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: false, settings_password_enabled: false }));
  }));
});

describe('default Material navigation', () => {
  it('uses the built-in palette, shape and breakpoints', () => {
    const defaults = createTheme({ cssVariables: true });
    for (const name of ['primary', 'secondary', 'error', 'success', 'info', 'warning'] as const) expect(theme.palette[name]).toEqual(defaults.palette[name]);
    expect(theme.palette.background).toEqual(defaults.palette.background);
    expect(theme.shape).toEqual(defaults.shape);
    expect(theme.breakpoints.values).toEqual(defaults.breakpoints.values);
    expect(theme.typography.fontSize).toBe(defaults.typography.fontSize);
    expect(theme.typography.fontFamily).toBe(defaults.typography.fontFamily);
    for (const variant of ['body1', 'body2', 'button', 'caption', 'subtitle1', 'subtitle2'] as const) expect(theme.typography[variant]).toEqual(defaults.typography[variant]);
  });

  it('keeps the toggle first, removes branding and keeps independent browser controls outside the toolbar', async () => {
    renderMaterial(<App />);
    await screen.findByRole('status', { name: '验证事件已连接' });
    const toolbar = document.querySelector('.topbar-toolbar')!;
    expect(toolbar.firstElementChild).toBe(screen.getByRole('button', { name: '收起导航' }));
    expect(toolbar).not.toHaveTextContent('webauthn-browser');
    expect(toolbar.querySelector('.brand-mark')).toBeNull();
    expect(within(toolbar as HTMLElement).queryByRole('status')).toBeNull();
    expect(document.getElementById('browser-controls')).not.toContainElement(toolbar as HTMLElement);
    expect(screen.getByRole('button', {name: '收起导航'})).toHaveTextContent('');
    expect(screen.getByRole('button', {name: '收起导航'}).querySelector('svg')).toBeInTheDocument();
    expect(within(toolbar as HTMLElement).getByRole('link', { name: '浏览器' })).toHaveAttribute('aria-current', 'page');
    for (let n = 0; n < 2; n++) {
      await userEvent.click(screen.getByRole('button', { name: '收起导航' }));
      expect(toolbar.firstElementChild).toBe(screen.getByRole('button', { name: '展开导航' }));
      expect(document.getElementById('navigation-group')).toHaveAttribute('hidden');
      expect(screen.getByRole('button', {name: '重新连接'})).toBeVisible();
      await userEvent.click(screen.getByRole('button', { name: '展开导航' }));
    }
    expect(screen.getByRole('button', { name: '重新连接' })).toBeVisible();
    expect(screen.getByRole('button', { name: '全屏' })).toBeVisible();
  });

  it('shows browser lifecycle status only in the canvas, hiding it after connection and showing recovery failure', async () => {
    renderMaterial(<App />);
    await screen.findByRole('status', { name: '验证事件已连接' });
    const canvas = screen.getByRole('region', { name: '浏览器远程桌面' });
    expect(within(canvas).getByRole('status')).toHaveTextContent(/正在(?:连接浏览器|准备浏览器窗口)/);
    const placeholder = canvas.querySelector('.vnc-placeholder')!;
    expect(placeholder).toHaveAttribute('aria-live', 'polite');
    expect(placeholder.querySelector('.MuiPaper-root')).toBeNull();
    expect(placeholder.firstElementChild).toHaveClass('MuiTypography-body2');
    expect(clients).toHaveLength(1);
    act(() => clients[0].emit('connect'));
    expect(canvas.querySelector('.vnc-placeholder')).toBeNull();
    act(() => clients[0].emit('disconnect'));
    expect(within(canvas).getByRole('status')).toHaveTextContent('连接已断开');
    failReconnect = true;
    await userEvent.click(screen.getByRole('button', { name: '重新连接' }));
    expect(within(canvas).getByRole('status')).toHaveTextContent('恢复失败，请重试');
    failReconnect = false;
    await userEvent.click(screen.getByRole('button', { name: '重新连接' }));
    expect(clients).toHaveLength(2);
    act(() => clients[1].emit('connect'));
    expect(canvas.isConnected).toBe(false);
    expect(document.querySelector('.vnc-placeholder')).toBeNull();
  });

  it('does not cover a still-displayed desktop during a failed recovery', async () => {
    renderMaterial(<App />);
    await screen.findByRole('status', { name: '验证事件已连接' });
    act(() => clients[0].emit('connect'));
    failReconnect = true;
    await userEvent.click(screen.getByRole('button', { name: '重新连接' }));
    expect(document.querySelector('.vnc-placeholder')).toBeNull();
    expect(screen.getByText('启动失败')).toBeVisible();
  });

  it('reserves the same noninteractive toggle slot on settings without collapsing navigation', async () => {
    const browser = renderMaterial(<App />);
    await screen.findByRole('button', { name: '收起导航' });
    const toggle = screen.getByRole('button', { name: '收起导航' });
    const layoutProperties = ['display', 'min-width', 'padding', 'margin', 'font-size', 'white-space', 'flex-shrink'];
    const layout = layoutProperties.map(property => getComputedStyle(toggle).getPropertyValue(property));
    const label = toggle.textContent;
    browser.unmount();
    window.history.replaceState({}, '', '/settings');
    renderMaterial(<App />);
    await screen.findByRole('heading', { name: '安全设置' });
    const placeholder = document.querySelector('.navigation-toggle') as HTMLButtonElement;
    expect(document.querySelector('.topbar-toolbar')!.firstElementChild).toBe(placeholder);
    expect(placeholder.nextElementSibling).toBe(document.getElementById('navigation-group'));
    expect(placeholder.textContent).toBe(label);
    expect(layoutProperties.map(property => getComputedStyle(placeholder).getPropertyValue(property))).toEqual(layout);
    expect(getComputedStyle(placeholder).visibility).toBe('hidden');
    expect(placeholder).not.toHaveAttribute('hidden');
    expect(placeholder).toBeDisabled();
    expect(placeholder).toHaveAttribute('tabindex', '-1');
    expect(placeholder).toHaveAttribute('aria-hidden', 'true');
    expect(placeholder).not.toHaveAttribute('aria-expanded');
    expect(placeholder).not.toHaveAttribute('aria-controls');
    placeholder.focus();
    expect(placeholder).not.toHaveFocus();
    placeholder.click();
    expect(document.querySelector('.topbar')).not.toHaveClass('collapsed');
    expect(document.getElementById('navigation-group')).not.toHaveAttribute('hidden');
    expect(screen.queryByRole('button', { name: /[收展]起?开?导航/ })).toBeNull();
    expect(screen.getByRole('link', { name: '设置' })).toHaveAttribute('aria-current', 'page');
  });
});
