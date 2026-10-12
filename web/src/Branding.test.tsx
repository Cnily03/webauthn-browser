import { readFileSync } from 'node:fs';
import { screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import App from './App';
import { renderMaterial } from './test-render';

it.each([['/', '解锁浏览器'], ['/settings', '解锁设置']])('uses the expanded brand on the %s login without translating its controls', async (route, heading) => {
  window.history.replaceState({}, '', route);
  const fetcher = vi.fn(async (_input: RequestInfo | URL) => Response.json({csrf_token: 'brand-test', vnc_authenticated: false, settings_authenticated: false,
    vnc_password_enabled: true, settings_password_enabled: true}));
  vi.stubGlobal('fetch', fetcher);
  renderMaterial(<App />);
  expect(await screen.findByRole('heading', {name: heading})).toBeVisible();
  expect(screen.getByText('WebAuthn Browser')).toBeVisible();
  expect(screen.queryByText('webauthn-browser')).toBeNull();
  expect(screen.getByLabelText('密码')).toBeVisible();
  expect(screen.getByRole('button', {name: '解锁'})).toBeEnabled();
  expect(fetcher.mock.calls.every(call => String(call[0]) === '/api/status')).toBe(true);
});

it('uses the expanded brand in the page title and Chinese no-JavaScript fallback', () => {
  const html = readFileSync('index.html', 'utf8');
  const page = new DOMParser().parseFromString(html, 'text/html');
  expect(page.title).toBe('WebAuthn Browser');
  expect(page.documentElement.lang).toBe('zh-CN');
  expect(page.querySelector('noscript')?.textContent).toBe('请启用 JavaScript，以使用 WebAuthn Browser 的浏览器和密钥管理功能。');
});
