import { StrictMode } from 'react';
import { act, fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderMaterial } from './test-render';
import type { BrowserProfile, ProfileConfiguration, ProfileViewer } from './profiles';

const clients = vi.hoisted(() => [] as {url: string; viewOnly: boolean; resizeSession: boolean; emit: (name: string) => void; disconnect: ReturnType<typeof vi.fn>}[]);
vi.mock('/p/default/novnc/core/rfb.js', () => ({default: class {
  viewOnly = false; resizeSession = true; listeners = new Map<string, () => void>();
  canvas = document.createElement('canvas'); disconnect = vi.fn(() => this.canvas.remove());
  constructor(host: HTMLElement, public url: string) {host.append(this.canvas); clients.push(this);}
  addEventListener(name: string, fn: () => void) {this.listeners.set(name, fn);}
  emit(name: string) {this.listeners.get(name)?.();}
  focus() {} sendKey() {}
}}));
vi.mock('/p/work/novnc/core/rfb.js', () => ({default: class {
  viewOnly = false; resizeSession = true; listeners = new Map<string, () => void>();
  canvas = document.createElement('canvas'); disconnect = vi.fn(() => this.canvas.remove());
  constructor(host: HTMLElement, public url: string) {host.append(this.canvas); clients.push(this);}
  addEventListener(name: string, fn: () => void) {this.listeners.set(name, fn);}
  emit(name: string) {this.listeners.get(name)?.();}
  focus() {} sendKey() {}
}}));
class Socket {static OPEN = 1; readyState = 0; send = vi.fn(); close = vi.fn(); onopen = null; onclose = null; onmessage = null; onerror = null;}
const token = 'a'.repeat(64);
const originalViewport = {width: window.innerWidth, height: window.innerHeight};
afterEach(() => {vi.stubGlobal('innerWidth', originalViewport.width); vi.stubGlobal('innerHeight', originalViewport.height);});
const workId = '59df70a6-bdd5-4b04-af35-76332cd72419';
const savedKey = 'webauthn-browser.saved-profiles';
const saveHints = (...profiles: Pick<BrowserProfile, 'id' | 'name'>[]) => localStorage.setItem(savedKey, JSON.stringify(profiles.map(profile => ({...profile, lastUsedAt: 1}))));
const savedNames = () => JSON.parse(localStorage.getItem(savedKey) || '[]').map((profile: {name: string}) => profile.name);
const baseProfile: BrowserProfile = {id: 'default', name: 'default', enabled: true, effective_enabled: true, password_enabled: true, idle_timeout_seconds: 180};
let configuration: ProfileConfiguration;
let viewer: ProfileViewer;
let authenticated: boolean;
let calls: {path: string; method: string; body: any; headers: Record<string,string>; signal?: AbortSignal | null}[];
let acquireResponse: (() => Promise<Response>) | null;
let statusResponse: (() => Promise<Response>) | null;
let browserMetadataResponse: (() => Promise<Response>) | null;
let browserActionResponse: ((init?: RequestInit) => Promise<Response>) | null;
let loginFailure: boolean;
const flush = async () => { for (let i = 0; i < 100; i++) await Promise.resolve(); };
const pathCalls = (path: string) => calls.filter(call => call.path === `/p/default${path}`);
const browserActions = () => pathCalls('/api/browser/reconnect').filter(call => call.method === 'POST');
const browserMetadata = () => Response.json({operation_scope: '541fa903-e3f9-4673-910a-ae286c773d25', operation_sequence: '1'});
const setViewport = (width: number, height: number) => {vi.stubGlobal('innerWidth', width); vi.stubGlobal('innerHeight', height);};
const advance = (ms: number) => act(async () => {await vi.advanceTimersByTimeAsync(ms); await flush();});
beforeEach(() => {
  vi.resetModules(); vi.useFakeTimers(); sessionStorage.clear(); clients.length = 0; calls = []; authenticated = false; loginFailure = false; acquireResponse = null; statusResponse = null;
  browserMetadataResponse = null; browserActionResponse = null;
  configuration = {multi_profile: true, profiles: [{...baseProfile}]};
  viewer = {viewer_id: 'first-viewer', viewer_token: token, owner: true, generation: 1, expired: false, idle_remaining_ms: 180000, idle_timeout_seconds: 180};
  vi.stubGlobal('WebSocket', Socket);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input), method = init?.method || 'GET', body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({path, method, body, headers: init?.headers as Record<string,string> || {}, signal: init?.signal});
    const route = path.replace(/^\/p\/[^/]+/, '/p/default');
    if (route === '/api/profiles/public') return Response.json({...configuration, profiles: configuration.profiles.map(({id: _id, ...profile}) => profile)});
    if (route === '/api/profiles') return Response.json(configuration);
    if (route === '/api/profiles/config' && method === 'PUT') {
      configuration = {...configuration, multi_profile: body.multi_profile, profiles: configuration.profiles.map(profile => ({...profile, effective_enabled: body.multi_profile ? profile.enabled : profile.id === 'default'}))};
      return Response.json(configuration);
    }
    if (route.startsWith('/api/profiles/') && method === 'PATCH') {
      if (body.password !== undefined) authenticated = false;
      configuration = {...configuration, profiles: configuration.profiles.map(profile => profile.id === route.slice('/api/profiles/'.length) ? {...profile, ...body, password_enabled: body.password === null ? false : profile.password_enabled} : profile)};
      return Response.json(configuration);
    }
    if (route === '/p/default/api/status' || route === '/api/status' || route === '/api/security') return Response.json({csrf_token: 'csrf', vnc_authenticated: authenticated, settings_authenticated: true, vnc_password_enabled: configuration.profiles[0]?.password_enabled ?? false, settings_password_enabled: true, engine_connected: true, profile: configuration.profiles[0]});
    if (route === '/p/default/api/login') {if (loginFailure) return Response.json({error: '密码错误。'}, {status: 401}); authenticated = true; return Response.json({ok: true});}
    if (route === '/p/default/api/logout') {authenticated = false; return Response.json({ok: true});}
    if (route === '/p/default/api/viewer/acquire') {
      if (acquireResponse) return acquireResponse();
      if ((init?.headers as Record<string,string>)?.['X-Viewer-Token']) {viewer = {...viewer, expired: false, owner: true, generation: viewer.generation + 1}; const {viewer_token: _, ...value} = viewer; return Response.json(value);}
      return Response.json(viewer);
    }
    if (route === '/p/default/api/viewer/status') {if (statusResponse) return statusResponse(); const {viewer_token: _, ...value} = viewer; return Response.json(value);}
    if (route === '/p/default/api/viewer/ticket') return Response.json({ticket: 'one-use-ticket', expires_in_ms: 10000});
    if (route === '/p/default/api/browser/reconnect') {
      if (method === 'GET') return browserMetadataResponse ? browserMetadataResponse() : browserMetadata();
      if (browserActionResponse) return browserActionResponse(init);
      return Response.json({ok: true, ...body, restarted: body.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (route === '/p/default/api/browser/mode') return Response.json({mode: 'software', state: 'software', generation: 1, active: false, owned: false, control_connected: true});
    if (route === '/p/default/api/requests/events') return new Response(new ReadableStream({start(controller) {
      controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: {"requests":[],"connected":true,"cursor":"profile:1","events":[]}\n\n'));
      init?.signal?.addEventListener('abort', () => {try {controller.close();} catch {}});
    }}), {headers: {'Content-Type': 'text/event-stream'}});
    if (route === '/api/keys') return Response.json({keys: []});
    if (route === '/api/downloads') return Response.json({files: []});
    return Response.json({ok: true});
  }));
});
async function mount(route: string, strict = false, historyState: unknown = {}) {
  window.history.replaceState(historyState, '', route);
  const {default: ProfileApp} = await import('./ProfileApp');
  const navigateDocument = vi.fn(), replaceDocument = vi.fn();
  const app = <ProfileApp navigateDocument={navigateDocument} replaceDocument={replaceDocument} />;
  const view = renderMaterial(strict ? <StrictMode>{app}</StrictMode> : app);
  await act(flush); return {...view, navigateDocument, replaceDocument};
}

describe('profile entry and remembered cookies', () => {
  it('removes legacy profile UUIDs from menu, preferences, history, session and root query before ordinary use', async () => {
    saveHints({id: workId, name: 'WoRk'});
    localStorage.setItem(`webauthn-browser.mode.${workId}`, 'native');
    sessionStorage.setItem('webauthn-browser.profile-navigation', JSON.stringify({id: workId, name: 'work'}));
    await mount(`/?profile=${workId}`, true, {__webauthnBrowserProfile: {id: workId, name: 'work'}, unrelated: true});
    expect(JSON.stringify({...localStorage})).not.toContain(workId);
    expect(JSON.stringify({...sessionStorage})).not.toContain(workId);
    expect(JSON.stringify(window.history.state)).not.toContain(workId); expect(window.history.state.unrelated).toBe(true);
    expect(window.location.search).toBe(''); expect(savedNames()).toEqual(['work']);
    expect(localStorage.getItem('webauthn-browser.mode.name.work')).toBe('native');
    expect(calls.every(call => !call.path.includes(workId) && !JSON.stringify(call.body ?? null).includes(workId))).toBe(true);
  });

  it('requires a nonempty password for a fixed protected name and clears it after failure and success', async () => {
    await mount('/profile/DeFaUlT');
    expect(screen.getByRole('textbox', {name: '配置名称'})).toBeDisabled(); expect(screen.getByRole('textbox', {name: '配置名称'})).toHaveValue('default');
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.getByText('请输入密码。')).toBeVisible(); expect(pathCalls('/api/login')).toHaveLength(0);
    loginFailure = true; fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'wrong'}}); fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.getByText('密码错误。')).toBeVisible(); expect(screen.getByLabelText(/^密码/)).toHaveValue('');
    loginFailure = false; fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'right'}}); fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(screen.queryByLabelText(/^密码/)).toBeNull();
    expect(localStorage.getItem('webauthn-browser.saved-profiles')).not.toMatch(/right|wrong|viewer_token/);
  });
  it('clears a detached password input and ignores a late successful login after pagehide', async () => {
    const view = await mount('/profile/default'); const field = screen.getByLabelText(/^密码/) as HTMLInputElement;
    fireEvent.change(field, {target: {value: 'private-test-only'}});
    const original = globalThis.fetch; let finish!: (value: Response) => void;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/api/login') ? new Promise<Response>(resolve => {finish = resolve;}) : original(input, init)));
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(field.value).toBe(''); act(() => window.dispatchEvent(new Event('pagehide')));
    await act(async () => {finish(Response.json({ok: true})); await flush();});
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(0); expect(localStorage.getItem('webauthn-browser.saved-profiles')).toBeNull();
    fireEvent.change(field, {target: {value: 'detached-test-only'}}); view.unmount(); expect(field.value).toBe('');
  });
  it('uses an existing HttpOnly-authorized session without replaying login or storing a token', async () => {
    authenticated = true; await mount('/profile/default', true); await advance(0);
    expect(pathCalls('/api/login')).toHaveLength(0); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    expect(localStorage.getItem('webauthn-browser.saved-profiles')).not.toContain(token);
    expect(clients).toHaveLength(1);
    expect(clients[0].url).toBe('ws://localhost:8080/p/default/ws?ticket=one-use-ticket');
    expect(clients[0].url).not.toContain(token);
  });
  it('enters a passwordless default directly when multi-profile mode is off', async () => {
    configuration.multi_profile = false; configuration.profiles[0].password_enabled = false;
    await mount('/'); expect(pathCalls('/api/login')[0].body).toEqual({scope: 'vnc', password: ''});
    expect(screen.queryByRole('textbox', {name: '配置名称'})).toBeNull(); expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('shows only the password for a protected default with multi-profile mode off', async () => {
    configuration.multi_profile = false; await mount('/');
    expect(screen.queryByRole('textbox', {name: '配置名称'})).toBeNull(); expect(screen.getByLabelText(/^密码/)).toBeVisible(); expect(pathCalls('/api/viewer/acquire')).toHaveLength(0);
  });
  it('asks for a profile at the multi-profile root and supports a passwordless explicit login', async () => {
    configuration.profiles[0].password_enabled = false;
    const {navigateDocument} = await mount('/');
    expect(screen.getByRole('textbox', {name: '配置名称'})).toBeEnabled(); expect(pathCalls('/api/viewer/acquire')).toHaveLength(0);
    fireEvent.change(screen.getByRole('textbox', {name: '配置名称'}), {target: {value: 'DEFAULT'}}); fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(navigateDocument).toHaveBeenCalledWith('/profile/default'); expect(pathCalls('/api/login')[0].body.password).toBe('');
  });
  it('lists only remembered profiles and offers the multi-profile login route', async () => {
    localStorage.setItem('webauthn-browser.saved-profiles', JSON.stringify([{id: 'default', name: 'old-name', lastUsedAt: Date.now()}]));
    await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'}));
    expect(within(screen.getByRole('menuitem', {name: 'old-name 配置不存在或已停用'})).getByText('old-name')).toBeVisible();
    expect(screen.getByRole('menuitem', {name: '登录其他配置'})).toBeVisible();
  });
  it.each(['/downloads', '/downloads?profile=default', '/downloads?profile=missing'])('opens global %s without a profile or runtime and returns Browser to the root', async route => {
    authenticated = false; configuration.profiles[0].password_enabled = true;
    acquireResponse = () => new Promise(() => {});
    const {navigateDocument} = await mount(route);
    expect(window.location.pathname + window.location.search).toBe('/downloads');
    expect(screen.getByRole('heading', {name: '下载'})).toBeVisible();
    expect(calls.filter(call => call.path === '/api/downloads')).toHaveLength(1);
    expect(calls.some(call => call.path.startsWith('/p/'))).toBe(false); expect(clients).toHaveLength(0);
    expect(screen.getByRole('link', {name: '下载'})).toHaveAttribute('href', '/downloads');
    expect(screen.getByRole('link', {name: '浏览器'})).toHaveAttribute('href', '/');
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(navigateDocument).toHaveBeenCalledExactlyOnceWith('/');
  });
  it('loads a non-default profile module and scopes its runtime, VNC, and event requests independently', async () => {
    authenticated = true; const id = '59df70a6-bdd5-4b04-af35-76332cd72419';
    configuration.profiles = [{...baseProfile, id, name: 'work'}];
    await mount('/profile/WORK'); await advance(0);
    expect(clients).toHaveLength(1); expect(clients[0].url).toContain('/p/work/ws?ticket=');
    expect(calls.filter(call => call.path !== '/api/profiles/public').every(call => call.path.startsWith('/p/work/'))).toBe(true);
    expect(screen.getByRole('link', {name: '下载'})).toHaveAttribute('href', '/downloads');
  });
  it.each(['/profile/default', '/profile/work', '/profile/missing', '/profile/a%2Fb', '/profile/project.git', '/profile/%E0%A4%A', '/profile/'])('replaces legacy %s with the single-profile root before validating names', async route => {
    configuration.multi_profile = false; authenticated = true;
    const length = window.history.length; const view = await mount(route);
    expect(window.location.pathname + window.location.search).toBe('/'); expect(window.history.length).toBe(length);
    expect(screen.queryByRole('textbox', {name: '配置名称'})).toBeNull();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(view.navigateDocument).not.toHaveBeenCalled();
    expect(calls.filter(call => call.path.startsWith('/p/')).every(call => call.path.startsWith('/p/default/'))).toBe(true);
    expect(screen.getByRole('link', {name: '浏览器'})).toHaveAttribute('href', '/');
  });
  it('uses the same default password flow after a legacy named URL is replaced in single mode', async () => {
    configuration.multi_profile = false; const view = await mount('/profile/work?profile=work');
    expect(window.location.pathname + window.location.search).toBe('/'); expect(screen.queryByRole('textbox', {name: '配置名称'})).toBeNull();
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'same-default-password'}});
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(pathCalls('/api/login')[0].body).toEqual({scope: 'vnc', password: 'same-default-password'});
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(window.location.pathname).toBe('/');
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(view.replaceDocument).not.toHaveBeenCalled();
  });
  it('ignores an expired named identity when single mode has one canonical default', async () => {
    configuration.multi_profile = false; authenticated = true;
    await mount('/profile/work', true, {__webauthnBrowserProfile: {id: workId, name: 'work', path: '/profile/work', expired: true}});
    expect(window.location.pathname).toBe('/'); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    expect(screen.queryByText('配置切换已过期，请重新选择配置。')).toBeNull();
  });
  it('rejects a disabled named profile and treats one trailing slash as the same enabled profile', async () => {
    configuration.profiles[0].effective_enabled = false;
    const locked = await mount('/profile/default'); expect(screen.getByRole('button', {name: '解锁'})).toBeDisabled();
    locked.unmount(); configuration.profiles[0].effective_enabled = true; authenticated = true;
    await mount('/profile/DEFAULT/'); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('does not make global Settings depend on profile discovery or an enabled browser profile', async () => {
    configuration.profiles = []; const original = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/api/profiles/public' ? new Promise<Response>(() => {}) : original(input, init)));
    await mount('/settings'); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    expect(calls.some(call => call.path.includes('/api/viewer/'))).toBe(false);
  });
  it('leaves global settings accessible without acquiring any profile or engine', async () => {
    await mount('/settings'); expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible();
    expect(calls.some(call => call.path.includes('/api/viewer/'))).toBe(false); expect(calls.some(call => call.path.includes('/api/browser/'))).toBe(false);
  });
});

describe('profile navigation placement and current selection', () => {
  it.each([
    ['/profile/default', true, '/profile/default', '/downloads'],
    ['/', true, '/', '/downloads'],
    ['/', false, '/', '/downloads'],
  ] as const)('shows the full password-gate navbar on %s with multi-profile=%s without acquiring browser capabilities', async (route, multiProfile, browserPath, downloadsPath) => {
    configuration.multi_profile = multiProfile;
    const {navigateDocument} = await mount(route);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    const navigation = screen.getByRole('navigation', {name: '主导航'});
    expect(within(navigation).getAllByRole('link').map(link => link.textContent)).toEqual(['浏览器', '设置', '下载']);
    expect(within(navigation).getByRole('link', {name: '浏览器'})).toHaveAttribute('href', browserPath);
    expect(within(navigation).getByRole('link', {name: '下载'})).toHaveAttribute('href', downloadsPath);
    const toggle = document.querySelector('.navigation-toggle')!;
    expect(toggle).toBeDisabled(); expect(toggle).toHaveAttribute('aria-hidden', 'true'); expect(toggle).toHaveStyle({visibility: 'hidden'});
    expect(toggle.nextElementSibling).toBe(document.getElementById('navigation-group'));
    if (multiProfile) expect(document.getElementById('navigation-group')!.firstElementChild).toBe(screen.getByRole('button', {name: '浏览器配置'}));
    else {expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull(); expect(document.querySelector('.topbar-toolbar')!.firstElementChild).toBe(toggle);}
    fireEvent.click(within(navigation).getByRole('link', {name: '设置'}));
    expect(navigateDocument).toHaveBeenLastCalledWith('/settings');
    fireEvent.click(within(navigation).getByRole('link', {name: '下载'})); await act(flush);
    expect(navigateDocument).toHaveBeenLastCalledWith(downloadsPath);
    expect(calls.filter(call => call.path.includes('/api/viewer/') || call.path.includes('/api/browser/'))).toHaveLength(0);
    expect(clients).toHaveLength(0);
  });
  it('keeps collapse far left and hides the profile icon together with the navigation group', async () => {
    authenticated = true; await mount('/profile/default');
    const toolbar = document.querySelector('.topbar-toolbar')!;
    const profileButton = screen.getByRole('button', {name: '浏览器配置'});
    const toggle = screen.getByRole('button', {name: '收起导航'});
    expect(document.querySelectorAll('.topbar')).toHaveLength(1);
    expect(toolbar.firstElementChild).toBe(toggle); expect(document.getElementById('navigation-group')!.firstElementChild).toBe(profileButton);
    expect(toggle.nextElementSibling).toBe(document.getElementById('navigation-group'));
    expect(getComputedStyle(profileButton).width).toBe(getComputedStyle(toggle).width);
    expect(getComputedStyle(profileButton).height).toBe(getComputedStyle(toggle).height);
    expect(getComputedStyle(document.querySelector('.topbar')!).right).toBe('auto');
    fireEvent.click(toggle); await act(flush);
    expect(screen.getByRole('button', {name: '展开导航'})).toBe(toggle);
    expect(document.getElementById('navigation-group')).toHaveAttribute('hidden'); expect(profileButton).not.toBeVisible();
    expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    fireEvent.click(toggle); await act(flush);
    act(() => profileButton.focus());
    fireEvent.click(profileButton); await act(flush);
    expect(profileButton).toHaveAttribute('aria-expanded', 'true');
    const current = screen.getByRole('menuitem', {name: 'default 当前配置'});
    expect(current).toHaveAttribute('aria-current', 'true');
    expect(within(current).getByRole('img', {name: '当前配置'})).toHaveClass('MuiSvgIcon-colorSuccess');
    expect(screen.getByRole('menuitem', {name: '登录其他配置'})).toBeVisible();
    fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'}); await advance(300);
    expect(screen.queryByRole('menu')).toBeNull(); expect(profileButton).toHaveAttribute('aria-expanded', 'false');
    expect(profileButton).toHaveFocus();
    expect(document.getElementById('navigation-group')).not.toHaveAttribute('hidden');
  });
  it.each([true, false])('marks only the current authenticated name when owner=%s and invalidates a renamed cached name', async owner => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'});
    authenticated = true; viewer.owner = owner; await mount('/profile/work');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 当前配置'})).toHaveAttribute('aria-current', 'true');
    fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'}); await advance(300);
    configuration.profiles[1] = {...configuration.profiles[1], name: 'renamed-work'};
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible();
    expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
    expect(savedNames()).toContain('work'); expect(localStorage.getItem(savedKey)).not.toContain(workId);
  });
  it('retains the live viewer through global navigation and returns Downloads Browser to the root', async () => {
    authenticated = true; const view = await mount('/profile/default');
    const profileButton = screen.getByRole('button', {name: '浏览器配置'});
    const toggle = screen.getByRole('button', {name: '收起导航'});
    const client = clients[0];
    for (const route of ['设置', '浏览器', '下载']) {
      fireEvent.click(screen.getByRole('link', {name: route})); await act(flush);
      expect(screen.getByRole('button', {name: '浏览器配置'})).toBe(profileButton);
      expect(document.getElementById('navigation-group')!.firstElementChild).toBe(profileButton);
      expect(document.querySelector('.topbar-toolbar')!.firstElementChild).toBe(toggle);
      expect(getComputedStyle(toggle).visibility).toBe(route === '浏览器' ? 'visible' : 'hidden');
      if (route === '浏览器') expect(toggle).toBeEnabled(); else expect(toggle).toBeDisabled();
      fireEvent.click(profileButton); await act(flush);
      expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toHaveAttribute('aria-current', 'true');
      fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'}); await advance(300);
    }
    expect(clients).toHaveLength(1); expect(client.disconnect).not.toHaveBeenCalled();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(pathCalls('/api/viewer/release')).toHaveLength(0);
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(view.navigateDocument).toHaveBeenCalledExactlyOnceWith('/');
  });
  it.each(['/login', '/settings', '/profile/default'])('does not mark a remembered profile as current on unauthenticated %s', async route => {
    localStorage.setItem('webauthn-browser.saved-profiles', JSON.stringify([{id: 'default', name: 'default', lastUsedAt: Date.now()}]));
    await mount(route);
    const profileButton = screen.getByRole('button', {name: '浏览器配置'});
    expect(document.getElementById('navigation-group')!.firstElementChild).toBe(profileButton);
    expect(document.querySelectorAll('.topbar')).toHaveLength(1);
    fireEvent.click(profileButton); await act(flush);
    expect(within(screen.getByRole('menuitem', {name: /^default(?: 配置认证失效)?$/})).getByText('default')).toBeVisible();
    expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
    expect(screen.getByRole('menuitem', {name: /^default(?: 配置认证失效)?$/})).not.toHaveAttribute('aria-current');
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(0);
  });
  it('keeps the active profile visible even if its remembered-menu entry is removed', async () => {
    authenticated = true; await mount('/profile/default');
    localStorage.removeItem('webauthn-browser.saved-profiles');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toHaveAttribute('aria-current', 'true');
  });
  it('keeps single-mode Browser at root through Settings and real back/forward traversal', async () => {
    configuration.multi_profile = false; authenticated = true; const view = await mount('/profile/old');
    const client = clients[0], length = window.history.length;
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    expect(window.location.pathname).toBe('/settings');
    await act(async () => {window.history.back(); await vi.advanceTimersByTimeAsync(50); await flush();});
    expect(window.location.pathname).toBe('/'); expect(screen.getByRole('link', {name: '浏览器'})).toHaveAttribute('aria-current', 'page');
    await act(async () => {window.history.forward(); await vi.advanceTimersByTimeAsync(50); await flush();});
    expect(window.location.pathname).toBe('/settings');
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(window.location.pathname).toBe('/'); expect(window.history.length).toBe(length + 2);
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(view.replaceDocument).not.toHaveBeenCalled();
    expect(clients).toEqual([client]); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('replaces a live non-default Browser with root when single mode becomes active', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true;
    const view = await mount('/profile/work');
    configuration = {...configuration, multi_profile: false, profiles: configuration.profiles.map(profile => ({...profile, effective_enabled: profile.id === 'default'}))};
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    expect(view.replaceDocument).toHaveBeenCalledExactlyOnceWith('/'); expect(view.navigateDocument).not.toHaveBeenCalled();
    expect(calls.some(call => call.path.startsWith('/p/default/'))).toBe(false); expect(savedNames()).toContain('work');
  });
  it('hides the profile icon in single-profile mode and responds to mode changes without replacing VNC', async () => {
    authenticated = true; configuration.multi_profile = false; await mount('/');
    const client = clients[0], length = window.history.length;
    expect(window.location.pathname).toBe('/');
    expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    expect(document.querySelector('.topbar-toolbar')!.firstElementChild).toBe(screen.getByRole('button', {name: '收起导航'}));
    configuration.multi_profile = true; fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    expect(document.getElementById('navigation-group')!.firstElementChild).toBe(screen.getByRole('button', {name: '浏览器配置'}));
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menu')).toBeVisible();
    configuration.multi_profile = false; fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    expect(screen.queryByRole('menu')).toBeNull();
    configuration.multi_profile = true; fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    expect(screen.getByRole('button', {name: '浏览器配置'})).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('menu')).toBeNull();
    expect(clients).toHaveLength(1); expect(client.disconnect).not.toHaveBeenCalled();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    expect(window.location.pathname).toBe('/profile/default'); expect(window.history.length).toBe(length);
  });
});

describe('persistent profile hints and explicit local forget', () => {
  it('resumes only a remembered default at the normal root and lets plus bypass it', async () => {
    authenticated = true; saveHints(baseProfile);
    const view = await mount('/');
    expect(pathCalls('/api/login')).toHaveLength(0); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.click(screen.getByRole('menuitem', {name: '登录其他配置'}));
    expect(view.navigateDocument).toHaveBeenCalledWith('/');
    view.unmount(); calls = [];
    const chooser = await mount('/');
    expect(screen.getByRole('textbox', {name: '配置名称'})).toBeEnabled(); expect(pathCalls('/api/status')).toHaveLength(0);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(0); expect(chooser.navigateDocument).not.toHaveBeenCalled();
  });
  it('does not guess a remembered named profile when default is absent', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true;
    saveHints({id: workId, name: 'work'}); await mount('/');
    expect(screen.getByRole('textbox', {name: '配置名称'})).toBeEnabled();
    expect(calls.some(call => call.path.includes('/api/viewer/') || call.path.startsWith('/p/'))).toBe(false);
  });
  it('retains passwordless default and other saved hints through repeated single/multi toggles and root remount', async () => {
    authenticated = true; configuration.multi_profile = false; configuration.profiles[0].password_enabled = false;
    saveHints({id: workId, name: 'work'}); const view = await mount('/');
    expect(savedNames()).toEqual(['default', 'work']); expect(pathCalls('/api/login')).toHaveLength(0);
    for (const multi_profile of [true, false, true, false, true]) {
      configuration = {...configuration, multi_profile}; fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
      expect(savedNames()).toEqual(['default', 'work']);
      expect(Boolean(screen.queryByRole('button', {name: '浏览器配置'}))).toBe(multi_profile);
    }
    view.unmount(); calls = []; await mount('/');
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull(); expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    expect(pathCalls('/api/login')).toHaveLength(0); expect(savedNames()).toEqual(['default', 'work']);
  });
  it('retains expired or rejected login hints in orange until successful authentication', async () => {
    saveHints(baseProfile); await mount('/profile/default');
    const open = async () => {fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);};
    const close = async () => {fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'}); await advance(300);};
    await open(); expect(within(screen.getByRole('menuitem', {name: 'default 配置认证失效'})).getByRole('img', {name: '配置认证失效'})).toHaveClass('MuiSvgIcon-colorWarning'); await close();
    loginFailure = true; fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'wrong'}}); fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(savedNames()).toEqual(['default']); await open(); expect(screen.getByRole('menuitem', {name: 'default 配置认证失效'})).toBeVisible(); await close();
    loginFailure = false; fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'right'}}); fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    await open(); expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toHaveAttribute('aria-current', 'true');
    expect(screen.queryByRole('img', {name: '配置认证失效'})).toBeNull(); expect(localStorage.getItem(savedKey)).not.toMatch(/right|wrong|viewer_token/);
  });
  it('revalidates invalid cached access and opens its named password gate without sending the current viewer capability', async () => {
    saveHints(baseProfile); const view = await mount('/profile/default');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default 配置认证失效'})).toBeVisible(); const before = calls.length;
    fireEvent.click(screen.getByRole('menuitem', {name: 'default 配置认证失效'})); await act(flush);
    expect(view.navigateDocument).toHaveBeenCalledExactlyOnceWith('/profile/default');
    const validation = calls.slice(before).find(call => call.path === '/p/default/api/status');
    expect(validation).toBeDefined(); expect(validation!.headers).not.toHaveProperty('X-Viewer-Token');
    expect(pathCalls('/api/login')).toHaveLength(0); expect(savedNames()).toEqual(['default']);
    view.unmount(); const gate = await mount('/profile/default');
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    loginFailure = true; fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'wrong'}});
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.getByRole('alert')).toHaveTextContent('密码错误。'); expect(gate.navigateDocument).not.toHaveBeenCalled();
  });
  it.each(['status', 'login'])('marks a profile deleted during entry %s red instead of reporting invalid authentication', async boundary => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'});
    const original = globalThis.fetch; const unavailable = `${boundary === 'status' ? '/api/status' : '/api/login'}`;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === `/p/work${unavailable}` ? Promise.resolve(Response.json({error: '浏览器配置不存在或已停用。'}, {status: 404})) : original(input, init)));
    await mount('/profile/work');
    if (boundary === 'login') {
      fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'test-only'}});
      fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    }
    expect(screen.getByRole('button', {name: '解锁'})).toBeDisabled();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible();
    expect(screen.queryByRole('img', {name: '配置认证失效'})).toBeNull(); expect(savedNames()).toEqual(['work']);
  });
  it.each([200, 401, 404])('ignores a delayed menu status %s after a newer successful same-document login', async status => {
    saveHints(baseProfile); const view = await mount('/profile/default'); const original = globalThis.fetch;
    let finish!: (response: Response) => void, delay = true;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/p/default/api/status' && delay) {delay = false; return new Promise<Response>(resolve => {finish = resolve;});}
      return original(input, init);
    }));
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.click(screen.getByRole('menuitem', {name: 'default 配置认证失效'})); await act(flush);
    fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'}); await advance(300);
    fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'new-session-test-only'}});
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
    await act(async () => {finish(Response.json(status === 200 ? {vnc_authenticated: false} : {error: 'stale validation'}, {status})); await flush();});
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull();
    expect(screen.queryByText('stale validation')).toBeNull(); expect(screen.queryByText('浏览器配置不存在或已停用。')).toBeNull();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toBeVisible();
    expect(JSON.parse(localStorage.getItem(savedKey)!)[0]).not.toHaveProperty('status');
  });
  it('marks a target removed during cookie validation red and reports the error outside the menu', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'});
    const original = globalThis.fetch; vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === `/p/work/api/status` ? Promise.resolve(Response.json({error: 'gone'}, {status: 404})) : original(input, init)));
    const view = await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.click(screen.getByRole('menuitem', {name: 'work'})); await act(flush); await advance(300);
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(screen.getByRole('alert')).toHaveTextContent('浏览器配置不存在或已停用。');
    expect(screen.queryByRole('menu')).toBeNull(); expect(savedNames()).toEqual(['work']);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible();
    expect(within(screen.getByRole('menu')).queryByRole('alert')).toBeNull();
  });
  it('retains a hint without a failure dot after a network error', async () => {
    saveHints(baseProfile); const original = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/p/default/api/status' ? Promise.reject(new Error('network unavailable')) : original(input, init)));
    await mount('/profile/default');
    expect(screen.getByRole('navigation', {name: '主导航'})).toBeVisible(); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default'})).toBeVisible(); expect(screen.queryByRole('img', {name: '配置认证失效'})).toBeNull(); expect(savedNames()).toEqual(['default']);
  });
  it('opens the named login gate when the server rejects an old credential after name reuse', async () => {
    saveHints({id: workId, name: 'reused'}); configuration.profiles.push({...baseProfile, id: 'replacement-admin-id', name: 'reused'});
    const view = await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.click(screen.getByRole('menuitem', {name: 'reused'})); await act(flush);
    expect(view.navigateDocument).toHaveBeenCalledExactlyOnceWith('/profile/reused');
    expect(calls.some(call => call.path === '/p/reused/api/status')).toBe(true);
    expect(calls.some(call => call.path.endsWith('/api/login') || call.path.endsWith('/api/viewer/acquire'))).toBe(false);
    expect(savedNames()).toEqual(['reused']); expect(localStorage.getItem(savedKey)).not.toContain(workId);
  });
  it('stays safely locked when the selected name disappears after a rename', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'});
    await mount('/profile/work'); configuration.profiles[1].name = 'renamed';
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'not-for-renamed'}});
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.getByText('浏览器配置不存在或已停用。')).toBeVisible();
    expect(calls.some(call => call.path.startsWith('/p/renamed/') || call.path.endsWith('/api/login'))).toBe(false);
    expect(screen.getByRole('button', {name: '浏览器'})).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByRole('link', {name: '下载'})).toHaveAttribute('href', '/downloads');
  });
  it('forgets only the inactive target credential and hint from the hover delete action', async () => {
    authenticated = true; saveHints({id: workId, name: 'retired'}); const view = await mount('/profile/default');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const active = screen.getByRole('menuitem', {name: 'default 当前配置'});
    fireEvent.mouseEnter(active); fireEvent.keyDown(active, {key: 'Delete'});
    expect(screen.queryByRole('button', {name: '移除配置 default'})).toBeNull();
    const retired = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); fireEvent.mouseEnter(retired);
    expect(within(retired).queryByTestId('AccountCircleOutlinedIcon')).toBeNull();
    fireEvent.click(within(retired).getByRole('button', {name: '移除配置 retired'}));
    expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false);
    fireEvent.click(within(retired).getByRole('button', {name: '移除配置 retired'})); await act(flush);
    const forget = calls.find(call => call.path === `/p/retired/api/logout`)!;
    expect(forget.body).toEqual({scope: 'vnc'}); expect(forget.method).toBe('POST'); expect(forget.headers['X-CSRF-Token']).toBe('csrf');
    expect(forget.headers).not.toHaveProperty('X-Viewer-Token'); expect(forget.headers).not.toHaveProperty('X-Owner-Generation');
    const csrf = calls.find(call => call.path === '/api/status')!; expect(csrf.headers).not.toHaveProperty('X-Viewer-Token');
    expect(savedNames()).toEqual(['default']); expect(screen.queryByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/})).toBeNull();
    expect(screen.getByRole('menuitem', {name: '登录其他配置'})).toHaveFocus(); expect(view.navigateDocument).not.toHaveBeenCalled();
    expect(pathCalls('/api/viewer/release')).toHaveLength(0); expect(clients[0].disconnect).not.toHaveBeenCalled();
  });
  it.each(['Delete', 'Backspace'])('supports %s on a focused inactive row without navigating', async key => {
    saveHints({id: workId, name: 'retired'}); const view = await mount('/login');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const row = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); act(() => row.focus());
    expect(within(row).getByRole('button', {name: '移除配置 retired'})).toBeVisible();
    fireEvent.keyDown(row, {key}); expect(savedNames()).toEqual(['retired']); fireEvent.keyDown(row, {key}); await act(flush);
    expect(savedNames()).toEqual([]); expect(view.navigateDocument).not.toHaveBeenCalled(); expect(screen.getByRole('menuitem', {name: '登录其他配置'})).toHaveFocus();
  });
  it.each([401, 503, 'network'])('retains the inactive hint after uncertain/failed forget %s and permits retry', async failure => {
    saveHints({id: workId, name: 'retired'}); const original = globalThis.fetch; let reject = true;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === `/p/retired/api/logout` && reject
      ? failure === 'network' ? Promise.reject(new Error('network unavailable')) : Promise.resolve(Response.json({error: '移除失败'}, {status: failure as number})) : original(input, init)));
    const view = await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.keyDown(screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}), {key: 'Delete'}); fireEvent.keyDown(screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}), {key: 'Delete'}); await act(flush);
    await advance(300); expect(savedNames()).toEqual(['retired']); expect(screen.getByRole('alert')).toBeVisible(); expect(view.navigateDocument).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('img', {name: '配置不存在或已停用'})).toBeVisible(); reject = false;
    fireEvent.keyDown(screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}), {key: 'Delete'}); fireEvent.keyDown(screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}), {key: 'Delete'}); await act(flush); expect(savedNames()).toEqual([]);
  });
});

describe('named profile navigation and deliberate menu actions', () => {
  it('leaves the current row, name, and icon inert without navigation or network work', async () => {
    authenticated = true; const view = await mount('/profile/default');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const row = screen.getByRole('menuitem', {name: 'default 当前配置'}); const before = calls.length;
    fireEvent.click(row); fireEvent.click(within(row).getByText('default')); fireEvent.click(within(row).getByTestId('AccountCircleOutlinedIcon'));
    fireEvent.keyDown(row, {key: 'Enter'}); fireEvent.keyDown(row, {key: ' '}); fireEvent.keyUp(row, {key: ' '});
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete'}); await act(flush);
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(calls).toHaveLength(before); expect(clients).toHaveLength(1);
    expect(clients[0].disconnect).not.toHaveBeenCalled(); expect(screen.queryByRole('button', {name: '移除配置 default'})).toBeNull();
  });
  it('arms red for three seconds and requires a fresh second click after timeout', async () => {
    saveHints({id: workId, name: 'retired'}); await mount('/login');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const row = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); fireEvent.mouseEnter(row);
    const button = within(row).getByRole('button', {name: '移除配置 retired'});
    fireEvent.mouseOver(button); await advance(1000); expect(screen.getByRole('tooltip')).toHaveTextContent(/^移除此配置$/);
    fireEvent.click(button); expect(button).toHaveAttribute('aria-pressed', 'true'); expect(button).toHaveClass('MuiIconButton-colorError');
    expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false); await advance(3000);
    expect(button).toHaveAttribute('aria-pressed', 'false'); expect(button).not.toHaveClass('MuiIconButton-colorError');
    fireEvent.click(button); expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false);
    await advance(2999); fireEvent.click(button); await act(flush);
    expect(calls.filter(call => call.path === `/p/retired/api/logout`)).toHaveLength(1); expect(savedNames()).toEqual([]);
  });
  it('does not confirm a held Delete key and resets its arm when another row receives focus', async () => {
    saveHints({id: workId, name: 'retired'}, baseProfile); await mount('/login');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const row = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); act(() => row.focus());
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete', repeat: true}); await act(flush);
    expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false);
    act(() => screen.getByRole('menuitem', {name: 'default'}).focus()); act(() => row.focus());
    expect(within(row).getByRole('button', {name: '移除配置 retired'})).toHaveAttribute('aria-pressed', 'false');
    fireEvent.keyDown(row, {key: 'Delete'}); expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false);
    fireEvent.keyDown(row, {key: 'Delete'}); await act(flush); expect(savedNames()).toEqual(['default']);
  });
  it.each(['close', 'collapse', 'pagehide'])('resets pending forget confirmation on %s', async boundary => {
    authenticated = true; saveHints({id: workId, name: 'retired'}); await mount('/profile/default');
    const toggle = screen.getByRole('button', {name: '收起导航'});
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const row = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); fireEvent.mouseEnter(row); fireEvent.click(within(row).getByRole('button', {name: '移除配置 retired'}));
    if (boundary === 'close') fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'});
    else if (boundary === 'collapse') fireEvent.click(toggle);
    else act(() => window.dispatchEvent(new Event('pagehide')));
    await advance(300); expect(screen.queryByRole('menu')).toBeNull();
    if (boundary === 'collapse') {expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull(); fireEvent.click(toggle);}
    if (boundary === 'pagehide') {act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))); await act(flush);}
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    const next = screen.getByRole('menuitem', {name: /^retired(?: 配置不存在或已停用)?$/}); fireEvent.mouseEnter(next);
    const button = within(next).getByRole('button', {name: '移除配置 retired'}); expect(button).toHaveAttribute('aria-pressed', 'false');
    fireEvent.click(button); expect(calls.some(call => call.path.endsWith('/api/logout'))).toBe(false);
  });
  it.each(['disabled', 'missing'])('marks a %s saved profile red before selection while retaining it', async availability => {
    saveHints({id: workId, name: 'work'});
    if (availability === 'disabled') configuration.profiles.push({...baseProfile, id: workId, name: 'work', effective_enabled: false});
    await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible(); expect(savedNames()).toEqual(['work']);
    expect(calls.some(call => call.path.startsWith('/p/'))).toBe(false);
  });
  it('retains a renamed cached name as unavailable instead of resolving an administrative ID', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'});
    const view = await mount('/login'); configuration.profiles[1].name = 'renamed';
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush); fireEvent.click(screen.getByRole('menuitem', {name: 'work'})); await act(flush);
    expect(view.navigateDocument).not.toHaveBeenCalled(); await advance(300);
    expect(screen.getByRole('alert')).toHaveTextContent('浏览器配置不存在或已停用。');
    expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull(); expect(savedNames()).toEqual(['work']);
  });
  it('revalidates the name after document navigation without retaining any profile UUID handoff', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'});
    const view = await mount('/login'); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    fireEvent.click(screen.getByRole('menuitem', {name: 'work'})); await act(flush); expect(view.navigateDocument).toHaveBeenCalledWith('/profile/work');
    view.unmount(); calls = []; configuration.profiles = [{...baseProfile, name: 'work'}]; authenticated = false;
    await mount('/profile/work', true);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    expect(calls.some(call => call.path === '/p/work/api/status')).toBe(true);
    expect(calls.some(call => call.path.endsWith('/api/viewer/acquire'))).toBe(false);
    expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull(); expect(JSON.stringify(window.history.state)).not.toContain(workId);
  });
  it('keeps name-only history after Settings → Browser and a hard refresh', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; const view = await mount('/profile/work');
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush); fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(window.location.pathname).toBe('/profile/work'); expect(window.location.search).toBe(''); const state = window.history.state;
    expect(state).not.toHaveProperty('__webauthnBrowserProfile'); expect(JSON.stringify(state)).not.toContain(workId);
    view.unmount(); calls = []; await mount('/profile/work', true, state);
    expect(calls.some(call => call.path === '/p/work/api/status')).toBe(true);
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
  });
  it('keeps global Downloads independent when a saved profile is deleted or its name reused', async () => {
    saveHints({id: workId, name: 'work'}); authenticated = true;
    const view = await mount('/downloads?profile=work'); configuration.profiles = [{...baseProfile, name: 'work'}];
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    expect(screen.getByRole('heading', {name: '下载'})).toBeVisible();
    expect(screen.getByRole('link', {name: '下载'})).toHaveAttribute('href', '/downloads');
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(view.navigateDocument).toHaveBeenCalledExactlyOnceWith('/');
    expect(calls.some(call => call.path.startsWith('/p/'))).toBe(false);
  });
  it.each(['reused name', 'expired session'])('revalidates a direct named entry on BFCache without retaining %s authority', async failure => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount('/profile/work');
    act(() => window.dispatchEvent(new Event('pagehide'))); await act(flush);
    if (failure === 'reused name') configuration.profiles = [{...baseProfile, name: 'work'}]; authenticated = false;
    const before = calls.length; act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible();
    expect(calls.slice(before).some(call => call.path.startsWith('/p/default/'))).toBe(false);
    expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置认证失效'})).toBeVisible(); expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
  });
  it('ignores a late named-navigation lookup after pagehide', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); saveHints({id: workId, name: 'work'}); const view = await mount('/login');
    const original = globalThis.fetch; let finish!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/api/profiles/public' ? new Promise<Response>(resolve => {finish = resolve;}) : original(input, init)));
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush); fireEvent.click(screen.getByRole('menuitem', {name: 'work'})); await act(flush);
    act(() => window.dispatchEvent(new Event('pagehide'))); await act(async () => {finish(Response.json(configuration)); await flush();});
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull();
  });
});

describe('independent Settings lifetime during profile changes', () => {
  it('does not persist a false auth failure when duplicate authority-loss callbacks discover a disabled name', async () => {
    const lease = await import('./useProfileViewer'); const originalHook = lease.useProfileViewer;
    let loseAccess!: (reason?: 'unauthorized' | 'unavailable') => void;
    vi.spyOn(lease, 'useProfileViewer').mockImplementation((callback, enabled) => {loseAccess = callback; return originalHook(callback, enabled);});
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount('/profile/work');
    const previous = structuredClone(configuration); const original = globalThis.fetch; const finish: ((response: Response) => void)[] = [];
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/api/profiles/public'
      ? new Promise<Response>(resolve => {finish.push(resolve);}) : original(input, init)));
    act(() => {loseAccess('unauthorized'); loseAccess('unauthorized');}); await act(flush); expect(finish).toHaveLength(2);
    configuration.profiles[1].effective_enabled = false;
    await act(async () => {finish[1](Response.json(configuration)); await flush(); finish[0](Response.json(previous)); await flush();});
    const hint = JSON.parse(localStorage.getItem(savedKey)!).find((entry: {name: string}) => entry.name === 'work');
    expect(hint).not.toHaveProperty('status'); expect(hint).not.toHaveProperty('id');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible(); expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
  });

  it('canonicalizes an active default alias after external mode-off while preserving its still-valid viewer', async () => {
    authenticated = true; await mount('/profile/default'); configuration.multi_profile = false;
    await advance(10000);
    expect(window.location.pathname).toBe('/'); expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(pathCalls('/api/viewer/release')).toHaveLength(0);
    expect(clients[0].disconnect).not.toHaveBeenCalled(); expect(pathCalls('/api/viewer/activity')).toHaveLength(0);
  });

  it('does not overlap default-alias catalog refreshes or publish a response after pagehide', async () => {
    authenticated = true; await mount('/profile/default'); const original = globalThis.fetch;
    let finish!: (response: Response) => void; let probes = 0;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/api/profiles/public') {probes++; return new Promise<Response>(resolve => {finish = resolve;});}
      return original(input, init);
    }));
    await advance(30000); fireEvent(window, new Event('focus')); await act(flush); expect(probes).toBe(1);
    act(() => window.dispatchEvent(new Event('pagehide'))); await advance(20000);
    fireEvent(window, new Event('focus')); fireEvent(window, new Event('browser-profiles-changed')); await act(flush); expect(probes).toBe(1);
    await act(async () => {finish(Response.json({...configuration, multi_profile: false})); await flush();});
    expect(window.location.pathname).toBe('/profile/default'); expect(pathCalls('/api/viewer/activity')).toHaveLength(0);
  });
  it.each(['default', 'work'])('replaces the named %s Browser entry when viewer authority loss reveals mode-off from another document', async selectedName => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; const view = await mount(`/profile/${selectedName}`);
    configuration.multi_profile = false; configuration.profiles[1].effective_enabled = false;
    statusResponse = async () => Response.json({error: '会话已失效。'}, {status: 401}); await advance(1000);
    expect(view.replaceDocument).toHaveBeenCalledExactlyOnceWith('/'); expect(view.navigateDocument).not.toHaveBeenCalled();
  });

  it.each(['renamed', 'deleted', 'disabled'])('revokes a live named viewer and marks its saved name red when externally %s', async change => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount('/profile/work');
    if (change === 'renamed') configuration.profiles[1].name = 'renamed';
    else if (change === 'deleted') configuration.profiles.pop();
    else configuration.profiles[1].effective_enabled = false;
    statusResponse = async () => Response.json({error: '浏览器配置不存在或已停用。'}, {status: change === 'disabled' ? 401 : 404});
    await advance(1000);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull();
    expect(calls.some(call => call.path === '/p/work/api/viewer/release')).toBe(true);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible(); expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
    expect(savedNames()).toContain('work');
    if (change === 'disabled') expect(JSON.parse(localStorage.getItem(savedKey)!).find((entry: {name: string}) => entry.name === 'work')).not.toHaveProperty('status');
  });
  it.each(['设置', '下载'])('keeps global %s mounted when viewer polling discovers an external rename', async page => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount('/profile/work');
    fireEvent.click(screen.getByRole('link', {name: page})); await act(flush);
    const heading = screen.getByRole('heading', {name: page === '设置' ? '安全设置' : '下载'});
    configuration.profiles[1].name = 'renamed'; statusResponse = async () => Response.json({error: 'gone'}, {status: 404}); await advance(1000);
    expect(screen.getByRole('heading', {name: page === '设置' ? '安全设置' : '下载'})).toBe(heading);
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible();
  });

  it.each(['/profile/work'])('keeps Settings mounted after mode-off from %s and opens default next', async route => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true;
    const view = await mount(route); fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    fireEvent.click(screen.getByRole('link', {name: '浏览器设置'})); await act(flush);
    const heading = screen.getByRole('heading', {name: '浏览器设置'}); const switcher = screen.getByRole('switch', {name: '多配置模式'});
    fireEvent.click(switcher); await act(flush);
    expect(window.location.pathname).toBe('/settings'); expect(screen.getByRole('heading', {name: '浏览器设置'})).toBe(heading);
    expect(screen.getByRole('switch', {name: '多配置模式'})).toBe(switcher); expect(switcher).not.toBeChecked();
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull(); expect(screen.queryByRole('heading', {name: '解锁设置'})).toBeNull();
    expect(screen.getByRole('link', {name: '浏览器'})).toHaveAttribute('href', '/');
    expect(savedNames()).toContain('work'); expect(calls.filter(call => call.path.endsWith('/api/login'))).toHaveLength(0);
    expect(calls.some(call => call.path === '/api/status' && !call.headers['X-Viewer-Token'])).toBe(true);
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush); expect(view.navigateDocument).toHaveBeenCalledWith('/');
  });
  it.each(['/profile/work'])('keeps Settings mounted and marks failed profile authentication after its password changes from %s', async route => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount(route);
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush); fireEvent.click(screen.getByRole('link', {name: '浏览器设置'})); await act(flush);
    const heading = screen.getByRole('heading', {name: '浏览器设置'}); const row = screen.getByRole('article', {name: '浏览器配置 work'});
    fireEvent.click(within(row).getByRole('button', {name: 'work 配置设置'})); await act(flush);
    fireEvent.change(within(row).getByLabelText('访问密码'), {target: {value: 'replacement-test-only'}});
    let finishPoll: ((response: Response) => void) | undefined;
    if (route.startsWith('/profile/')) {
      statusResponse = () => new Promise(resolve => {finishPoll = resolve;}); await advance(1000);
      expect(finishPoll).toBeDefined();
    }
    fireEvent.click(within(row).getByRole('button', {name: '保存'}));
    await act(async () => {finishPoll?.(Response.json({error: '会话已失效。'}, {status: 401})); await flush();});
    expect(screen.getByRole('heading', {name: '浏览器设置'})).toBe(heading); expect(window.location.pathname).toBe('/settings');
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull(); expect(screen.queryByRole('heading', {name: '解锁设置'})).toBeNull();
    expect(calls.filter(call => call.path.endsWith('/api/login'))).toHaveLength(0); expect(savedNames()).toContain('work');
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'work 配置认证失效'})).toBeVisible(); expect(screen.queryByRole('img', {name: '当前配置'})).toBeNull();
    expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull(); expect(localStorage.getItem(savedKey)).not.toContain('replacement-test-only');
  }, 30000);
  it('restores global Settings from BFCache after the selected profile was deleted', async () => {
    configuration.profiles.push({...baseProfile, id: workId, name: 'work'}); authenticated = true; await mount('/profile/work');
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    act(() => window.dispatchEvent(new Event('pagehide'))); await act(flush);
    configuration.profiles = [configuration.profiles[0]]; const original = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input).startsWith(`/p/work/`) ? Promise.resolve(Response.json({error: 'missing'}, {status: 404})) : original(input, init)));
    const before = calls.length; act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))); await act(flush);
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible(); expect(screen.queryByText('暂时无法连接服务')).toBeNull();
    expect(calls.slice(before).some(call => call.path === '/api/status')).toBe(true); expect(calls.slice(before).some(call => call.path.endsWith('/api/login'))).toBe(false);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush); expect(screen.getByRole('menuitem', {name: 'work 配置不存在或已停用'})).toBeVisible();
    expect(screen.getByRole('button', {name: '浏览器', hidden: true})).toHaveAttribute('aria-disabled', 'true'); expect(screen.getByRole('button', {name: '浏览器', hidden: true})).not.toHaveAttribute('href');
  });
  it('ignores a delayed failed config-status check after a newer successful login', async () => {
    saveHints(baseProfile); await mount('/profile/default');
    const original = globalThis.fetch; let finish!: (response: Response) => void; let delay = true;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/p/default/api/status' && delay) {delay = false; return new Promise<Response>(resolve => {finish = resolve;});}
      return original(input, init);
    }));
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    fireEvent.change(screen.getByLabelText(/^密码/), {target: {value: 'new-session-test-only'}});
    fireEvent.submit(screen.getByRole('button', {name: '解锁'}).closest('form')!); await act(flush);
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
    await act(async () => {finish(Response.json({vnc_authenticated: false})); await flush();});
    expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toBeVisible(); expect(pathCalls('/api/viewer/release')).toHaveLength(0);
  });
  it('ignores a config-status failure from before pagehide when global Settings resumes', async () => {
    authenticated = true; await mount('/profile/default'); fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    const original = globalThis.fetch; let finish!: (response: Response) => void; let delay = true;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/p/default/api/status' && delay) {delay = false; return new Promise<Response>(resolve => {finish = resolve;});}
      return original(input, init);
    }));
    fireEvent(window, new Event('browser-profiles-changed')); await act(flush);
    act(() => window.dispatchEvent(new Event('pagehide'))); await act(flush);
    act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))); await act(flush);
    await act(async () => {finish(Response.json({vnc_authenticated: false})); await flush();});
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible(); fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toBeVisible();
  });
  it('still locks Settings when its own administrative authorization expires', async () => {
    authenticated = true; await mount('/profile/default'); fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    fireEvent.click(screen.getByRole('link', {name: '浏览器设置'})); await act(flush); const original = globalThis.fetch;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input) === '/api/profiles/config' ? Promise.resolve(Response.json({error: '设置会话已失效。'}, {status: 401})) : original(input, init)));
    fireEvent.click(screen.getByRole('switch', {name: '多配置模式'})); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁设置'})).toBeVisible(); expect(screen.queryByRole('heading', {name: '解锁浏览器'})).toBeNull();
  });
});

describe('first-viewer engine ownership', () => {
  it('allows a standby to view without engine streams, browser controls, clipboard, restart, or resize', async () => {
    authenticated = true; viewer.owner = false; await mount('/profile/default');
    expect(clients).toHaveLength(1); expect(clients[0].viewOnly).toBe(true); expect(clients[0].resizeSession).toBe(false);
    expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull();
    expect(pathCalls('/api/browser/reconnect')).toHaveLength(0); expect(pathCalls('/api/requests/events')).toHaveLength(0);
    act(() => clients[0].emit('connect')); await act(flush);
    expect(pathCalls('/api/viewer/ticket').map(call => call.body.kind)).toEqual(['vnc']);
    setViewport(960, 540); fireEvent(window, new Event('resize')); await advance(2000);
    expect(clients[0].resizeSession).toBe(false); expect(pathCalls('/api/browser/reconnect')).toHaveLength(0);
  });
  it('promotes and demotes the same VNC socket while mounting engine capabilities only for the owner', async () => {
    setViewport(1920, 1080);
    authenticated = true; viewer.owner = false; await mount('/profile/default'); const client = clients[0];
    setViewport(960, 540); fireEvent(window, new Event('resize'));
    viewer = {...viewer, owner: true, generation: 2}; await advance(1000);
    expect(clients).toHaveLength(1); expect(client.viewOnly).toBe(false); expect(client.resizeSession).toBe(false);
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBeVisible(); expect(pathCalls('/api/requests/events')).toHaveLength(1);
    const intent = pathCalls('/api/browser/reconnect').find(call => call.method === 'POST')!;
    expect(intent.body.viewport).toEqual({width: 960, height: 540}); expect(intent.headers['X-Owner-Generation']).toBe('2');
    viewer = {...viewer, owner: false, expired: true, generation: 3, idle_remaining_ms: 0}; await advance(1000);
    expect(client.viewOnly).toBe(true); expect(clients).toHaveLength(1); expect(client.disconnect).not.toHaveBeenCalled();
    expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull(); expect(pathCalls('/api/requests/events')[0].signal?.aborted).toBe(true);
    setViewport(1280, 720); fireEvent(window, new Event('resize')); await advance(1000);
    expect(browserActions()).toHaveLength(1); expect(client.resizeSession).toBe(false);
  });
  it('keeps the same viewer and VNC connection through Settings and Downloads navigation', async () => {
    authenticated = true; await mount('/profile/default'); const client = clients[0];
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    expect(screen.getByRole('heading', {name: '安全设置'})).toBeVisible(); expect(screen.queryByRole('region', {name: '浏览器远程桌面'})).toBeNull();
    fireEvent.click(screen.getByRole('link', {name: '下载'})); await act(flush); expect(screen.getByRole('heading', {name: '下载'})).toBeVisible(); expect(window.location.search).toBe('');
    fireEvent.click(screen.getByRole('link', {name: '设置'})); await act(flush);
    fireEvent.click(screen.getByRole('link', {name: '浏览器'})); await act(flush);
    expect(screen.getByRole('region', {name: '浏览器远程桌面'})).toBeVisible(); expect(clients).toHaveLength(1); expect(client.disconnect).not.toHaveBeenCalled();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(pathCalls('/api/viewer/release')).toHaveLength(0);
  });
  it.each([
    [{width: 1280, height: 720}, {width: 1920, height: 1080}],
    [{width: 1920, height: 1080}, {width: 960, height: 540}],
  ])('uses the current viewport %j → %j on manual restart and replaces VNC while retaining the viewer', async (before, after) => {
    setViewport(before.width, before.height);
    authenticated = true; await mount('/profile/default'); const client = clients[0];
    const initial = pathCalls('/api/browser/reconnect').find(call => call.method === 'POST')!;
    expect(initial.body.action).toBe('ensure'); expect(initial.body.viewport).toEqual(before);
    expect(initial.headers['X-Viewer-Token']).toBe(token); expect(initial.headers['X-Owner-Generation']).toBe('1');
    act(() => client.emit('connect')); await act(flush);
    setViewport(after.width, after.height); fireEvent(window, new Event('resize')); await advance(2000);
    expect(browserActions()).toHaveLength(1); expect(client.resizeSession).toBe(false);
    fireEvent.click(screen.getByRole('button', {name: '重新连接'})); await act(flush); await advance(0);
    const manual = pathCalls('/api/browser/reconnect').filter(call => call.method === 'POST').at(-1)!;
    expect(manual.body.action).toBe('restart'); expect(manual.body.viewport).toEqual(after);
    expect(manual.body.request_id).not.toBe(initial.body.request_id);
    expect(manual.headers['X-Viewer-Token']).toBe(token); expect(manual.headers['X-Owner-Generation']).toBe('1');
    expect(client.disconnect).toHaveBeenCalledTimes(1); expect(clients).toHaveLength(2);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1); expect(pathCalls('/api/viewer/release')).toHaveLength(0);
    expect(pathCalls('/api/viewer/ticket').filter(call => call.body.kind === 'vnc')).toHaveLength(2);
    act(() => client.emit('disconnect')); await act(flush);
    expect(pathCalls('/api/viewer/release')).toHaveLength(0);
  });
  it('samples each repeated manual restart independently and never restarts merely for a window resize', async () => {
    setViewport(1440, 900); authenticated = true; await mount('/profile/default');
    for (const viewport of [{width: 900, height: 600}, {width: 1680, height: 1050}, {width: 1024, height: 768}]) {
      const previousCount = browserActions().length;
      setViewport(viewport.width, viewport.height); fireEvent(window, new Event('resize')); await advance(1000);
      expect(browserActions()).toHaveLength(previousCount);
      fireEvent.click(screen.getByRole('button', {name: '重新连接'})); await act(flush);
      expect(browserActions()).toHaveLength(previousCount + 1);
      expect(browserActions().at(-1)!.body).toMatchObject({action: 'restart', viewport});
    }
    expect(browserActions().map(call => call.body.action)).toEqual(['ensure', 'restart', 'restart', 'restart']);
    expect(new Set(browserActions().map(call => call.body.request_id)).size).toBe(4);
    expect(clients.every(client => !client.resizeSession)).toBe(true);
  });
  it.each([
    [{width: 1280, height: 720}, {width: 1920, height: 1080}],
    [{width: 1920, height: 1080}, {width: 960, height: 540}],
  ])('samples a new ensure after a page remount at %j → %j without reusing the prior operation', async (before, after) => {
    setViewport(before.width, before.height); authenticated = true;
    const first = await mount('/profile/default', true);
    expect(browserActions()).toHaveLength(1); expect(browserActions()[0].body.viewport).toEqual(before);
    first.unmount(); await act(flush);
    setViewport(after.width, after.height);
    viewer = {...viewer, viewer_id: 'refreshed-viewer', viewer_token: 'b'.repeat(64), generation: 2};
    await mount('/profile/default', true);
    expect(browserActions()).toHaveLength(2);
    expect(browserActions()[1].body).toMatchObject({action: 'ensure', viewport: after});
    expect(browserActions()[1].body.request_id).not.toBe(browserActions()[0].body.request_id);
    expect(browserActions()[1].headers['X-Viewer-Token']).toBe(viewer.viewer_token);
    expect(browserActions()[1].headers['X-Owner-Generation']).toBe('2');
    expect(browserActions().every(call => call.body.action === 'ensure')).toBe(true);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(2);
    expect(clients).toHaveLength(2); expect(clients.every(client => !client.resizeSession)).toBe(true);
  });
  it('samples the restored page viewport after releasing the old viewer on pagehide', async () => {
    setViewport(1920, 1080); authenticated = true; await mount('/profile/default');
    fireEvent(window, new PageTransitionEvent('pagehide')); await act(flush);
    expect(pathCalls('/api/viewer/release')).toHaveLength(1);
    setViewport(960, 540);
    viewer = {...viewer, viewer_id: 'restored-viewer', viewer_token: 'b'.repeat(64), generation: 2};
    fireEvent(window, new PageTransitionEvent('pageshow', {persisted: true})); await act(flush);
    expect(browserActions()).toHaveLength(2);
    expect(browserActions()[1].body).toMatchObject({action: 'ensure', viewport: {width: 960, height: 540}});
    expect(browserActions()[1].body.request_id).not.toBe(browserActions()[0].body.request_id);
    expect(browserActions()[1].headers['X-Viewer-Token']).toBe(viewer.viewer_token);
  });
  it('reads dimensions after metadata resolves rather than capturing them at entry', async () => {
    let finish!: (response: Response) => void;
    browserMetadataResponse = () => new Promise(resolve => {finish = resolve;});
    setViewport(1920, 1080); authenticated = true; await mount('/profile/default');
    expect(browserActions()).toHaveLength(0);
    setViewport(960, 540); fireEvent(window, new Event('resize'));
    await act(async () => {finish(browserMetadata()); await flush();});
    expect(browserActions()).toHaveLength(1);
    expect(browserActions()[0].body).toMatchObject({action: 'ensure', viewport: {width: 960, height: 540}});
  });
  it('resamples dimensions and operation identity after a definitely unadmitted ensure', async () => {
    let attempts = 0;
    browserActionResponse = async init => {
      if (attempts++ === 0) return Response.json({ok: false, code: 'browser_operation_busy', message: 'Busy'}, {status: 409});
      return Response.json({ok: true, ...JSON.parse(String(init?.body)), restarted: false, engine_ready: true, window_count: 1});
    };
    setViewport(1920, 1080); authenticated = true; await mount('/profile/default');
    expect(browserActions()).toHaveLength(1);
    setViewport(960, 540); fireEvent(window, new Event('resize')); await advance(1000);
    expect(browserActions()).toHaveLength(2);
    expect(browserActions().map(call => call.body.viewport)).toEqual([{width: 1920, height: 1080}, {width: 960, height: 540}]);
    expect(browserActions()[1].body.request_id).not.toBe(browserActions()[0].body.request_id);
    expect(browserActions().every(call => call.body.action === 'ensure')).toBe(true);
  });
  it('cancels pending sizing admission when an owner becomes standby and ignores late metadata', async () => {
    let finish!: (response: Response) => void;
    browserMetadataResponse = () => new Promise(resolve => {finish = resolve;});
    setViewport(1920, 1080); authenticated = true; await mount('/profile/default');
    const metadata = pathCalls('/api/browser/reconnect')[0];
    viewer = {...viewer, owner: false, generation: 2};
    setViewport(960, 540); fireEvent(window, new Event('resize')); await advance(1000);
    expect(metadata.signal?.aborted).toBe(true);
    await act(async () => {finish(browserMetadata()); await flush();});
    expect(browserActions()).toHaveLength(0); expect(clients[0].viewOnly).toBe(true); expect(clients[0].resizeSession).toBe(false);
    expect(screen.queryByRole('button', {name: '重新连接'})).toBeNull();
  });
  it.each(['deleted', 'disabled', 'revoked'] as const)('hides takeover immediately when a disconnected profile is %s', async reason => {
    authenticated = true; await mount('/profile/default');
    if (reason === 'deleted') configuration.profiles = [];
    else if (reason === 'disabled') configuration.profiles[0].effective_enabled = false;
    else authenticated = false;
    act(() => clients[0].emit('disconnect'));
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    await act(flush); await advance(2000);
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('withholds takeover until disconnected profile availability and authentication are revalidated', async () => {
    authenticated = true; await mount('/profile/default');
    const original = vi.mocked(fetch).getMockImplementation()!;
    let finish!: (response: Response) => void;
    vi.mocked(fetch).mockImplementation((input, init) => String(input) === '/api/profiles/public' ? new Promise(resolve => {finish = resolve;}) : original(input, init));
    act(() => clients[0].emit('disconnect')); await act(flush);
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    await act(async () => {finish(Response.json(configuration)); await flush();});
    expect(screen.getByRole('button', {name: '接管控制'})).toBeVisible();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('rechecks failed availability without reacquiring and ignores a late check after unmount', async () => {
    authenticated = true; const view = await mount('/profile/default');
    const original = vi.mocked(fetch).getMockImplementation()!;
    let finish!: (response: Response) => void;
    let checks = 0;
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (String(input) !== '/api/profiles/public') return original(input, init);
      checks += 1;
      if (checks === 1) return Promise.reject(new TypeError('offline'));
      return new Promise(resolve => {finish = resolve;});
    });
    act(() => clients[0].emit('disconnect')); await act(flush);
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    await advance(1000); expect(checks).toBe(2);
    const before = pathCalls('/api/status').length;
    view.unmount();
    await act(async () => {finish(Response.json(configuration)); await flush();});
    expect(pathCalls('/api/status')).toHaveLength(before);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('restores takeover after a transient disconnected-profile availability failure without automatic acquisition', async () => {
    authenticated = true; await mount('/profile/default');
    const original = vi.mocked(fetch).getMockImplementation()!;
    let failed = false;
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (String(input) === '/api/profiles/public' && !failed) {failed = true; return Promise.reject(new TypeError('offline'));}
      return original(input, init);
    });
    act(() => clients[0].emit('disconnect')); await act(flush);
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    await advance(1000);
    expect(screen.getByRole('button', {name: '接管控制'})).toBeVisible();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('does not offer takeover during profile revocation discovered by viewer polling', async () => {
    authenticated = true; await mount('/profile/default');
    configuration.profiles = [];
    statusResponse = async () => Response.json({error: '配置不可用。'}, {status: 403});
    await advance(1000);
    expect(screen.queryByRole('button', {name: '接管控制'})).toBeNull();
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
  });
  it('requires explicit acquisition after a real disconnect and creates a new RFB for the new viewer identity', async () => {
    authenticated = true; await mount('/profile/default'); const client = clients[0];
    act(() => client.emit('disconnect')); await act(flush);
    expect(pathCalls('/api/viewer/release')).toHaveLength(1); await advance(3000);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    viewer = {...viewer, viewer_id: 'replacement', viewer_token: 'b'.repeat(64), generation: 2, owner: false};
    fireEvent.click(screen.getByRole('button', {name: '接管控制'})); await act(flush); await advance(0);
    expect(clients).toHaveLength(2); expect(clients[1].viewOnly).toBe(true); expect(pathCalls('/api/viewer/acquire')).toHaveLength(2);
    expect(pathCalls('/api/viewer/acquire')[1].headers).not.toHaveProperty('X-Viewer-Token');
  });
  it('never turns polling, synthetic events, or passive time into activity and permits explicit reacquire without a returned token', async () => {
    authenticated = true; await mount('/profile/default');
    fireEvent.pointerMove(window); fireEvent.keyDown(window, {key: 'a'}); await advance(3000);
    expect(pathCalls('/api/viewer/activity')).toHaveLength(0);
    viewer = {...viewer, owner: false, expired: true, idle_remaining_ms: 0}; await advance(1000); await advance(10000);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', {name: '接管控制'})); await act(flush);
    expect(pathCalls('/api/viewer/acquire')).toHaveLength(2); expect(pathCalls('/api/viewer/acquire')[1].headers['X-Viewer-Token']).toBe(token);
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBeVisible();
  });
  it('throttles genuine outer-page activity below a one-second idle timeout', async () => {
    authenticated = true; viewer.idle_timeout_seconds = 1; viewer.idle_remaining_ms = 1000;
    const events = vi.spyOn(window, 'addEventListener'); await mount('/profile/default');
    const activity = events.mock.calls.find(call => call[0] === 'pointermove')![1] as (event: Event) => void;
    for (let i = 0; i < 4; i++) {act(() => activity({type: 'pointermove', isTrusted: true} as Event)); await act(flush); await advance(250);}
    expect(pathCalls('/api/viewer/activity')).toHaveLength(4);
  });
  it('releases exactly the returned late capability if acquisition finishes after unmount', async () => {
    authenticated = true; let finish!: (response: Response) => void; acquireResponse = () => new Promise(resolve => {finish = resolve;});
    const {unmount} = await mount('/profile/default'); unmount();
    await act(async () => {finish(Response.json(viewer)); await flush();});
    expect(pathCalls('/api/viewer/release')).toHaveLength(1); expect(pathCalls('/api/viewer/release')[0].headers['X-Viewer-Token']).toBe(token); expect(clients).toHaveLength(0);
  });
  it('revokes the live viewer and disables the fixed-name submit when that profile is removed or disabled', async () => {
    authenticated = true; await mount('/profile/default');
    configuration.profiles = [];
    act(() => window.dispatchEvent(new Event('browser-profiles-changed'))); await act(flush);
    expect(screen.getByRole('button', {name: '解锁'})).toBeDisabled();
    expect(pathCalls('/api/viewer/release')).toHaveLength(1); expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull();
  });
  it('releases live control but retains the saved entry without a failure marker on intentional logout', async () => {
    authenticated = true; await mount('/profile/default');
    let finish!: (response: Response) => void; statusResponse = () => new Promise(resolve => {finish = resolve;}); await advance(1000);
    fireEvent.click(screen.getByRole('button', {name: '锁定会话'})); await act(flush);
    expect(screen.getByRole('heading', {name: '解锁浏览器'})).toBeVisible(); expect(pathCalls('/api/viewer/release')).toHaveLength(1);
    expect(JSON.parse(localStorage.getItem('webauthn-browser.saved-profiles')!)).toEqual([expect.objectContaining({name: 'default'})]);
    fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);
    expect(screen.getByRole('menuitem', {name: 'default'})).not.toHaveAttribute('aria-current');
    expect(screen.queryByRole('img', {name: '配置认证失效'})).toBeNull();
    await act(async () => {finish(Response.json({...viewer, owner: true})); await flush();});
    expect(screen.queryByRole('region', {name: '浏览器控制栏'})).toBeNull();
  });
});
