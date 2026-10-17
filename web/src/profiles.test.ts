import { beforeEach, describe, expect, it, vi } from 'vitest';
import { forgetProfile, rememberProfile, savedProfiles, validProfileName, prepareProfileNavigation, clearProfileNavigation, retainProfileSelection, prepareProfileChooser, readProfileChooser, setSavedProfileStatus } from './profiles';

const storageKey = 'webauthn-browser.saved-profiles';
const id = '59df70a6-bdd5-4b04-af35-76332cd72419';
beforeEach(() => localStorage.clear());
describe('profile names and browser-local menu metadata', () => {
  it.each(['default', '.github', '_private', '-work', 'Work.v2', 'a'.repeat(100)])('accepts %s', name => expect(validProfileName(name)).toBe(true));
  it.each(['', '.', '..', 'a'.repeat(101), 'a/b', '中文', 'white space', 'demo.git', 'DEMO.WIKI', 'a\n'])('rejects %s', name => expect(validProfileName(name)).toBe(false));
  it('stores only canonical name and access time, never supplied credentials or viewer capabilities', () => {
    rememberProfile({id, name: 'work', password: 'not-persisted', viewer_token: 'not-persisted'} as any);
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual([{name: 'work', lastUsedAt: expect.any(Number)}]);
    expect(localStorage.getItem(storageKey)).not.toContain('not-persisted');
  });
  it('retains old remembered metadata until explicit removal without renewing its age', () => {
    const now = Date.now();
    const entries = [{name: 'work', lastUsedAt: now - 365 * 86400000}, {name: 'default', lastUsedAt: now - 1000}];
    localStorage.setItem(storageKey, JSON.stringify(entries));
    expect(savedProfiles()).toEqual(entries);
    expect(savedProfiles()).toEqual(entries);
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual(entries);
    forgetProfile('WORK');
    expect(savedProfiles()).toEqual([entries[1]]);
  });
  it('remembers passwordless default and retains other profiles across repeated visits', () => {
    rememberProfile({name: 'work'});
    for (let visit = 0; visit < 3; visit++) rememberProfile({name: 'default'});
    expect(savedProfiles().map(entry => entry.name)).toEqual(['default', 'work']);
    expect(localStorage.getItem(storageKey)).not.toContain('password');
  });
  it('does not extend inactivity time merely by displaying the saved menu', () => {
    const lastUsedAt = Date.now() - 1000;
    localStorage.setItem(storageKey, JSON.stringify([{id, name: 'work', lastUsedAt}]));
    expect(savedProfiles()[0].lastUsedAt).toBe(lastUsedAt); expect(savedProfiles()[0].lastUsedAt).toBe(lastUsedAt);
  });
  it('drops invalid and duplicate metadata without interpreting it as authorization', () => {
    localStorage.setItem(storageKey, JSON.stringify([{name: '../other', lastUsedAt: Date.now()}, {id, name: 'work', lastUsedAt: Date.now()}, {name: 'WORK', lastUsedAt: Date.now()}]));
    expect(savedProfiles()).toHaveLength(1); expect(savedProfiles()[0].name).toBe('work');
  });
  it('drops legacy error flags from saved menu hints without treating them as authentication or availability', () => {
    const lastUsedAt = Date.now();
    localStorage.setItem(storageKey, JSON.stringify([{id, name: 'work', lastUsedAt, failed: true, error: 'old failure', status: 'invalid'}]));
    expect(savedProfiles()).toEqual([{name: 'work', lastUsedAt}]);
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual([{name: 'work', lastUsedAt}]);
  });
  it.each([{auth: false}, {error: true}, {status: 'auth_invalid'}])('normalizes legacy access metadata %j to a non-authoritative enum hint', flags => {
    const lastUsedAt = Date.now() - 1000;
    localStorage.setItem(storageKey, JSON.stringify([{id, name: 'work', lastUsedAt, ...flags}]));
    expect(savedProfiles()).toEqual([{name: 'work', lastUsedAt, status: 'auth_invalid'}]);
    expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual([{name: 'work', lastUsedAt, status: 'auth_invalid'}]);
    setSavedProfileStatus('work', 'unknown');
    expect(savedProfiles()).toEqual([{name: 'work', lastUsedAt}]);
    setSavedProfileStatus('work', 'auth_invalid'); rememberProfile({name: 'work'});
    expect(savedProfiles()[0]).not.toHaveProperty('status');
  });
  it('tolerates unavailable or read-only storage', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {throw new DOMException('Blocked', 'SecurityError');});
    expect(savedProfiles()).toEqual([]); expect(() => rememberProfile({name: 'work'})).not.toThrow();
  });
});

describe('name-scoped profile API and transport binding', () => {
  beforeEach(() => vi.resetModules());
  it('scopes browser calls and viewer headers while leaving global configuration APIs untouched', async () => {
    const profiles = await import('./profiles'); const api = await import('./api');
    profiles.bindBrowserProfile('WoRk'); profiles.setProfileViewer({viewer_id: 'viewer', viewer_token: 'memory-only', generation: 7, owner: true, idle_timeout_seconds: 180});
    api.setCsrfToken('csrf');
    const fetcher = vi.fn(async () => Response.json({ok: true})); vi.stubGlobal('fetch', fetcher);
    await api.request('/api/browser/mode'); await api.request('/api/keys'); await api.request('/api/profiles/config', 'PUT', {multi_profile: false});
    await api.request('/api/logout', 'POST', {scope: 'settings'}); await api.request('/api/downloads');
    const calls = fetcher.mock.calls as unknown as [string, RequestInit][];
    expect(calls.map(call => call[0])).toEqual([`/p/work/api/browser/mode`, '/api/keys', '/api/profiles/config', '/api/logout', '/api/downloads']);
    expect(calls[0][1].headers).toMatchObject({'X-Viewer-Token': 'memory-only', 'X-Owner-Generation': '7', 'X-CSRF-Token': 'csrf'});
    expect(calls[1][1].headers).not.toHaveProperty('X-Viewer-Token'); expect(calls[4][1].headers).not.toHaveProperty('X-Viewer-Token');
    expect(() => profiles.bindBrowserProfile('default')).toThrow('请重新打开浏览器配置。');
  });
  it('obtains a one-use ticket for WebSocket admission without exposing persistent cookies or viewer tokens in its URL', async () => {
    const profiles = await import('./profiles'); const api = await import('./api');
    profiles.bindBrowserProfile('WoRk'); profiles.setProfileViewer({viewer_id: 'viewer', viewer_token: 'memory-only', generation: 7, owner: false, idle_timeout_seconds: 180});
    const fetcher = vi.fn(async () => Response.json({ticket: 'one-use-ticket', expires_in_ms: 10000})); vi.stubGlobal('fetch', fetcher);
    const url = await api.browserTransportUrl('/ws', 'vnc');
    expect(url.pathname).toBe(`/p/work/ws`); expect(url.searchParams.get('ticket')).toBe('one-use-ticket'); expect(url.href).not.toContain('memory-only');
    expect(JSON.parse((fetcher.mock.calls as unknown as [string, RequestInit][])[0][1].body as string)).toEqual({kind: 'vnc'});
    expect(localStorage.length).toBe(0);
  });
});

describe('profile-specific browser-control preferences', () => {
  it('isolates mode and address between canonical names while preserving default legacy preferences', async () => {
    vi.resetModules();
    const first = await import('./profiles'); const preferences = await import('./browserControlPreferences');
    localStorage.setItem('webauthn-browser.mode', 'native'); localStorage.setItem('webauthn-browser.helper-address', 'ws://localhost:12000');
    first.bindBrowserProfile('WORK');
    expect(preferences.readBrowserControlPreferences('ws://localhost:10233')).toEqual({mode: 'software', address: 'ws://localhost:10233'});
    preferences.saveBrowserMode('native'); preferences.saveHelperAddress('ws://localhost:14000');
    vi.resetModules(); const second = await import('./profiles'); const secondPreferences = await import('./browserControlPreferences');
    second.bindBrowserProfile('personal');
    expect(secondPreferences.readBrowserControlPreferences('ws://localhost:10233')).toEqual({mode: 'software', address: 'ws://localhost:10233'});
    vi.resetModules(); const defaults = await import('./profiles'); const defaultPreferences = await import('./browserControlPreferences');
    defaults.bindBrowserProfile('default');
    expect(defaultPreferences.readBrowserControlPreferences('unused')).toEqual({mode: 'native', address: 'ws://localhost:12000'});
    expect(Object.keys(localStorage).every(key => key.startsWith('webauthn-browser.mode') || key.startsWith('webauthn-browser.helper-address'))).toBe(true);
  });
});


describe('name-only navigation and legacy metadata removal', () => {
  beforeEach(() => {sessionStorage.clear(); window.history.replaceState(null, '', '/');});
  it('uses a named URL without persisting identity, credentials or a navigation handoff', () => {
    const path = prepareProfileNavigation({name: 'Work.v2'});
    expect(path).toBe('/profile/work.v2'); expect(sessionStorage.length).toBe(0);
    window.history.replaceState({unrelated: true}, '', path);
    retainProfileSelection({name: 'Work.v2'});
    expect(window.history.state).toEqual({unrelated: true});
  });
  it.each(['/', '/downloads', '/profile/work'])('physically removes obsolete UUID state and query on %s', path => {
    sessionStorage.setItem('webauthn-browser.profile-navigation', JSON.stringify({id, name: 'work'}));
    window.history.replaceState({unrelated: true, __webauthnBrowserProfile: {id, name: 'work'}}, '', `${path}?profile=${id}`);
    clearProfileNavigation();
    expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull();
    expect(window.history.state).toEqual({unrelated: true}); expect(window.location.href).not.toContain(id);
  });
  it('keeps single-profile navigation at the root and removes legacy history on named revisits', () => {
    expect(prepareProfileNavigation({name: 'default'}, false)).toBe('/');
    window.history.replaceState({__webauthnBrowserProfile: {id, name: 'work'}}, '', '/profile/work');
    retainProfileSelection({name: 'work'});
    expect(window.history.state).toEqual({}); expect(window.location.pathname).toBe('/profile/work');
  });
  it('uses a bounded chooser intent at plain root and retains it for Strict Mode', () => {
    prepareProfileNavigation({name: 'work'}); prepareProfileChooser();
    expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull();
    expect(readProfileChooser()).toBe(true); expect(readProfileChooser()).toBe(true);
    expect(window.location.pathname + window.location.search).toBe('/');
  });
  it('rejects expired or future chooser intents', () => {
    for (const age of [-1000, 60001]) {
      window.history.replaceState(null, '', '/'); sessionStorage.setItem('webauthn-browser.profile-chooser', String(Date.now() - age));
      expect(readProfileChooser()).toBe(false); expect(readProfileChooser()).toBe(false);
    }
  });
  it('keeps named navigation usable without storage and fails closed for the optional chooser intent', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {throw new DOMException('Blocked', 'SecurityError');});
    expect(prepareProfileNavigation({name: 'work'})).toBe('/profile/work');
    expect(() => prepareProfileChooser()).toThrow('无法安全打开登录页面');
  });
  it('migrates known UUID preferences and removes orphaned UUID keys without changing default data', () => {
    localStorage.setItem(storageKey, JSON.stringify([{id, name: 'WoRk', lastUsedAt: 1, auth: false}]));
    localStorage.setItem(`webauthn-browser.mode.${id}`, 'native');
    localStorage.setItem('webauthn-browser.helper-address.e29b5137-8f9b-48b6-b714-54f8901dfd12', 'ws://old');
    localStorage.setItem('webauthn-browser.mode', 'native');
    expect(savedProfiles()).toEqual([{name: 'work', lastUsedAt: 1, status: 'auth_invalid'}]);
    expect(localStorage.getItem('webauthn-browser.mode.name.work')).toBe('native');
    expect(localStorage.getItem('webauthn-browser.mode')).toBe('native');
    expect(JSON.stringify({...localStorage})).not.toContain(id);
    expect(Object.keys(localStorage).some(key => key.includes('e29b5137'))).toBe(false);
  });
  it('preserves name-keyed preferences for valid UUID-shaped public names', async () => {
    vi.resetModules(); const profiles = await import('./profiles'); const preferences = await import('./browserControlPreferences');
    profiles.bindBrowserProfile(id); preferences.saveBrowserMode('native'); profiles.rememberProfile({name: id}); profiles.savedProfiles();
    expect(preferences.readBrowserControlPreferences('unused').mode).toBe('native');
    expect(localStorage.getItem(`webauthn-browser.mode.name.${id}`)).toBe('native');
  });
});
