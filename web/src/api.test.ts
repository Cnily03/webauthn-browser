import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, getCsrfToken, refreshStatus, request, requestBlob, setCsrfToken } from './api';

afterEach(() => { vi.unstubAllGlobals(); setCsrfToken(''); });
describe('same-origin API boundary', () => {
  it('serializes once with CSRF header, never a token in the URL', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"ok":true}'));
    vi.stubGlobal('fetch', fetcher);
    setCsrfToken('token');
    await request('/api/requests/id/decision', 'POST', { action: 'verify_password', password: '秘密' });
    expect(fetcher).toHaveBeenCalledOnce();
    const [path, init] = fetcher.mock.calls[0];
    expect(path).toBe('/api/requests/id/decision');
    expect(init).toMatchObject({ credentials: 'same-origin', cache: 'no-store', headers: { 'X-CSRF-Token': 'token', 'Content-Type': 'application/json' } });
    expect(JSON.parse(init.body)).toEqual({ action: 'verify_password', password: '秘密' });
  });
  it('does not retry uncertain mutations', async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError('Network interrupted'));
    vi.stubGlobal('fetch', fetcher);
    await expect(request('/api/restore/confirm', 'POST', {})).rejects.toThrow('Network interrupted');
    expect(fetcher).toHaveBeenCalledOnce();
  });
  it('reports plain text and structured status errors without reissuing requests', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('Locked', { status: 401 })).mockResolvedValueOnce(new Response('{"error":"Preview expired"}', { status: 409 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(request('/api/keys')).rejects.toMatchObject({ status: 401, message: 'Locked' });
    await expect(request('/api/restore/confirm', 'POST')).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('retains an explicit failure code without retrying the mutation itself', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(Response.json({ok: false, code: 'stale_browser_intent', message: 'Admission changed'}, {status: 409}))
      .mockResolvedValueOnce(Response.json({code: 'browser_operation_busy', message: 'Unmarked failure'}, {status: 409}));
    vi.stubGlobal('fetch', fetcher);
    await expect(request('/api/browser/reconnect', 'POST', {})).rejects.toMatchObject({status: 409, code: 'stale_browser_intent', message: 'Admission changed'});
    await expect(request('/api/browser/reconnect', 'POST', {})).rejects.toMatchObject({status: 409, code: undefined});
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('refreshes CSRF from status and preserves authenticated blob downloads', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response('{"csrf_token":"rotated"}')).mockResolvedValueOnce(new Response('backup'));
    vi.stubGlobal('fetch', fetcher);
    await refreshStatus();
    expect(getCsrfToken()).toBe('rotated');
    expect(await (await requestBlob('/api/backup')).text()).toBe('backup');
    expect(fetcher.mock.calls[1][1].headers['X-CSRF-Token']).toBe('rotated');
  });
  it('reads global admin status without scoped profile paths or viewer headers', async () => {
    vi.resetModules();
    const profiles = await import('./profiles'); const api = await import('./api');
    profiles.bindBrowserProfile('default');
    profiles.setProfileViewer({viewer_id: 'viewer', viewer_token: 'private-viewer', generation: 3, owner: true, idle_timeout_seconds: 180});
    api.setCsrfToken('csrf');
    const fetcher = vi.fn().mockResolvedValue(Response.json({settings_authenticated: true}));
    vi.stubGlobal('fetch', fetcher);
    await api.request('/api/status', 'GET', undefined, {scope: 'global'});
    const [path, options] = fetcher.mock.calls[0];
    expect(path).toBe('/api/status');
    expect(options.headers).not.toHaveProperty('X-Viewer-Token');
    expect(options.headers).not.toHaveProperty('X-Owner-Generation');
    expect(options.headers['X-CSRF-Token']).toBe('csrf');
    expect(options).not.toHaveProperty('scope');
    expect(profiles.browserProfileName()).toBe('default');
  });
  it('targets another profile logout without copying the active viewer capability', async () => {
    vi.resetModules();
    const profiles = await import('./profiles'); const api = await import('./api');
    profiles.bindBrowserProfile('default');
    profiles.setProfileViewer({viewer_id: 'viewer', viewer_token: 'private-viewer', generation: 3, owner: true, idle_timeout_seconds: 180});
    api.setCsrfToken('target-csrf');
    const fetcher = vi.fn().mockResolvedValue(Response.json({ok: true}));
    vi.stubGlobal('fetch', fetcher);
    const target = '/p/work/api/logout';
    await api.request(target, 'POST', {scope: 'vnc'}, {scope: 'global'});
    const [path, options] = fetcher.mock.calls[0];
    expect(path).toBe(target);
    expect(options.headers).not.toHaveProperty('X-Viewer-Token');
    expect(options.headers).not.toHaveProperty('X-Owner-Generation');
    expect(options.headers['X-CSRF-Token']).toBe('target-csrf');
    expect(options.credentials).toBe('same-origin');
    expect(JSON.parse(options.body)).toEqual({scope: 'vnc'});
    expect(fetcher).toHaveBeenCalledOnce();
  });

});
