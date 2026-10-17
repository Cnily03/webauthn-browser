import type { AppStatus } from './types';
import { browserApiPath, browserProfileName, isProfileBrowserPath, profileViewerHeaders } from './profiles';

let csrfToken = '';
export const setCsrfToken = (token: string) => { csrfToken = token; };
export const getCsrfToken = () => csrfToken;
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string) { super(message); this.name = 'ApiError'; }
}
// Mutations are never automatically retried: an interrupted response can still
// mean that the server committed a decision or restored a backup.
type RequestOptions = Pick<RequestInit, 'signal' | 'keepalive'> & {headers?: Record<string, string>; scope?: 'global'};
async function fetchResponse(path: string, method = 'GET', body?: unknown, options?: RequestOptions): Promise<Response> {
  const {scope, ...fetchOptions} = options ?? {};
  const headers: Record<string, string> = { Accept: 'application/json', ...(scope !== 'global' && isProfileBrowserPath(path, body) ? profileViewerHeaders() : {}), ...options?.headers };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  if (method !== 'GET' && body === undefined) body = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(scope === 'global' ? path : browserApiPath(path, body), {
    ...fetchOptions, method, headers, credentials: 'same-origin', cache: 'no-store',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const raw = await response.text();
    let message = raw;
    let code: string | undefined;
    try {
      const data = JSON.parse(raw); message = data.error || data.message || raw;
      if (data.ok === false && typeof data.code === 'string') code = data.code;
    } catch { /* Plain-text API errors are supported. */ }
    throw new ApiError(typeof message === 'string' && message ? message : `请求失败（${response.status}）`, response.status, code);
  }
  return response;
}
export async function request<T = any>(path: string, method = 'GET', body?: unknown, options?: RequestOptions): Promise<T> {
  const response = await fetchResponse(path, method, body, options);
  const text = await response.text();
  return (text ? JSON.parse(text) : {}) as T;
}
export async function requestBlob(path: string, method = 'GET', body?: unknown): Promise<Blob> {
  return (await fetchResponse(path, method, body)).blob();
}
export async function refreshStatus(): Promise<AppStatus> {
  const status = await request<AppStatus>('/api/status');
  setCsrfToken(status.csrf_token);
  return status;
}

export async function browserTransportUrl(path: string, kind: 'vnc' | 'clipboard', signal?: AbortSignal) {
  const url = new URL(browserApiPath(path), window.location.href);
  url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  if (browserProfileName()) {
    const result = await request<{ticket: string; expires_in_ms: number}>('/api/viewer/ticket', 'POST', {kind}, {signal});
    if (typeof result.ticket !== 'string' || !result.ticket || result.ticket.length > 1024 || !Number.isFinite(result.expires_in_ms) || result.expires_in_ms <= 0) throw new Error('浏览器连接授权无效。');
    url.searchParams.set('ticket', result.ticket);
  }
  return url;
}
