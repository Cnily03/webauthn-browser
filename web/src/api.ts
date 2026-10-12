import type { AppStatus } from './types';

let csrfToken = '';
export const setCsrfToken = (token: string) => { csrfToken = token; };
export const getCsrfToken = () => csrfToken;
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string) { super(message); this.name = 'ApiError'; }
}
// Mutations are never automatically retried: an interrupted response can still
// mean that the server committed a decision or restored a backup.
async function fetchResponse(path: string, method = 'GET', body?: unknown, options?: Pick<RequestInit, 'signal' | 'keepalive'>): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  if (method !== 'GET' && body === undefined) body = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, {
    ...options, method, headers, credentials: 'same-origin', cache: 'no-store',
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
export async function request<T = any>(path: string, method = 'GET', body?: unknown, options?: Pick<RequestInit, 'signal' | 'keepalive'>): Promise<T> {
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
