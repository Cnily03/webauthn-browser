import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false, media: query, onchange: null,
    addListener: vi.fn(), removeListener: vi.fn(),
    addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
  })),
});
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub);
Element.prototype.scrollIntoView = vi.fn();
Object.defineProperty(URL, 'createObjectURL', { writable: true, value: vi.fn(() => 'blob:test-download') });
Object.defineProperty(URL, 'revokeObjectURL', { writable: true, value: vi.fn() });

beforeEach(() => {
  localStorage.clear();
  window.history.replaceState({}, '', '/');
  const meta = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]') ?? document.createElement('meta');
  meta.name = 'csp-nonce';
  meta.content = 'test-response-nonce';
  if (!meta.isConnected) document.head.append(meta);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
