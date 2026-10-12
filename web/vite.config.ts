import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  // The gateway replaces this placeholder with a fresh nonce per HTML response.
  // Vite propagates it to modulepreload links and asynchronously loaded styles.
  html: { cspNonce: '__CSP_NONCE__' },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    assetsInlineLimit: 0,
    license: { fileName: 'assets/third-party-licenses.txt' },
  },
  server: {
    proxy: {
      '/api/clipboard/ws': { target: 'ws://127.0.0.1:8080', ws: true },
      '/api': 'http://127.0.0.1:8080',
      '/downloads': 'http://127.0.0.1:8080',
      '/novnc': 'http://127.0.0.1:8080',
      '/ws': { target: 'ws://127.0.0.1:8080', ws: true },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    restoreMocks: true,
    clearMocks: true,
    environmentOptions: { jsdom: { url: 'http://localhost:8080/' } },
    testTimeout: 15000,
  },
});
