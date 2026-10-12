import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { CssBaseline, ThemeProvider } from '@mui/material';
import App from './App';
import theme from './theme';
import './styles.css';

// All Emotion-generated <style> elements use the gateway's response nonce.
// No runtime CDN, remote fonts, inline script, or eval is required.
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;
const cache = createCache({ key: 'webauthn-browser', nonce, prepend: true });
const root = document.getElementById('root');
if (!root) throw new Error('Missing application root');

createRoot(root).render(
  <StrictMode>
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </CacheProvider>
  </StrictMode>,
);
