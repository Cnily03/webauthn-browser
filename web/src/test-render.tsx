import type { ReactElement } from 'react';
import { render } from '@testing-library/react';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { CssBaseline, ThemeProvider } from '@mui/material';
import theme from './theme';

export function renderMaterial(element: ReactElement) {
  const cache = createCache({ key: 'test-auth', nonce: 'test-response-nonce', prepend: true });
  return render(<CacheProvider value={cache}><ThemeProvider theme={theme}><CssBaseline />{element}</ThemeProvider></CacheProvider>);
}
