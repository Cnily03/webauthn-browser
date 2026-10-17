import { act, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { Root } from 'react-dom/client';

const roots = vi.hoisted(() => [] as Root[]);
vi.mock('react-dom/client', async importOriginal => {
  const original = await importOriginal<typeof import('react-dom/client')>();
  return { ...original, createRoot: (...args: Parameters<typeof original.createRoot>) => {
    const root = original.createRoot(...args);
    roots.push(root);
    return root;
  } };
});
vi.mock('./ProfileApp', async () => {
  const { Button, Dialog, DialogTitle } = await import('@mui/material');
  return { default: () => <><Button variant="contained">Nonce test action</Button><Dialog open><DialogTitle>Nonce test dialog</DialogTitle></Dialog></> };
});
afterEach(async () => {
  await act(async () => { for (const root of roots.splice(0)) root.unmount(); });
  document.getElementById('root')?.remove();
});

it('the real entry gives every Emotion style tag the response nonce, including portalled MUI dialogs', async () => {
  const element = document.createElement('div');
  element.id = 'root';
  document.body.append(element);
  await act(async () => { await import('./main'); });
  expect(await screen.findByRole('dialog', { name: 'Nonce test dialog' })).toBeInTheDocument();
  expect(document.querySelector('.MuiDialog-root')).toBeInTheDocument();
  await waitFor(() => {
    const styles = [...document.querySelectorAll<HTMLStyleElement>('style[data-emotion]')];
    expect(styles.length).toBeGreaterThan(0);
    for (const style of styles) expect(style.nonce).toBe('test-response-nonce');
  });
});
