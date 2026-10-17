import { StrictMode } from 'react';
import { act, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderMaterial } from './test-render';

const name = 'work';
beforeEach(() => {vi.resetModules();});
describe('global helper downloads link', () => {
  it.each([name, 'default', null])('links directly to global Downloads with profile %s, without discovery or navigation state', async profileName => {
    const profiles = await import('./profiles');
    if (profileName) {
      profiles.bindBrowserProfile(profileName);
      profiles.setProfileViewer({viewer_id: 'viewer', viewer_token: 'private-test-token', owner: true, generation: 1, idle_timeout_seconds: 180});
    }
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const popup = vi.spyOn(window, 'open');
    const {HelperDownloadLink} = await import('./Helper');
    const view = renderMaterial(<StrictMode><HelperDownloadLink /></StrictMode>); await act(async () => {});
    const link = screen.getByRole('link', {name: '下载'});
    expect(link).toHaveAttribute('href', '/downloads'); expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer'); expect(link).not.toHaveAttribute('aria-disabled');
    expect(fetcher).not.toHaveBeenCalled(); expect(popup).not.toHaveBeenCalled();
    expect(sessionStorage.getItem('webauthn-browser.profile-navigation')).toBeNull();
    view.unmount(); expect(fetcher).not.toHaveBeenCalled(); expect(popup).not.toHaveBeenCalled();
  });
});
