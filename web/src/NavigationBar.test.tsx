import { useState, type ContextType, type Dispatch, type SetStateAction } from 'react';
import { act, fireEvent, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NavigationBar, ProfileNavigationContext } from './NavigationBar';
import { useAppNotification } from './AppNotifications';
import { request, setCsrfToken } from './api';
import { savedProfiles, type PublicBrowserProfile } from './profiles';
import { renderMaterial } from './test-render';

vi.mock('./api', () => ({request: vi.fn(), setCsrfToken: vi.fn()}));

const savedKey = 'webauthn-browser.saved-profiles';
const base: PublicBrowserProfile = {name: 'default', enabled: true, effective_enabled: true, password_enabled: true, idle_timeout_seconds: 180};
const invalid = {...base, name: 'invalid'};
const disabled = {...base, name: 'disabled', effective_enabled: false};
const missing = {...base, name: 'missing'};
const ready = {...base, name: 'ready'};
const save = (...profiles: Pick<PublicBrowserProfile, 'name'>[]) => localStorage.setItem(savedKey, JSON.stringify(profiles.map(profile => ({...profile, lastUsedAt: 1}))));
const flush = async () => {for (let index = 0; index < 20; index++) await Promise.resolve();};
const advance = (ms = 300) => act(async () => {await vi.advanceTimersByTimeAsync(ms); await flush();});
const openMenu = async () => {fireEvent.click(screen.getByRole('button', {name: '浏览器配置'})); await act(flush);};
type NavigationState = NonNullable<ContextType<typeof ProfileNavigationContext>> & {collapsed: boolean};

function mount(overrides: Partial<NavigationState> = {}) {
  const notifyError = vi.fn();
  const navigateProfile = vi.fn(async () => {});
  const navigateDocument = vi.fn();
  let update!: Dispatch<SetStateAction<NavigationState>>;
  function Harness() {
    const [state, setState] = useState<NavigationState>({profiles: [base, invalid, disabled, ready], activeProfileName: base.name,
      profileStatuses: {[invalid.name]: 'auth_invalid'}, notifyError, navigateProfile, navigateDocument, collapsed: false, ...overrides});
    update = setState;
    const {notify, snackbar} = useAppNotification();
    return <ProfileNavigationContext.Provider value={{...state, notifyError: message => {state.notifyError(message); notify(message, true);}}}>
      <NavigationBar collapsible collapsed={state.collapsed} onToggle={() => setState(current => ({...current, collapsed: !current.collapsed}))}>
        <nav aria-label="主导航"><a href="/">浏览器</a><a href="/settings">设置</a></nav>
      </NavigationBar>
      {snackbar}
    </ProfileNavigationContext.Provider>;
  }
  const view = renderMaterial(<Harness />);
  return {...view, notifyError, navigateProfile, navigateDocument, update: (patch: Partial<NavigationState>) => act(() => update(state => ({...state, ...patch})))};
}

beforeEach(() => {
  vi.useFakeTimers(); sessionStorage.clear();
  vi.mocked(request).mockReset();
  vi.mocked(request).mockImplementation(async path => path === '/api/status' ? {csrf_token: 'fresh-csrf'} : {ok: true});
});

describe('profile menu status and accessible errors', () => {
  it('keeps the collapse control left of the collapsible profile/navigation group', async () => {
    mount();
    const toggle = screen.getByRole('button', {name: '收起导航'});
    const group = document.getElementById('navigation-group')!;
    expect(toggle.compareDocumentPosition(group) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(group).toContainElement(screen.getByRole('button', {name: '浏览器配置'}));
    fireEvent.click(toggle); await advance();
    expect(group).toHaveAttribute('hidden');
    expect(screen.queryByRole('button', {name: '浏览器配置'})).toBeNull();
    expect(screen.getByRole('button', {name: '展开导航'})).toBeVisible();
  });

  it('shows only authenticated current green, missing/disabled red, and invalid authentication orange', async () => {
    save(invalid, disabled, missing, ready);
    mount({profileStatuses: {[base.name]: 'auth_invalid', [invalid.name]: 'auth_invalid', [disabled.name]: 'auth_invalid', [missing.name]: 'auth_invalid'}}); await openMenu();
    const cases = [
      ['default', '当前配置', 'Success'], ['invalid', '配置认证失效', 'Warning'],
      ['disabled', '配置不存在或已停用', 'Error'], ['missing', '配置不存在或已停用', 'Error'],
    ];
    for (const [name, status, color] of cases) {
      const row = screen.getByRole('menuitem', {name: `${name} ${status}`});
      const dot = within(row).getByRole('img', {name: status});
      expect(dot).toHaveClass(`MuiSvgIcon-color${color}`);
      expect(dot).toHaveStyle({fontSize: '10px'});
      expect(getComputedStyle(dot).boxShadow).toContain('0 0 0 4px');
      expect(row.textContent).toBe(name);
      expect(row.lastElementChild).toContainElement(dot);
      expect(row.querySelector('[title], title')).toBeNull();
    }
    expect(screen.getByRole('menuitem', {name: 'default 当前配置'})).toHaveAttribute('aria-current', 'true');
    expect(within(screen.getByRole('menuitem', {name: 'ready'})).queryByRole('img')).toBeNull();
    expect(within(screen.getByRole('menu')).queryByRole('alert')).toBeNull();
  });

  it.each([
    ['missing', '配置不存在或已停用'], ['disabled', '配置不存在或已停用'], ['invalid', '配置认证失效'],
  ])('shows the exact right-side Material tooltip for %s on dot hover and row focus', async (name, status) => {
    save(missing, disabled, invalid); mount(); await openMenu();
    const row = screen.getByRole('menuitem', {name: `${name} ${status}`});
    const dot = within(row).getByRole('img', {name: status});
    fireEvent.mouseEnter(dot); await advance();
    let tooltip = screen.getByRole('tooltip');
    expect(tooltip).toHaveTextContent(status);
    expect(tooltip.closest('[data-popper-placement]')).toHaveAttribute('data-popper-placement', 'right');
    expect(dot).not.toHaveAttribute('title'); expect(dot.querySelector('title')).toBeNull();
    fireEvent.mouseLeave(dot); fireEvent.mouseLeave(row);
    act(() => screen.getByRole('menuitem', {name: '登录其他配置'}).focus()); await advance();
    expect(screen.queryByRole('tooltip')).toBeNull();
    act(() => row.focus()); await advance();
    tooltip = screen.getByRole('tooltip');
    expect(tooltip).toHaveTextContent(status);
    expect(row).toHaveAttribute('aria-describedby', tooltip.id);
  });

  it('keeps the actual authenticated row inert for name, icon, status, and keyboard actions', async () => {
    save(base); const view = mount(); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'default 当前配置'});
    fireEvent.mouseEnter(row);
    for (const target of [row, within(row).getByText('default'), within(row).getByTestId('AccountCircleOutlinedIcon'), within(row).getByRole('img')]) fireEvent.click(target);
    for (const key of ['Enter', ' ', 'Delete', 'Delete', 'Backspace', 'Backspace']) fireEvent.keyDown(row, {key});
    fireEvent.keyUp(row, {key: ' '}); await act(flush);
    expect(view.navigateProfile).not.toHaveBeenCalled(); expect(view.navigateDocument).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled(); expect(view.notifyError).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', {name: '移除配置 default'})).toBeNull();
    expect(savedProfiles().map(profile => profile.name)).toEqual([base.name]);
  });

  it('never treats a remembered active status as proof of current authentication', async () => {
    save(base); mount({activeProfileName: null, profileStatuses: {[base.name]: 'active'}}); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'default'});
    expect(row).not.toHaveAttribute('aria-current'); expect(within(row).queryByRole('img')).toBeNull();
    fireEvent.mouseEnter(row); expect(within(row).getByRole('button', {name: '移除配置 default'})).toBeVisible();
  });

  it.each([missing, disabled])('blocks unavailable $name selection and keeps its hint after an accessible global error', async profile => {
    save(profile); const view = mount(); await openMenu();
    fireEvent.click(screen.getByRole('menuitem', {name: `${profile.name} 配置不存在或已停用`})); await advance();
    expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('浏览器配置不存在或已停用。');
    expect(view.navigateProfile).not.toHaveBeenCalled(); expect(request).not.toHaveBeenCalled();
    expect(screen.queryByRole('menu')).toBeNull();
    expect(screen.getByRole('alert')).toHaveTextContent('浏览器配置不存在或已停用。');
    expect(savedProfiles().map(item => item.name)).toEqual([profile.name]);
    await openMenu(); expect(screen.getByRole('menuitem', {name: `${profile.name} 配置不存在或已停用`})).toBeVisible();
    expect(within(screen.getByRole('menu')).queryByText('浏览器配置不存在或已停用。')).toBeNull();
  });

  it('allows invalid authentication to re-enter the exact remembered identity and clears orange after success', async () => {
    save(invalid); const view = mount(); await openMenu();
    fireEvent.click(screen.getByRole('menuitem', {name: 'invalid 配置认证失效'})); await advance();
    expect(view.navigateProfile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({name: 'invalid'}));
    expect(view.notifyError).not.toHaveBeenCalled(); expect(savedProfiles().map(profile => profile.name)).toEqual([invalid.name]);
    view.update({activeProfileName: invalid.name, profileStatuses: {}}); await openMenu();
    expect(within(screen.getByRole('menuitem', {name: 'invalid 当前配置'})).getByRole('img')).toHaveClass('MuiSvgIcon-colorSuccess');
    expect(screen.queryByRole('img', {name: '配置认证失效'})).toBeNull();
  });

  it('keeps the old remembered name unavailable after a rename', async () => {
    save(missing); const view = mount({profiles: [base, {...missing, name: 'renamed'}]}); await openMenu();
    fireEvent.click(screen.getByRole('menuitem', {name: 'missing 配置不存在或已停用'})); await advance();
    expect(view.navigateProfile).not.toHaveBeenCalled(); expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('浏览器配置不存在或已停用。');
    expect(savedProfiles().map(profile => profile.name)).toEqual([missing.name]);
  });

  it('lets the server reject an old credential when a remembered name is reused', async () => {
    save(missing);
    const navigateProfile = vi.fn().mockRejectedValue(new Error('配置认证失效，请重新登录。'));
    const view = mount({profiles: [base, {...ready, name: missing.name}], navigateProfile}); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'missing'});
    expect(row).not.toHaveAttribute('aria-current');
    fireEvent.click(row); await advance();
    expect(navigateProfile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({name: 'missing'}));
    expect(navigateProfile.mock.calls[0][0]).not.toHaveProperty('id');
    expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('配置认证失效，请重新登录。');
    expect(savedProfiles().map(profile => profile.name)).toEqual([missing.name]);
    view.update({profileStatuses: {[missing.name]: 'auth_invalid'}}); await openMenu();
    expect(screen.getByRole('menuitem', {name: 'missing 配置认证失效'})).not.toHaveAttribute('aria-current');
  });

  it('matches current, saved, and catalog names case-insensitively without duplicate rows', async () => {
    save({...ready, name: 'READY'});
    const view = mount({profiles: [base, {...ready, name: 'Ready'}], activeProfileName: 'rEaDy'}); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'Ready 当前配置'});
    expect(screen.getAllByRole('menuitem')).toHaveLength(2);
    fireEvent.mouseEnter(row); fireEvent.click(row);
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete'});
    expect(view.navigateProfile).not.toHaveBeenCalled(); expect(request).not.toHaveBeenCalled();
    expect(within(row).queryByRole('button', {name: '移除配置 Ready'})).toBeNull();
  });

  it('uses canonical name keys for authentication hints while preserving catalog spelling', async () => {
    save({...invalid, name: 'INVALID'});
    const view = mount({profiles: [base, {...invalid, name: 'Invalid'}]}); await openMenu();
    fireEvent.click(screen.getByRole('menuitem', {name: 'Invalid 配置认证失效'})); await advance();
    expect(view.navigateProfile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({name: 'Invalid'}));
  });

  it('uses the global callback for a rejected switch without putting its concrete error into the menu', async () => {
    save(invalid); const navigateProfile = vi.fn().mockRejectedValue(new Error('配置登录请求失败，请重试。'));
    const view = mount({navigateProfile}); await openMenu();
    fireEvent.click(screen.getByRole('menuitem', {name: 'invalid 配置认证失效'})); await advance();
    expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('配置登录请求失败，请重试。');
    expect(screen.getByRole('alert')).toHaveTextContent('配置登录请求失败，请重试。');
    await openMenu(); expect(within(screen.getByRole('menu')).queryByText('配置登录请求失败，请重试。')).toBeNull();
    expect(screen.getByRole('menuitem', {name: 'invalid 配置认证失效'})).toBeVisible();
  });

  it('reports a chooser storage failure globally while preserving the saved rows', async () => {
    save(invalid); const view = mount(); await openMenu();
    const setItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, key, value) {
      if (this === sessionStorage) throw new Error('blocked');
      return setItem.call(this, key, value);
    });
    fireEvent.click(screen.getByRole('menuitem', {name: '登录其他配置'})); await advance();
    expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('无法安全打开登录页面，请重试。');
    expect(screen.getByRole('alert')).toHaveTextContent('无法安全打开登录页面，请重试。');
    expect(view.navigateDocument).not.toHaveBeenCalled(); expect(savedProfiles()).toHaveLength(1);
  });
});

describe('deliberate local profile forget', () => {
  it('requires two clicks within three seconds and removes only the chosen inactive identity', async () => {
    save(invalid, ready); const view = mount(); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'invalid 配置认证失效'}); fireEvent.mouseEnter(row);
    const remove = within(row).getByRole('button', {name: '移除配置 invalid'});
    fireEvent.click(remove); expect(remove).toHaveAttribute('aria-pressed', 'true');
    expect(remove).toHaveClass('MuiIconButton-colorError'); expect(request).not.toHaveBeenCalled();
    await advance(3000); expect(remove).toHaveAttribute('aria-pressed', 'false');
    fireEvent.click(remove); expect(request).not.toHaveBeenCalled();
    await advance(2999); fireEvent.click(remove); await act(flush);
    expect(request).toHaveBeenNthCalledWith(1, '/api/status', 'GET', undefined, expect.objectContaining({scope: 'global', signal: expect.any(AbortSignal)}));
    expect(setCsrfToken).toHaveBeenCalledWith('fresh-csrf');
    expect(request).toHaveBeenNthCalledWith(2, `/p/${invalid.name}/api/logout`, 'POST', {scope: 'vnc'}, expect.objectContaining({signal: expect.any(AbortSignal)}));
    expect(savedProfiles().map(profile => profile.name)).toEqual([ready.name]);
    expect(screen.getByRole('menuitem', {name: 'ready'})).toHaveFocus();
    expect(view.navigateProfile).not.toHaveBeenCalled();
  });

  it('forgets the canonical name cookie and all casing variants of only that local hint', async () => {
    save({...invalid, name: 'INVALID'}, ready);
    mount({profiles: [base, {...invalid, name: 'Invalid'}, ready]}); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'Invalid 配置认证失效'});
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete'}); await act(flush);
    expect(request).toHaveBeenNthCalledWith(2, '/p/invalid/api/logout', 'POST', {scope: 'vnc'}, expect.objectContaining({signal: expect.any(AbortSignal)}));
    expect(savedProfiles().map(profile => profile.name)).toEqual([ready.name]);
    expect(screen.getByRole('menuitem', {name: 'ready'})).toHaveFocus();
  });

  it('ignores held Delete and clears the confirmation when focus moves or the row becomes current', async () => {
    save(invalid, ready); const view = mount(); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'invalid 配置认证失效'}); act(() => row.focus());
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete', repeat: true});
    expect(request).not.toHaveBeenCalled();
    act(() => screen.getByRole('menuitem', {name: 'ready'}).focus()); act(() => row.focus());
    expect(within(row).getByRole('button', {name: '移除配置 invalid'})).toHaveAttribute('aria-pressed', 'false');
    fireEvent.keyDown(row, {key: 'Backspace'});
    view.update({activeProfileName: invalid.name});
    expect(screen.queryByRole('button', {name: '移除配置 invalid'})).toBeNull();
    fireEvent.keyDown(row, {key: 'Backspace'}); expect(request).not.toHaveBeenCalled();
  });

  it.each(['close', 'collapse', 'pagehide'])('clears the two-click confirmation across %s', async boundary => {
    save(invalid); const view = mount(); await openMenu();
    const row = screen.getByRole('menuitem', {name: 'invalid 配置认证失效'}); fireEvent.mouseEnter(row);
    fireEvent.click(within(row).getByRole('button', {name: '移除配置 invalid'}));
    if (boundary === 'close') fireEvent.keyDown(screen.getByRole('menu'), {key: 'Escape'});
    else if (boundary === 'collapse') view.update({collapsed: true});
    else act(() => window.dispatchEvent(new Event('pagehide')));
    await advance(); expect(screen.queryByRole('menu')).toBeNull();
    if (boundary === 'collapse') view.update({collapsed: false});
    await openMenu();
    const next = screen.getByRole('menuitem', {name: 'invalid 配置认证失效'}); fireEvent.mouseEnter(next);
    const remove = within(next).getByRole('button', {name: '移除配置 invalid'});
    expect(remove).toHaveAttribute('aria-pressed', 'false'); fireEvent.click(remove);
    expect(request).not.toHaveBeenCalled();
  });

  it('retains the unavailable hint on failed logout and permits a fresh confirmed retry after the global error', async () => {
    save(missing); const view = mount(); await openMenu();
    vi.mocked(request).mockImplementation(async path => {
      if (path.endsWith('/api/logout')) throw new Error('配置凭据清除失败。');
      return {csrf_token: 'fresh-csrf'};
    });
    const row = screen.getByRole('menuitem', {name: 'missing 配置不存在或已停用'});
    fireEvent.keyDown(row, {key: 'Delete'}); fireEvent.keyDown(row, {key: 'Delete'}); await advance();
    expect(view.notifyError).toHaveBeenCalledExactlyOnceWith('配置凭据清除失败。');
    expect(screen.getByRole('alert')).toHaveTextContent('配置凭据清除失败。'); expect(screen.queryByRole('menu')).toBeNull();
    expect(savedProfiles().map(profile => profile.name)).toEqual([missing.name]);
    vi.mocked(request).mockResolvedValue({csrf_token: 'fresh-csrf'}); await openMenu();
    const retry = screen.getByRole('menuitem', {name: 'missing 配置不存在或已停用'});
    expect(within(screen.getByRole('menu')).queryByText('配置凭据清除失败。')).toBeNull();
    fireEvent.keyDown(retry, {key: 'Delete'}); fireEvent.keyDown(retry, {key: 'Delete'}); await act(flush);
    expect(savedProfiles()).toEqual([]); expect(screen.getByRole('menuitem', {name: '登录其他配置'})).toHaveFocus();
  });
});
