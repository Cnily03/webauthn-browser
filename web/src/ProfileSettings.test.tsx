import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ProfileSettings, { type ProfileConfiguration } from './ProfileSettings';
import { renderMaterial } from './test-render';
import { setCsrfToken } from './api';
import { bindBrowserProfile, setProfileViewer } from './profiles';

const exits = vi.hoisted(() => new Map<string, Array<() => void>>());
vi.mock('@mui/material', async load => {
  const actual = await load<typeof import('@mui/material')>();
  return { ...actual, Accordion: (props: import('@mui/material').AccordionProps) => {
    const transition = props.slotProps?.transition;
    const name = props['aria-label'];
    if (name && typeof transition === 'object' && transition.onExited) {
      const callback = transition.onExited;
      exits.set(name, [...(exits.get(name) ?? []), () => callback(document.createElement('div'))]);
    }
    return <actual.Accordion {...props} />;
  } };
});

let configuration: ProfileConfiguration;
let calls: Array<{ path: string; method: string; body: Record<string, unknown> }>;
let pending: Promise<void> | undefined;
let cleanupResponse: unknown;
let cleanupStatus: number;
const notify = vi.fn();
const changed = vi.fn();
const unauthorized = vi.fn();
beforeEach(() => {
  exits.clear();
  calls = []; pending = undefined;
  cleanupResponse = { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: 0, browser_data_retained: true };
  cleanupStatus = 200;
  configuration = { multi_profile: true, profiles: [
    { id: 'default', name: 'default', enabled: false, effective_enabled: false, password_enabled: true, idle_timeout_seconds: 180 },
    { id: 'stable-id', name: 'work', enabled: true, effective_enabled: true, password_enabled: false, idle_timeout_seconds: 300 },
  ] };
  setCsrfToken('csrf');
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const method = init?.method || 'GET';
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    calls.push({ path, method, body });
    expect(init?.credentials).toBe('same-origin');
    expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe('csrf');
    if (method !== 'GET' && pending) await pending;
    if (path === '/api/runtime/cleanup' && method === 'POST') return new Response(JSON.stringify(cleanupResponse), { status: cleanupStatus, headers: { 'Content-Type': 'application/json' } });
    if (method === 'PUT') {
      configuration.multi_profile = body.multi_profile;
      for (const p of configuration.profiles) p.effective_enabled = configuration.multi_profile ? p.enabled : p.id === 'default';
    } else if (method === 'PATCH') {
      const profile = configuration.profiles.find(p => path.endsWith(p.id))!;
      Object.assign(profile, body);
      if ('password' in body) profile.password_enabled = body.password !== null;
    } else if (method === 'POST') configuration.profiles.push({ ...body, id: 'new-id', name: body.name.toLowerCase(), effective_enabled: body.enabled, password_enabled: body.password !== null } as ProfileConfiguration['profiles'][number]);
    else if (method === 'DELETE') configuration.profiles = configuration.profiles.filter(p => !path.endsWith(p.id));
    return new Response(JSON.stringify(method === 'GET' ? configuration : method === 'DELETE' ? { ok: true, browser_data_retained: false } : { ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }));
});
async function mount() {
  const view = renderMaterial(<ProfileSettings notify={notify} onUnauthorized={unauthorized} onChanged={changed} />);
  await screen.findByRole('article', { name: '浏览器配置 default' });
  return view;
}
const mutations = () => calls.filter(call => call.method !== 'GET');
const activeFields = () => within(screen.getByRole('form'));

describe('browser profile settings', () => {
  it('keeps profile margins and summary height unchanged when expanded', async () => {
    await mount();
    const summary = screen.getByRole('button', { name: 'work 配置设置' });
    const accordion = summary.closest('.MuiAccordion-root')!;
    expect(accordion.parentElement).toHaveStyle({ gap: 'calc(2 * var(--mui-spacing))' });
    for (let cycle = 0; cycle < 3; cycle++) {
      expect(accordion).toHaveStyle({ marginTop: '0px', marginBottom: '0px', boxShadow: 'none' });
      expect(summary).toHaveStyle({ minHeight: '48px' });
      expect(summary.querySelector('.MuiAccordionSummary-content')).toHaveStyle({ marginTop: '12px', marginBottom: '12px' });
      await userEvent.click(summary);
    }
  });

  it('retains the same disabled content for the collapse interval and clears plaintext immediately', async () => {
    await mount();
    vi.useFakeTimers();
    const summary = screen.getByRole('button', { name: 'default 配置设置' });
    fireEvent.click(summary);
    act(() => vi.advanceTimersByTime(180));
    const form = screen.getByRole('form');
    const timeout = activeFields().getByLabelText('空闲超时（秒）');
    const password = activeFields().getByLabelText('访问密码');
    fireEvent.change(timeout, { target: { value: '700' } });
    fireEvent.change(password, { target: { value: 'exit secret' } });
    fireEvent.click(summary);
    expect(form).toBeInTheDocument();
    expect(form).toHaveAttribute('inert');
    expect(form).toHaveAttribute('aria-hidden', 'true');
    expect(timeout).toHaveValue(700);
    expect(timeout).toBeDisabled();
    expect(password).toHaveValue('');
    expect(password).toBeDisabled();
    expect(form.closest('.MuiCollapse-root')).toHaveStyle({ transitionDuration: '180ms' });
    fireEvent.submit(form);
    expect(mutations()).toHaveLength(0);
    act(() => vi.advanceTimersByTime(179));
    expect(form).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(1));
    expect(form).not.toBeInTheDocument();
  });

  it('isolates a new active editor from retained content and late exit callbacks', async () => {
    await mount();
    vi.useFakeTimers();
    const firstSummary = screen.getByRole('button', { name: 'default 配置设置' });
    const secondSummary = screen.getByRole('button', { name: 'work 配置设置' });
    fireEvent.click(firstSummary);
    act(() => vi.advanceTimersByTime(180));
    const departing = screen.getByRole('form');
    const oldTimeout = activeFields().getByLabelText('空闲超时（秒）');
    const oldPassword = activeFields().getByLabelText('访问密码');
    fireEvent.change(oldPassword, { target: { value: 'first secret' } });
    fireEvent.click(secondSummary);
    const oldExit = exits.get('浏览器配置 default')!.at(-1)!;
    expect(departing).toBeInTheDocument();
    expect(oldPassword).toHaveValue('');
    fireEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const secondPassword = activeFields().getByLabelText('访问密码');
    fireEvent.change(secondPassword, { target: { value: 'second secret' } });
    fireEvent.change(oldTimeout, { target: { value: '999' } });
    fireEvent.submit(departing);
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(300);
    expect(mutations()).toHaveLength(0);
    act(() => oldExit());
    expect(departing).not.toBeInTheDocument();
    expect(secondPassword).toHaveValue('second secret');

    fireEvent.click(firstSummary);
    const secondExit = exits.get('浏览器配置 work')!.at(-1)!;
    const reopened = screen.getByRole('form');
    const newPassword = activeFields().getByLabelText('访问密码');
    fireEvent.change(newPassword, { target: { value: 'reopened secret' } });
    act(() => { oldExit(); secondExit(); vi.advanceTimersByTime(180); });
    expect(reopened).toBeInTheDocument();
    expect(firstSummary).toHaveAttribute('aria-expanded', 'true');
    expect(newPassword).toHaveValue('reopened secret');
    expect(mutations()).toHaveLength(0);
  });

  it('reopening the same profile before exit ignores its previous cleanup', async () => {
    await mount();
    vi.useFakeTimers();
    const summary = screen.getByRole('button', { name: 'default 配置设置' });
    fireEvent.click(summary);
    act(() => vi.advanceTimersByTime(180));
    const first = activeFields().getByLabelText('访问密码');
    fireEvent.change(first, { target: { value: 'first secret' } });
    fireEvent.click(summary);
    const oldExit = exits.get('浏览器配置 default')!.at(-1)!;
    fireEvent.click(summary);
    const replacement = activeFields().getByLabelText('访问密码');
    expect(replacement).not.toBe(first);
    expect(first).toHaveValue('');
    fireEvent.change(replacement, { target: { value: 'replacement secret' } });
    act(() => { oldExit(); vi.advanceTimersByTime(180); });
    expect(replacement).toHaveValue('replacement secret');
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(summary);
    const latest = screen.getByRole('form', { hidden: true });
    act(() => oldExit());
    expect(latest).toBeInTheDocument();
    expect(replacement).toHaveValue('');
    act(() => vi.advanceTimersByTime(180));
    expect(latest).not.toBeInTheDocument();
  });

  it('keeps retained profile cleanup separate from a creation password', async () => {
    await mount();
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    act(() => vi.advanceTimersByTime(180));
    const previous = activeFields().getByLabelText('访问密码');
    fireEvent.change(previous, { target: { value: 'old profile secret' } });
    fireEvent.click(screen.getByRole('button', { name: '添加配置' }));
    const exited = exits.get('浏览器配置 default')!.at(-1)!;
    fireEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const password = activeFields().getByLabelText('访问密码');
    fireEvent.change(password, { target: { value: 'new profile secret' } });
    act(() => { exited(); vi.advanceTimersByTime(180); });
    expect(previous).toHaveValue('');
    expect(password).toHaveValue('new profile secret');
    expect(screen.getByRole('dialog')).toHaveAccessibleName('添加浏览器配置');
    act(() => window.dispatchEvent(new Event('pagehide')));
    expect(password).toHaveValue('');
  });

  it('opens inline MUI details with accessible keyboard expansion and no edit dialog', async () => {
    await mount();
    const summary = screen.getByRole('button', { name: 'work 配置设置' });
    expect(summary).toHaveClass('MuiAccordionSummary-root');
    expect(summary).toHaveAttribute('aria-expanded', 'false');
    expect(summary.querySelector('button, input, a, [role="switch"]')).toBeNull();
    summary.focus();
    await userEvent.keyboard('{Enter}');
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    const details = document.getElementById(summary.getAttribute('aria-controls')!)!;
    expect(details).toHaveAttribute('role', 'region');
    expect(details).toHaveAttribute('aria-labelledby', summary.id);
    expect(within(details).getByLabelText('配置名称')).toHaveValue('work');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('编辑浏览器配置')).toBeNull();
    summary.focus();
    await userEvent.keyboard(' ');
    expect(summary).toHaveAttribute('aria-expanded', 'false');
    await waitFor(() => expect(screen.queryByLabelText('配置名称')).toBeNull());
    expect(mutations()).toHaveLength(0);
  });

  it.each(['collapse', 'cancel'] as const)('discards inline edits and clears the password on %s', async action => {
    await mount();
    const summary = screen.getByRole('button', { name: 'work 配置设置' });
    await userEvent.click(summary);
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'unsaved' } });
    fireEvent.change(activeFields().getByLabelText('空闲超时（秒）'), { target: { value: '900' } });
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const input = activeFields().getByLabelText('访问密码');
    fireEvent.change(input, { target: { value: 'discarded secret' } });
    await userEvent.click(action === 'collapse' ? summary : screen.getByRole('button', { name: '取消' }));
    expect(input).toHaveValue('');
    expect(summary).toHaveAttribute('aria-expanded', 'false');
    await userEvent.click(summary);
    expect(activeFields().getByLabelText('配置名称')).toHaveValue('work');
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(300);
    expect(screen.getByRole('switch', { name: '设置访问密码' })).not.toBeChecked();
    expect(activeFields().getByLabelText('访问密码')).toHaveValue('');
    expect(mutations()).toHaveLength(0);
  });

  it('isolates drafts and passwords when switching profiles and saves the immutable target ID', async () => {
    await mount();
    const defaultSummary = screen.getByRole('button', { name: 'default 配置设置' });
    await userEvent.click(defaultSummary);
    fireEvent.change(activeFields().getByLabelText('空闲超时（秒）'), { target: { value: '999' } });
    const previous = activeFields().getByLabelText('访问密码');
    fireEvent.change(previous, { target: { value: 'default-only secret' } });
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    expect(previous).toHaveValue('');
    expect(defaultSummary).toHaveAttribute('aria-expanded', 'false');
    expect(activeFields().getByLabelText('配置名称')).toHaveValue('work');
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(300);
    expect(activeFields().getByLabelText('访问密码')).toHaveValue('');
    expect(activeFields().getByLabelText('访问密码')).toBeDisabled();
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'renamed' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await screen.findByRole('article', { name: '浏览器配置 renamed' });
    expect(mutations()).toEqual([{ path: '/api/profiles/stable-id', method: 'PATCH', body: {
      name: 'renamed', idle_timeout_seconds: 300, enabled: true,
    } }]);
    await userEvent.click(defaultSummary);
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(180);
    expect(activeFields().getByLabelText('访问密码')).toHaveValue('');
  });

  it('keeps the current editor while saving and clears plaintext before the response', async () => {
    await mount();
    const summary = screen.getByRole('button', { name: 'default 配置设置' });
    const other = screen.getByRole('button', { name: 'work 配置设置' });
    await userEvent.click(summary);
    const input = activeFields().getByLabelText('访问密码');
    fireEvent.change(input, { target: { value: 'saved secret' } });
    let release!: () => void; pending = new Promise<void>(resolve => { release = resolve; });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(input).toHaveValue('');
    expect(input).toBeDisabled();
    expect(summary).toBeDisabled(); expect(other).toBeDisabled();
    expect(screen.getByRole('button', { name: '取消' })).toBeDisabled();
    const cleanup = screen.getByRole('button', { name: '清理资源' });
    expect(cleanup).toBeDisabled();
    fireEvent.click(cleanup);
    fireEvent.click(summary); fireEvent.click(other);
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    expect(other).toHaveAttribute('aria-expanded', 'false');
    expect(mutations()).toHaveLength(1);
    expect(mutations()[0].body.password).toBe('saved secret');
    await act(async () => { release(); });
    await waitFor(() => expect(summary).toHaveAttribute('aria-expanded', 'false'));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('clears inline secrets when opening creation or deletion dialogs', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const first = activeFields().getByLabelText('访问密码');
    fireEvent.change(first, { target: { value: 'discard before creation' } });
    await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    expect(first).toHaveValue('');
    expect(screen.getByRole('dialog')).toHaveAccessibleName('添加浏览器配置');
    expect(activeFields().getByLabelText('访问密码')).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const second = activeFields().getByLabelText('访问密码');
    fireEvent.change(second, { target: { value: 'discard before deletion' } });
    await userEvent.click(screen.getByRole('button', { name: '删除 work' }));
    expect(second).toHaveValue('');
    expect(screen.getByRole('dialog')).toHaveAccessibleName('删除配置？');
    expect(mutations()).toHaveLength(0);
  });

  it('clears unsaved inline plaintext on unmount without a mutation', async () => {
    const view = await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    const input = activeFields().getByLabelText('访问密码');
    fireEvent.change(input, { target: { value: 'discard on unmount' } });
    view.unmount();
    expect(input).toHaveValue('');
    expect(mutations()).toHaveLength(0);
  });

  it('keeps the default immutable and uses stable IDs for edits', async () => {
    await mount();
    const card = within(screen.getByRole('article', { name: '浏览器配置 default' }));
    expect(card.queryByRole('button', { name: /删除/ })).toBeNull();
    await userEvent.click(card.getByRole('button', { name: 'default 配置设置' }));
    expect(card.queryByRole('button', { name: /删除/ })).toBeNull();
    expect(activeFields().getByLabelText('配置名称')).toBeDisabled();
    fireEvent.change(activeFields().getByLabelText('空闲超时（秒）'), { target: { value: '240' } });
    fireEvent.change(activeFields().getByLabelText('访问密码'), { target: { value: 'confirmed password' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await waitFor(() => expect(card.getByRole('button', { name: 'default 配置设置' })).toHaveAttribute('aria-expanded', 'false'));
    expect(mutations()).toEqual([{ path: '/api/profiles/default', method: 'PATCH', body: { idle_timeout_seconds: 240, enabled: false, password: 'confirmed password' } }]);
  });

  it('changes effective availability without mutating saved enabled choices', async () => {
    await mount();
    await userEvent.click(screen.getByRole('switch', { name: '多配置模式' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '添加配置' })).toBeDisabled());
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    const defaults = screen.getByRole('switch', { name: '启用配置' });
    expect(defaults).toBeDisabled(); expect(defaults).toBeChecked();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    const other = screen.getByRole('switch', { name: '启用配置' });
    expect(other).toBeDisabled(); expect(other).not.toBeChecked();
    expect(configuration.profiles.map(p => p.enabled)).toEqual([false, true]);
    await userEvent.click(screen.getByRole('switch', { name: '多配置模式' }));
    await waitFor(() => expect(screen.getByRole('button', { name: '添加配置' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    expect(screen.getByRole('switch', { name: '启用配置' })).toBeEnabled();
    expect(screen.getByRole('switch', { name: '启用配置' })).not.toBeChecked();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    expect(screen.getByRole('switch', { name: '启用配置' })).toBeChecked();
    expect(mutations().map(call => call.body)).toEqual([{ multi_profile: false }, { multi_profile: true }]);
  });

  it('shows effective default availability in a disabled single-profile editor without saving it', async () => {
    configuration.multi_profile = false;
    configuration.profiles[0].effective_enabled = true;
    configuration.profiles[1].effective_enabled = false;
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    expect(screen.getByRole('switch', { name: '启用配置' })).toBeChecked();
    expect(screen.getByRole('switch', { name: '启用配置' })).toBeDisabled();
    fireEvent.change(activeFields().getByLabelText('访问密码'), { target: { value: 'confirmed password' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(mutations()[0].body).toEqual({ idle_timeout_seconds: 180, password: 'confirmed password' });
    expect(configuration.profiles[0].enabled).toBe(false);
  });

  it('creates a passwordless profile with the default timeout and validates canonical duplicates', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(180);
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'WORK' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('此名称已存在');
    expect(mutations()).toHaveLength(0);
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'Home_2.test' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await screen.findByRole('article', { name: '浏览器配置 home_2.test' });
    expect(mutations()[0]).toEqual({ path: '/api/profiles', method: 'POST', body: { name: 'Home_2.test', enabled: true, idle_timeout_seconds: 180, password: null } });
  });

  it.each(['../escape', '.', '..', 'spaces here', ' leading', 'trailing ', 'bad.git', 'bad.WIKI', '中文'])('rejects invalid name %s without a request', async name => {
    await mount(); await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: name } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(await screen.findByRole('alert')).toBeVisible(); expect(mutations()).toHaveLength(0);
  });

  it.each(['.github', '_private', '-project'])('accepts GitHub-compatible leading punctuation in %s', async name => {
    await mount(); await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: name } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await screen.findByRole('article', { name: `浏览器配置 ${name}` });
    expect(mutations()[0].body.name).toBe(name);
  });

  it.each(['0', '-1', '86401', '1.5'])('rejects invalid idle timeout %s', async timeout => {
    await mount(); await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'new' } });
    fireEvent.change(activeFields().getByLabelText('空闲超时（秒）'), { target: { value: timeout } });
    fireEvent.submit(screen.getByRole('button', { name: '保存' }).closest('form')!);
    expect(await screen.findByRole('alert')).toHaveTextContent('空闲超时');
    expect(mutations()).toHaveLength(0);
  });

  it('requires a nonempty enabled password and clears plaintext before response', async () => {
    await mount(); await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'secure' } });
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('请输入非空密码');
    expect(mutations()).toHaveLength(0);
    const input = activeFields().getByLabelText('访问密码');
    fireEvent.change(input, { target: { value: ' exact 🔑 value ' } });
    let release!: () => void; pending = new Promise<void>(resolve => { release = resolve; });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(input).toHaveValue(''); expect(screen.getByRole('button', { name: '取消' })).toBeDisabled();
    expect(mutations()[0].body.password).toBe(' exact 🔑 value ');
    await act(async () => { release(); });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('keeps one password control and the same input while toggling protection', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    expect(screen.queryByRole('switch', { name: '更改访问密码' })).toBeNull();
    const toggle = screen.getByRole('switch', { name: '设置访问密码' });
    const input = activeFields().getByLabelText('访问密码');
    expect(toggle).toBeChecked(); expect(input).toBeEnabled(); expect(input).toBeRequired();
    fireEvent.change(input, { target: { value: 'temporary replacement' } });
    await userEvent.click(toggle);
    expect(activeFields().getByLabelText('访问密码')).toBe(input);
    expect(input).toBeDisabled(); expect(input).toHaveValue(''); expect(input).not.toBeRequired();
    await userEvent.click(toggle);
    expect(activeFields().getByLabelText('访问密码')).toBe(input);
    expect(input).toBeEnabled(); expect(input).toHaveValue(''); expect(input).toBeRequired();
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('请输入非空密码。');
    expect(toggle).toBeChecked(); expect(input).toHaveFocus();
    expect(mutations()).toHaveLength(0);
    expect(configuration.profiles[0].password_enabled).toBe(true);
  });

  it('requires a fresh nonempty password for an already protected profile, including timeout-only edits', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    const input = activeFields().getByLabelText('访问密码');
    const toggle = screen.getByRole('switch', { name: '设置访问密码' });
    expect(toggle).toBeChecked(); expect(input).toHaveValue(''); expect(input).toBeRequired();
    expect(input).toHaveAttribute('autocomplete', 'new-password');
    fireEvent.change(activeFields().getByLabelText('空闲超时（秒）'), { target: { value: '240' } });
    fireEvent.submit(screen.getByRole('form'));
    expect(await screen.findByRole('alert')).toHaveTextContent('请输入非空密码。');
    expect(mutations()).toHaveLength(0);
    expect(toggle).toBeChecked(); expect(input).toBeEnabled(); expect(input).toHaveFocus();
    expect(activeFields().getByLabelText('空闲超时（秒）')).toHaveValue(240);
    fireEvent.change(input, { target: { value: ' replacement exact 🔑 ' } });
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('浏览器设置已保存。'));
    expect(input).toHaveValue('');
    expect(mutations()).toEqual([{ path: '/api/profiles/default', method: 'PATCH', body: { idle_timeout_seconds: 240, enabled: false, password: ' replacement exact 🔑 ' } }]);
  });

  it.each(['replace', 'remove'] as const)('can explicitly %s the saved password with the single control', async action => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    if (action === 'replace') fireEvent.change(activeFields().getByLabelText('访问密码'), { target: { value: 'new exact password' } });
    else await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    await userEvent.click(screen.getByRole('button', { name: '保存' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(mutations()[0].body.password).toBe(action === 'replace' ? 'new exact password' : null);
  });

  it('keeps the passwordless editor input mounted and clears it on pagehide and cancel', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    const input = activeFields().getByLabelText('访问密码');
    expect(input).toBeDisabled();
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    expect(activeFields().getByLabelText('访问密码')).toBe(input); expect(input).toBeEnabled();
    fireEvent.change(input, { target: { value: 'temporary' } });
    act(() => window.dispatchEvent(new Event('pagehide')));
    expect(input).toHaveValue('');
    fireEvent.change(input, { target: { value: 'temporary again' } });
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(input).toHaveValue(''); expect(mutations()).toHaveLength(0);
  });

  it('only deletes after explicit confirmation and supports cancellation', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('button', { name: '删除 work' }));
    expect(screen.getByRole('dialog')).toHaveTextContent('work：断开连接并永久删除此配置的全部浏览器数据，无法恢复。');
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(mutations()).toHaveLength(0);
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('button', { name: '删除 work' }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除配置' }));
    await waitFor(() => expect(screen.queryByRole('article', { name: '浏览器配置 work' })).toBeNull());
    expect(mutations()[0]).toEqual({ path: '/api/profiles/stable-id', method: 'DELETE', body: {} });
    expect(notify).toHaveBeenCalledWith('配置及其浏览器数据已永久删除。');
  });

  it('does not offer deletion for default', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    expect(screen.queryByRole('button', { name: '删除 default' })).toBeNull();
    expect(activeFields().getByLabelText('配置名称')).toBeDisabled();
    expect(mutations()).toHaveLength(0);
  });

  it.each([
    { status: 200, body: { ok: true }, message: '无法确认配置数据已删除，请稍后检查。' },
    { status: 200, body: { ok: true, browser_data_retained: true }, message: '无法确认配置数据已删除，请稍后检查。' },
    { status: 503, body: { error: '配置删除尚未完成，请稍后检查。' }, message: '配置删除尚未完成，请稍后检查。' },
  ])('keeps the deletion dialog open without success or automatic retry: %j', async ({ status, body, message }) => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('button', { name: '删除 work' }));
    vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除配置' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.getByRole('dialog')).toBeVisible();
    expect(notify).not.toHaveBeenCalled();
    expect(changed).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(vi.mocked(fetch).mock.calls[1][1]?.method).toBe('DELETE');
  });

  it('does not retry deletion after an uncertain network failure', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    await userEvent.click(screen.getByRole('button', { name: '删除 work' }));
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError('网络连接已中断。'));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '删除配置' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('网络连接已中断。');
    expect(screen.getByRole('dialog')).toBeVisible();
    expect(notify).not.toHaveBeenCalled();
    expect(changed).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('clears password DOM and ignores late mutation completion after unmount', async () => {
    const view = await mount(); await userEvent.click(screen.getByRole('button', { name: '添加配置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'secure' } });
    await userEvent.click(screen.getByRole('switch', { name: '设置访问密码' }));
    const input = activeFields().getByLabelText('访问密码'); fireEvent.change(input, { target: { value: 'transient' } });
    let release!: () => void; pending = new Promise<void>(resolve => { release = resolve; });
    await userEvent.click(screen.getByRole('button', { name: '保存' })); view.unmount();
    expect(input).toHaveValue(''); await act(async () => { release(); });
    expect(changed).not.toHaveBeenCalled(); expect(notify).not.toHaveBeenCalled();
  });
});

describe('manual runtime resource cleanup', () => {
  it('posts only on explicit click to the global administrative endpoint with CSRF and no viewer authority', async () => {
    window.history.replaceState({}, '', '/settings#browser');
    bindBrowserProfile('default');
    setProfileViewer({ viewer_id: 'viewer', viewer_token: 'browser-only-token', generation: 7, owner: true, idle_timeout_seconds: 180 });
    try {
      await mount();
      expect(mutations()).toHaveLength(0);
      await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
      await waitFor(() => expect(notify).toHaveBeenCalledWith('清理结果：已清理 2 项，待处理 0 项，跳过 1 项。', false));
      expect(mutations()).toEqual([{ path: '/api/runtime/cleanup', method: 'POST', body: {} }]);
      const [, init] = vi.mocked(fetch).mock.calls.at(-1)!;
      const headers = new Headers(init?.headers);
      expect(headers.get('X-CSRF-Token')).toBe('csrf');
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(headers.has('X-Viewer-Token')).toBe(false);
      expect(headers.has('X-Owner-Generation')).toBe(false);
      expect(calls.filter(call => call.method === 'GET')).toHaveLength(1);
      expect(changed).not.toHaveBeenCalled();
      expect(screen.getByRole('button', { name: '清理资源' })).toBeEnabled();
    } finally { setProfileViewer(null); }
  });

  it('prevents duplicate submissions while retaining the active draft, validation and DOM password', async () => {
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    const form = screen.getByRole('form');
    const fields = within(form);
    fireEvent.change(fields.getByLabelText('配置名称'), { target: { value: 'invalid name' } });
    fireEvent.change(fields.getByLabelText('空闲超时（秒）'), { target: { value: '700' } });
    await userEvent.click(fields.getByRole('switch', { name: '设置访问密码' }));
    const password = fields.getByLabelText('访问密码');
    fireEvent.change(password, { target: { value: 'unsaved profile secret' } });
    fireEvent.submit(form);
    expect(fields.getByRole('alert')).toHaveTextContent('配置名称无效。');
    let release!: () => void;
    pending = new Promise<void>(resolve => { release = resolve; });
    fireEvent.click(screen.getByRole('button', { name: '清理资源' }));
    const cleanup = screen.getByRole('button', { name: '正在清理…' });
    expect(cleanup).toBeDisabled(); expect(cleanup).toHaveAttribute('aria-busy', 'true');
    fireEvent.click(cleanup); fireEvent.submit(form);
    expect(mutations()).toHaveLength(1);
    expect(password).toHaveValue('unsaved profile secret');
    expect(password).toBeDisabled();
    expect(fields.getByRole('alert')).toHaveTextContent('配置名称无效。');
    await act(async () => { release(); });
    await waitFor(() => expect(screen.getByRole('button', { name: '清理资源' })).toBeEnabled());
    expect(screen.getByRole('form')).toBe(form);
    expect(fields.getByLabelText('配置名称')).toHaveValue('invalid name');
    expect(fields.getByLabelText('空闲超时（秒）')).toHaveValue(700);
    expect(fields.getByRole('switch', { name: '设置访问密码' })).toBeChecked();
    expect(password).toHaveValue('unsaved profile secret');
    expect(password).toBeEnabled();
    expect(fields.getByRole('alert')).toHaveTextContent('配置名称无效。');
    expect(calls.filter(call => call.method === 'GET')).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
    await userEvent.click(fields.getByRole('button', { name: '取消' }));
    expect(password).toHaveValue('');
  });

  it('reports pending cleanup as unfinished instead of successful completion', async () => {
    cleanupResponse = { ok: true, cleaned: 1, pending: 2, skipped: 3, browser_data_retained: true };
    await mount();
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('清理结果：已清理 1 项，待处理 2 项，跳过 3 项。', true));
    expect(mutations()).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
  });

  it.each([0, 1])('reports completed prior deletion while preserving pending=%s and an unrelated draft', async remaining => {
    cleanupResponse = { ok: true, cleaned: 2, pending: remaining, skipped: 1, deleted_profiles: 1, browser_data_retained: false };
    await mount();
    await userEvent.click(screen.getByRole('button', { name: 'work 配置设置' }));
    fireEvent.change(activeFields().getByLabelText('配置名称'), { target: { value: 'unsaved' } });
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith(`清理结果：已清理 2 项，待处理 ${remaining} 项，跳过 1 项。已完成此前请求的 1 个配置数据删除。`, remaining > 0));
    expect(activeFields().getByLabelText('配置名称')).toHaveValue('unsaved');
    expect(mutations()).toEqual([{ path: '/api/runtime/cleanup', method: 'POST', body: {} }]);
    expect(calls.filter(call => call.method === 'GET')).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
  });

  it('uses the server admission snapshot for cleanup counts despite concurrent profile changes', async () => {
    cleanupResponse = { ok: true, profile_count: 2, cleaned: 1, pending: 0, skipped: 1, deleted_profiles: 2, browser_data_retained: false, pending_details: [] };
    await mount();
    let release!: () => void;
    pending = new Promise<void>(resolve => {release = resolve;});
    fireEvent.click(screen.getByRole('button', {name: '清理资源'}));
    configuration.profiles = [];
    await act(async () => {release();});
    await waitFor(() => expect(notify).toHaveBeenCalledWith('清理结果：已清理 1 项，待处理 0 项，跳过 1 项。已完成此前请求的 2 个配置数据删除。', false));
    expect(calls.filter(call => call.method === 'GET')).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
  });

  it('shows concise deduplicated pending reasons without exposing internal profile IDs', async () => {
    cleanupResponse = { ok: true, cleaned: 1, pending: 4, skipped: 0, deleted_profiles: 0, browser_data_retained: true, pending_details: [
      { profile_id: 'internal-one', reason: '进程所有权无法确认。' },
      { profile_id: 'internal-two', reason: '进程所有权无法确认。' },
      { profile_id: 'internal-three', reason: '运行资源清理超时。' },
      { profile_id: 'internal-four', reason: '管理进程暂时不可用。' },
    ] };
    await mount();
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('清理结果：已清理 1 项，待处理 4 项，跳过 0 项。待处理原因：进程所有权无法确认；运行资源清理超时等。', true));
    expect(mutations()).toHaveLength(1);
  });

  it.each([401, 403, 503])('shows a %s failure and only locks Settings for expired administrative authentication', async status => {
    cleanupStatus = status;
    cleanupResponse = { error: '无法确认资源清理，请稍后重试。' };
    await mount();
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('无法确认资源清理，请稍后重试。', true));
    expect(unauthorized).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
    expect(mutations()).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: '清理资源' })).toBeEnabled();
  });

  it('does not retry an uncertain network failure', async () => {
    await mount();
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError('网络连接已中断。'));
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('网络连接已中断。', true));
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(changed).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: '清理资源' })).toBeEnabled();
  });

  it.each([
    null,
    {},
    ...[-1, 1.5, 4, null, '3'].map(profile_count => ({ ok: true, profile_count, cleaned: 2, pending: 0, skipped: 1, browser_data_retained: true })),
    { ok: true, cleaned: 2, pending: 0, skipped: 1, browser_data_retained: false },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: 0, browser_data_retained: false },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: 1, browser_data_retained: true },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: -1, browser_data_retained: false },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: 0.5, browser_data_retained: false },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: null, browser_data_retained: true },
    { ok: true, cleaned: 2, pending: 0, skipped: 1, deleted_profiles: '1', browser_data_retained: false },
    { ok: true, cleaned: -1, pending: 0, skipped: 1, browser_data_retained: true },
    { ok: true, cleaned: 2, pending: 0.5, skipped: 1, browser_data_retained: true },
    ...[null, {}, [{ profile_id: 'default', reason: '' }], [{ profile_id: 'default', reason: 123 }], [{ profile_id: '', reason: '未知原因' }], [{ profile_id: 'default', reason: 'x'.repeat(513) }]].map(pending_details => ({ ok: true, cleaned: 0, pending: 1, skipped: 0, browser_data_retained: true, pending_details })),
    { ok: true, cleaned: 1, pending: 0, skipped: 0, browser_data_retained: true, pending_details: [{ profile_id: 'default', reason: '运行资源清理超时。' }] },
  ])('does not claim success for an invalid cleanup acknowledgement: %j', async result => {
    cleanupResponse = result;
    await mount();
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith('无法确认资源清理结果，请稍后检查。', true));
    expect(mutations()).toHaveLength(1);
  });

  it.each([200, 401])('aborts cleanup on unmount and ignores a late %s response', async status => {
    cleanupStatus = status;
    if (status !== 200) cleanupResponse = { error: '设置会话已失效。' };
    const view = await mount();
    await userEvent.click(screen.getByRole('button', { name: 'default 配置设置' }));
    const password = activeFields().getByLabelText('访问密码');
    fireEvent.change(password, { target: { value: 'clear on unmount' } });
    let release!: () => void;
    pending = new Promise<void>(resolve => { release = resolve; });
    await userEvent.click(screen.getByRole('button', { name: '清理资源' }));
    const signal = vi.mocked(fetch).mock.calls.at(-1)![1]?.signal;
    expect(signal?.aborted).toBe(false);
    view.unmount();
    expect(signal?.aborted).toBe(true);
    expect(password).toHaveValue('');
    await act(async () => { release(); });
    expect(notify).not.toHaveBeenCalled();
    expect(unauthorized).not.toHaveBeenCalled();
    expect(changed).not.toHaveBeenCalled();
    expect(calls.filter(call => call.method === 'GET')).toHaveLength(1);
  });
});
