import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TextField } from '@mui/material';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import KeyForm from './KeyForm';
import { ClipboardSync } from './ClipboardSync';
import { renderMaterial } from './test-render';
import type { AppStatus, VirtualKey } from './types';

const status: AppStatus = { csrf_token: 'polish-csrf', vnc_authenticated: true, settings_authenticated: true, vnc_password_enabled: false, settings_password_enabled: false, engine_connected: true };
const key: VirtualKey = { id: 'polish-key', name: 'Review key', provider_label: 'Local provider', enabled: true, attachment: 'platform', presence_timeout_seconds: 120, model_aaguid: '00000000-0000-0000-0000-000000000000', resident_key_supported: true, attestation_mode: 'none', credentials: [{ credential_id: 'copy-this-id', rp_id: 'example.com', user_name: 'alice' }] };
const copy = vi.fn();
let eventController: ReadableStreamDefaultController<Uint8Array> | undefined;

class ClipboardSocket {
  static OPEN = 1;
  static instances: ClipboardSocket[] = [];
  readyState = 1;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  send = vi.fn();
  close = vi.fn();
  constructor(public url: URL) { ClipboardSocket.instances.push(this); }
  receive(frame: unknown) { this.onmessage?.({ data: JSON.stringify(frame) }); }
}

function mountClipboard() {
  vi.stubGlobal('WebSocket', ClipboardSocket);
  vi.stubGlobal('isSecureContext', true);
  ClipboardSocket.instances = [];
  const readText = vi.fn().mockRejectedValue(new Error('denied'));
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy, readText } });
  renderMaterial(<ClipboardSync connected copyAgain={vi.fn()} />);
  return { socket: ClipboardSocket.instances[0], readText };
}

beforeEach(() => {
  copy.mockReset().mockResolvedValue(undefined);
  eventController = undefined;
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: copy } });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path === '/api/browser/reconnect') {
      if (!init?.method || init.method === 'GET') return Response.json({operation_scope: '79c046fa-b06a-4e27-b369-5ac27558655a', operation_sequence: '1'});
      const action = JSON.parse(String(init.body));
      return Response.json({ok: true, ...action, restarted: action.action === 'restart', engine_ready: true, window_count: 1});
    }
    if (path === '/api/browser/mode') return Response.json({mode: 'software', state: 'software', generation: 1, active: false, owned: false, control_connected: true});
    if (path === '/api/requests/events') {
      const stream = new ReadableStream<Uint8Array>({ start(controller) {
        eventController = controller;
        controller.enqueue(new TextEncoder().encode('event: snapshot\ndata: {"requests":[],"connected":true,"cursor":"polish:1","events":[]}\n\n'));
        init?.signal?.addEventListener('abort', () => { try { controller.close(); } catch {} });
      } });
      return new Response(stream, { headers: { 'Content-Type': 'text/event-stream' } });
    }
    const data = path === '/api/status' || path === '/api/security' ? status : path === '/api/keys' ? { keys: [key] } : path === '/api/runtime' ? { state: 'ready', sandbox_enabled: false } : { ok: true };
    return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
  }));
});

async function mountApp() {
  window.history.replaceState({}, '', '/settings#authenticator');
  renderMaterial(<App />);
  await screen.findByRole('heading', { name: 'Review key' });
}

async function openCredential() {
  await mountApp();
  await userEvent.click(screen.getByRole('button', { name: 'RP ID：example.com，用户名：alice' }));
  return screen.getByRole('button', { name: '复制凭证 ID（Base64）' });
}

describe('UI polish regressions', () => {
  it('keeps ordinary Settings input text and all outlined labels at normal Material typography', () => {
    const properties = ['font-size', 'font-family', 'font-weight', 'letter-spacing', 'line-height'];
    const typography = (element: Element) => properties.map(property => getComputedStyle(element).getPropertyValue(property));
    const reference = renderMaterial(<ThemeProvider theme={createTheme({cssVariables: true})}><TextField label="默认输入框" size="small" /></ThemeProvider>);
    const defaultInput = screen.getByRole('textbox', {name: '默认输入框'});
    const defaultRoot = typography(defaultInput.closest('.MuiInputBase-root')!);
    const defaultText = typography(defaultInput);
    const defaultLabel = typography(reference.container.querySelector('.MuiInputLabel-root')!);
    reference.unmount();
    const {container} = renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} />);
    for (const name of [/^昵称/, /^Provider/]) {
      const input = screen.getByRole('textbox', {name});
      expect(typography(input.closest('.MuiInputBase-root')!)).toEqual(defaultRoot);
      expect(typography(input)).toEqual(defaultText);
      expect(input.style.fontFamily).toBe('');
      expect(input.style.fontSize).toBe('');
    }
    for (const label of container.querySelectorAll('.MuiInputLabel-root')) expect(typography(label)).toEqual(defaultLabel);
  });

  it('keeps zero reset icon-only, accessible and next to the random generator', async () => {
    const dirty = vi.fn();
    renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} onDirtyChange={dirty} />);
    expect(screen.getByRole('textbox', { name: /^Provider/ })).toHaveAttribute('placeholder', 'YubiKey 5A');
    expect(screen.getByRole('textbox', { name: /^Provider/ })).toHaveValue('');
    const random = screen.getByRole('button', { name: '随机生成 AAGUID' });
    const reset = screen.getByRole('button', { name: '重置为全零 AAGUID' });
    expect(random.parentElement).toBe(reset.parentElement);
    expect(reset.textContent).toBe('');
    expect(reset.querySelector('svg')).not.toBeNull();
    await userEvent.click(random);
    dirty.mockClear();
    await userEvent.click(reset);
    expect(screen.getByRole('textbox', { name: /^AAGUID/ })).toHaveValue('00000000-0000-0000-0000-000000000000');
    expect(dirty).toHaveBeenCalledWith(true);
  });

  it('shows a disabled fixed OU only for generated certificate identities', async () => {
    renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole('combobox', { name: '证明方式' }));
    await userEvent.click(screen.getByRole('option', { name: /证书证明/ }));
    const ou = screen.getByRole('textbox', { name: '组织单位（OU）' });
    expect(ou).toBeDisabled();
    expect(ou).toHaveValue('Authenticator Attestation');
    await userEvent.click(screen.getByRole('combobox', { name: '证书来源' }));
    await userEvent.click(screen.getByRole('option', { name: '导入证书' }));
    expect(screen.queryByRole('textbox', { name: '组织单位（OU）' })).not.toBeInTheDocument();
  });

  it('groups delete with edit and keeps the exact confirmation copy', async () => {
    await mountApp();
    const edit = screen.getByRole('button', { name: '编辑设置' });
    const remove = screen.getByRole('button', { name: '删除' });
    expect(edit.parentElement).toBe(remove.parentElement);
    await userEvent.click(remove);
    const dialog = screen.getByRole('dialog', { name: '删除“Review key”？' });
    expect(within(dialog).getByText('删除验证器会同时移除其通行密钥。')).toBeVisible();
    expect(vi.mocked(fetch).mock.calls.every(([path, init]) => !init?.method || init.method === 'GET'
      || (String(path) === '/api/browser/reconnect' && init.method === 'POST' && JSON.parse(String(init.body)).action === 'ensure'))).toBe(true);
  });

  it('hides a success after three seconds and restarts the timer for identical notices', async () => {
    const button = await openCredential();
    vi.useFakeTimers();
    await act(async () => { fireEvent.click(button); });
    const message = '凭证 ID（Base64）已复制。';
    expect(screen.getByText(message)).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(2000); });
    await act(async () => { fireEvent.click(button); });
    await act(async () => { vi.advanceTimersByTime(2999); });
    expect(screen.getByText(message)).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(1); });
    await act(async () => { vi.advanceTimersByTime(300); });
    expect(screen.queryByText(message)).not.toBeInTheDocument();
    expect(copy).toHaveBeenCalledTimes(2);
    expect(copy).toHaveBeenLastCalledWith('copy-this-id');
  });

  it('keeps errors visible until dismissed', async () => {
    const button = await openCredential();
    copy.mockRejectedValueOnce(new Error('Clipboard permission denied'));
    vi.useFakeTimers();
    await act(async () => { fireEvent.click(button); });
    await act(async () => { vi.advanceTimersByTime(60000); });
    const error = screen.getByRole('alert');
    expect(error).toHaveTextContent('Clipboard permission denied');
    fireEvent.click(within(error).getByRole('button', { name: 'Close' }));
    await act(async () => { vi.advanceTimersByTime(300); });
    expect(screen.queryByText('Clipboard permission denied')).not.toBeInTheDocument();
  });

  it('keeps independent control status available through navigation collapse and stream disconnect', async () => {
    renderMaterial(<App />);
    const connection = await screen.findByRole('status', { name: '验证事件已连接' });
    expect(connection.closest('#browser-controls')).not.toBeNull();
    expect(document.querySelectorAll('#request-connection')).toHaveLength(1);
    expect(document.querySelector('.request-status #request-connection')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '收起导航' }));
    expect(connection).toBeVisible();
    await userEvent.click(screen.getByRole('button', {name: '收起控制栏'}));
    expect(connection.closest('#browser-control-content')).toHaveAttribute('hidden');
    await act(async () => { eventController!.error(new Error('Event stream disconnected')); });
    await waitFor(() => expect(connection).toHaveAttribute('data-state', 'disconnected'));
    await userEvent.click(screen.getByRole('button', { name: '展开导航' }));
    await userEvent.click(screen.getByRole('button', {name: '展开控制栏'}));
    expect(connection.closest('#browser-control-content')).not.toHaveAttribute('hidden');
    expect(connection).toHaveAttribute('tabindex', '0');
    expect(connection).toHaveAttribute('aria-live', 'polite');
    expect(connection).toHaveAttribute('aria-label');
  });

  it('keeps repeated successful clipboard copies silent', async () => {
    vi.useFakeTimers();
    const { socket } = mountClipboard();
    await act(async () => { socket.receive({ type: 'copy', id: 'first', text: 'one' }); });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () => { vi.advanceTimersByTime(2000); });
    await act(async () => { socket.receive({ type: 'copy', id: 'second', text: 'two' }); });
    await act(async () => { vi.advanceTimersByTime(2999); });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(copy).toHaveBeenCalledTimes(2);
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'copy_result', id: 'second' }));
  });

  it('keeps only a permission retry icon after a silent successful copy', async () => {
    vi.useFakeTimers();
    const { socket, readText } = mountClipboard();
    await act(async () => { socket.receive({ type: 'copy', id: 'copy', text: 'value' }); });
    await act(async () => { vi.advanceTimersByTime(2000); });
    await act(async () => { socket.receive({ type: 'read', id: 'needs-permission' }); });
    await act(async () => { vi.advanceTimersByTime(60000); });
    expect(screen.getByRole('button', { name: '粘贴剪贴板内容' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/允许本次粘贴/)).not.toBeInTheDocument();
    expect(readText).toHaveBeenCalledTimes(1);
    expect(copy).toHaveBeenCalledTimes(1);
  });

  it('keeps oversized clipboard paste errors visible without retrying the read', async () => {
    vi.useFakeTimers();
    const { socket, readText } = mountClipboard();
    readText.mockResolvedValueOnce('x'.repeat(1024 * 1024 + 1));
    await act(async () => { socket.receive({ type: 'read', id: 'oversized' }); });
    await act(async () => { vi.advanceTimersByTime(60000); });
    expect(screen.getByRole('img', {name: '剪贴板文本超过 1 MiB'})).toBeVisible(); expect(screen.queryByRole('alert')).toBeNull();
    expect(readText).toHaveBeenCalledTimes(1);
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'read_result', id: 'oversized', error: 'too_large' }));
  });
});
