import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BackupDialogs } from './BackupDialogs';
import { setCsrfToken } from './api';

const preview = {token: 'exact-preview-token', key_count: 2, credential_count: 4, current_key_count: 3, current_credential_count: 5, warnings: ['不可合并']};
const backup = '{ "version": 1, "keys": [{"private_key":"test-only-sensitive-marker"}] }';
const flush = async () => { for (let i = 0; i < 15; i++) await Promise.resolve(); };
function fileWith(content = backup, name = 'backup.json') {
  return Object.assign(new File([content], name, {type: 'application/json'}), {text: vi.fn(async () => content)});
}
function fixture(override?: (path: string, init?: RequestInit) => Response | Promise<Response> | undefined) {
  const calls: {path: string; body?: Record<string, unknown>; init?: RequestInit}[] = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    calls.push({path, init, body: init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined});
    const custom = override?.(path, init); if (custom) return custom;
    if (path === '/api/restore/preview') return Response.json(preview);
    if (path === '/api/restore/confirm') return Response.json({ok: true});
    if (path === '/api/restore/backup' || path === '/api/backup') return new Response(backup, {headers: {'Content-Type': 'application/json'}});
    throw new Error('Unexpected path ' + path);
  });
  vi.stubGlobal('fetch', fetcher);
  const props = {csrfToken: 'csrf', onRestored: vi.fn(async () => {}), onUnauthorized: vi.fn(), notify: vi.fn()};
  const rendered = render(<BackupDialogs {...props} />);
  return {calls, fetcher, props, rendered};
}
async function upload(file = fileWith()) {
  fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
  fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [file]}});
  await screen.findByText('备份内：2 个验证器 · 4 个通行密钥');
}
async function allowRestore() {
  fireEvent.click(screen.getByRole('button', {name: '下载恢复前的安全备份'}));
  await screen.findByText('下载已发起。请确认文件已安全保存，再允许替换。');
  fireEvent.click(screen.getByRole('checkbox', {name: '我已保存恢复前的安全备份，并确认替换当前验证器'}));
}
beforeEach(() => {
  setCsrfToken('csrf');
  URL.createObjectURL = vi.fn(() => 'blob:test-download');
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('Material UI backup dialogs', () => {
  it('requires an explicit unencrypted-export warning confirmation and downloads privately', async () => {
    const f = fixture();
    fireEvent.click(screen.getByRole('button', {name: '导出验证器备份'}));
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveClass('MuiDialog-paper');
    expect(within(dialog).getByText(/未加密私钥/)).toBeVisible();
    expect(f.calls).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', {name: '下载未加密备份'}));
    await waitFor(() => expect(f.props.notify).toHaveBeenCalledWith(expect.stringContaining('备份下载已发起')));
    expect(f.calls).toEqual([expect.objectContaining({path: '/api/backup', init: expect.objectContaining({credentials: 'same-origin', cache: 'no-store', headers: expect.objectContaining({'X-CSRF-Token': 'csrf'})})})]);
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalledOnce();
    expect(document.querySelector('a[download]')).toBeNull();
  });
  it('rejects files over 2 MiB before reading or uploading', async () => {
    const f = fixture(); const selected = fileWith(); Object.defineProperty(selected, 'size', {value: 2 * 1024 * 1024 + 1});
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [selected]}});
    expect(await screen.findByText('备份文件不能超过 2 MiB。')).toBeVisible();
    expect(selected.text).not.toHaveBeenCalled(); expect(f.calls).toHaveLength(0);
  });
  it('rejects invalid JSON locally and does not expose source content in errors', async () => {
    const f = fixture();
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [fileWith('not-json-sensitive-marker')]}});
    expect(await screen.findByText('这不是有效的 JSON 备份文件，请重新选择。')).toBeVisible();
    expect(document.body.textContent).not.toContain('not-json-sensitive-marker'); expect(f.calls).toHaveLength(0);
  });
  it('requires preview, safety download and checkbox before sending the exact token and original bytes once', async () => {
    const f = fixture(); await upload();
    expect(f.calls[0]).toMatchObject({path: '/api/restore/preview', body: {backup}});
    expect(document.body.textContent).not.toContain('test-only-sensitive-marker');
    expect(document.body.textContent).not.toContain(preview.token);
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).toBeDisabled(); expect(screen.getByRole('button', {name: '替换当前验证器'})).toBeDisabled();
    fireEvent.click(screen.getByRole('button', {name: '替换当前验证器'}));
    expect(f.calls).toHaveLength(1);
    await allowRestore();
    expect(f.calls[1]).toMatchObject({path: '/api/restore/backup', body: {token: preview.token}});
    const confirm = screen.getByRole('button', {name: '替换当前验证器'});
    fireEvent.click(confirm); fireEvent.click(confirm);
    await waitFor(() => expect(f.props.onRestored).toHaveBeenCalledOnce());
    expect(f.calls[2]).toMatchObject({path: '/api/restore/confirm', body: {token: preview.token, backup}});
    expect(f.calls.filter(call => call.path === '/api/restore/confirm')).toHaveLength(1);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
  it('invalidates expired previews and requires a fresh file and safety download', async () => {
    const f = fixture(path => path === '/api/restore/backup' ? Response.json({error: 'expired'}, {status: 409}) : undefined);
    await upload(); fireEvent.click(screen.getByRole('button', {name: '下载恢复前的安全备份'}));
    expect(await screen.findByText(/预览已失效/)).toBeVisible();
    expect(screen.getByLabelText('选择验证器备份文件')).toBeEnabled();
    expect(screen.queryByRole('button', {name: '替换当前验证器'})).not.toBeInTheDocument();
    expect(f.calls.filter(call => call.path === '/api/restore/confirm')).toHaveLength(0);
  });
  it('never repeats a restore after a lost response and clears the consumed token', async () => {
    const f = fixture(path => path === '/api/restore/confirm' ? Promise.reject(new TypeError('connection dropped')) : undefined);
    await upload(); await allowRestore();
    const confirm = screen.getByRole('button', {name: '替换当前验证器'});
    fireEvent.click(confirm); fireEvent.click(confirm);
    expect(await screen.findByText(/恢复结果未能确认/)).toBeVisible();
    expect(screen.getByLabelText('选择验证器备份文件')).toHaveValue('');
    expect(screen.queryByRole('button', {name: '替换当前验证器'})).not.toBeInTheDocument();
    expect(f.calls.filter(call => call.path === '/api/restore/confirm')).toHaveLength(1);
    expect(f.props.onRestored).not.toHaveBeenCalled();
  });
  it('discards preview responses after cancellation and can open a clean new dialog', async () => {
    let resolve!: (value: Response) => void;
    const f = fixture(path => path === '/api/restore/preview' ? new Promise(done => { resolve = done; }) : undefined);
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [fileWith()]}});
    await act(flush);
    fireEvent.click(screen.getByRole('button', {name: '取消'}));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    await act(async () => { resolve(Response.json(preview)); await flush(); });
    expect(screen.getByLabelText('选择验证器备份文件')).toHaveValue('');
    expect(screen.queryByText('备份内：2 个验证器 · 4 个通行密钥')).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(f.calls).toHaveLength(1);
  });
  it('does not let an old cancelled operation unlock controls during a new upload', async () => {
    const resolvers: ((value: Response) => void)[] = [];
    fixture(path => path === '/api/restore/preview' ? new Promise(done => { resolvers.push(done); }) : undefined);
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [fileWith()]}}); await act(flush);
    fireEvent.click(screen.getByRole('button', {name: '取消'}));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [fileWith()]}}); await act(flush);
    await act(async () => { resolvers[0](Response.json(preview)); await flush(); });
    expect(screen.getByLabelText('选择验证器备份文件')).toBeDisabled();
    await act(async () => { resolvers[1](Response.json({...preview, token: 'second-token'})); await flush(); });
    expect(screen.getByRole('button', {name: '下载恢复前的安全备份'})).toBeEnabled();
  });
  it('clears pending preview state on session rotation and handles authorization failure', async () => {
    const f = fixture(); await upload();
    f.rendered.rerender(<BackupDialogs {...f.props} csrfToken="rotated" />);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    expect(screen.getByLabelText('选择验证器备份文件')).toHaveValue('');
    f.rendered.unmount();
    const unauthorized = fixture(path => path === '/api/backup' ? Response.json({error: 'locked'}, {status: 401}) : undefined);
    fireEvent.click(screen.getByRole('button', {name: '导出验证器备份'})); fireEvent.click(screen.getByRole('button', {name: '下载未加密备份'}));
    await waitFor(() => expect(unauthorized.props.onUnauthorized).toHaveBeenCalledOnce());
  });
  it('back-to-file clears safety-download and confirmation state', async () => {
    fixture(); await upload(); await allowRestore();
    fireEvent.click(screen.getByRole('button', {name: '返回选文件'}));
    expect(screen.getByLabelText('选择验证器备份文件')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('选择验证器备份文件'), {target: {files: [fileWith()]}});
    await screen.findByText('备份内：2 个验证器 · 4 个通行密钥');
    expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('checkbox')).toBeDisabled();
    expect(screen.getByRole('button', {name: '替换当前验证器'})).toBeDisabled();
  });
  it('clears restore state on pagehide so BFCache cannot restore approval or secrets', async () => {
    const f = fixture(); await upload(); await allowRestore();
    fireEvent(window, new Event('pagehide'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', {name: '从备份恢复'}));
    expect(screen.getByLabelText('选择验证器备份文件')).toHaveValue('');
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(f.calls.filter(call => call.path === '/api/restore/confirm')).toHaveLength(0);
  });

});
