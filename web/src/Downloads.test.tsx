import { StrictMode } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Downloads from './Downloads';
import { renderMaterial } from './test-render';

const file = {name: 'webauthn-helper.exe', url: '/downloads/webauthn-helper.exe', size: 1536, created_at: '2026-10-12T03:04:05Z'};
let files: typeof file[];
let unauthorized = vi.fn<() => void>();
beforeEach(() => {
  files = [{...file}]; unauthorized = vi.fn();
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({files})));
});
afterEach(() => vi.unstubAllGlobals());
const mount = () => renderMaterial(<Downloads onUnauthorized={unauthorized} />);

describe('Material download file list', () => {
  it('shows only filename, genuine creation time and readable size with native download links', async () => {
    const name = '<script>alert(1)</script> 空格 #.bin', url = '/downloads/%3Cscript%3Ealert%281%29%3C%2Fscript%3E%20%E7%A9%BA%E6%A0%BC%20%23.bin';
    files = [{...file, name, url}]; mount();
    const table = await screen.findByRole('table', {name: '下载文件'});
    expect(within(table).getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['文件名', '创建时间', '大小']);
    const link = within(table).getByRole('link', {name}); expect(link).toHaveAttribute('href', url); expect(link).toHaveAttribute('download', '');
    expect(link).not.toHaveAttribute('target'); expect(table.querySelector('script')).toBeNull();
    const time = table.querySelector('time')!;
    expect(time).toHaveAttribute('datetime', file.created_at);
    expect(time).toHaveTextContent(new Intl.DateTimeFormat('zh-CN', {year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).format(new Date(file.created_at)));
    expect(within(table).getByText('1.5 KiB')).toBeVisible();
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/downloads', expect.objectContaining({method: 'GET', credentials: 'same-origin', cache: 'no-store', signal: expect.any(AbortSignal)}));
  });
  it.each([null, 'invalid-date'])('shows an em dash for absent or invalid birthtime %s, never a modification time', async created_at => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({files: [{...file, created_at, modified_at: '2001-01-01T00:00:00Z'}]})));
    mount(); const table = await screen.findByRole('table');
    expect(within(table).getByText('—')).toBeVisible(); expect(table.querySelector('time')).toBeNull(); expect(table).not.toHaveTextContent('2001');
  });
  it.each([[0, '0 B'], [1, '1 B'], [1023, '1,023 B'], [1024, '1 KiB'], [1048576, '1 MiB'], [1073741824, '1 GiB']])('formats %s bytes as %s', async (size, formatted) => {
    files = [{...file, size: Number(size)}]; mount();
    expect(within(await screen.findByRole('table')).getByText(String(formatted))).toBeVisible();
  });
  it('keeps byte-encoded Unix URLs unchanged instead of recreating them from display names', async () => {
    files = [{...file, name: 'raw-�.bin', url: '/downloads/raw-%FF.bin'}]; mount();
    expect(await screen.findByRole('link', {name: 'raw-�.bin'})).toHaveAttribute('href', '/downloads/raw-%FF.bin');
  });
  it('keeps whitespace-only filenames visible and accessible and preserves whitespace in ordinary names', async () => {
    files = [{...file, name: '  ', url: '/downloads/%20%20'}, {...file, name: 'a  b.bin', url: '/downloads/a%20%20b.bin'}]; mount();
    const escaped = await screen.findByRole('link', {name: '"\\u0020\\u0020"'});
    expect(escaped).toHaveAttribute('href', '/downloads/%20%20');
    expect(screen.getByRole('link', {name: 'a b.bin'})).toHaveStyle({whiteSpace: 'break-spaces'});
  });
  it('keeps separate URLs for distinct byte names with the same display name', async () => {
    files = [{...file, name: '�', url: '/downloads/%FF'}, {...file, name: '�', url: '/downloads/%FE'}]; mount();
    const links = await screen.findAllByRole('link', {name: '�'});
    expect(links.map(link => link.getAttribute('href'))).toEqual(['/downloads/%FF', '/downloads/%FE']);
  });
  it('shows loading then the empty list without extra explanatory text', async () => {
    let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(done => {resolve = done;}))); mount();
    expect(screen.getByRole('status', {name: '正在读取下载列表'})).toBeVisible();
    await act(async () => resolve(Response.json({files: []})));
    expect(screen.getByText('暂无文件')).toBeVisible(); expect(screen.getAllByRole('row')).toHaveLength(2); expect(screen.queryByRole('link')).toBeNull();
  });
  it('retries a failed list request and fetches a fresh list on re-entry', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('无法读取下载目录')).mockImplementation(async () => Response.json({files})));
    const view = mount(); expect(await screen.findByRole('alert')).toHaveTextContent('无法读取下载目录');
    fireEvent.click(screen.getByRole('button', {name: '重试'})); expect(await screen.findByRole('link', {name: file.name})).toBeVisible();
    view.unmount(); files = [{...file, name: 'new.bin', url: '/downloads/new.bin'}]; mount();
    expect(await screen.findByRole('link', {name: 'new.bin'})).toBeVisible(); expect(screen.queryByRole('link', {name: file.name})).toBeNull();
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });
  it('hands a current 401 to the VNC scope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({error: 'locked'}, {status: 401}))); mount();
    await waitFor(() => expect(unauthorized).toHaveBeenCalledOnce()); expect(screen.queryByRole('alert')).toBeNull();
  });
  it.each([200, 401])('aborts and ignores a late %s response after leaving', async status => {
    let resolve!: (response: Response) => void; let signal!: AbortSignal;
    vi.stubGlobal('fetch', vi.fn((_input, init) => {signal = init.signal; return new Promise<Response>(done => {resolve = done;});}));
    const view = mount(); view.unmount(); expect(signal.aborted).toBe(true);
    await act(async () => {resolve(Response.json(status === 200 ? {files} : {error: 'locked'}, {status}));});
    expect(unauthorized).not.toHaveBeenCalled(); expect(screen.queryByRole('link')).toBeNull();
  });
  it('ignores the abandoned StrictMode request when the current request succeeds', async () => {
    let resolve!: (response: Response) => void;
    vi.stubGlobal('fetch', vi.fn().mockImplementationOnce(() => new Promise<Response>(done => {resolve = done;})).mockImplementation(async () => Response.json({files})));
    render(<StrictMode><Downloads onUnauthorized={unauthorized} /></StrictMode>);
    expect(await screen.findByRole('link', {name: file.name})).toBeVisible();
    await act(async () => resolve(Response.json({error: 'old login expired'}, {status: 401})));
    expect(unauthorized).not.toHaveBeenCalled(); expect(screen.getByRole('link', {name: file.name})).toBeVisible();
  });
  it.each(['javascript:alert(1)', '//other.example/file', '/downloads/../api/logout', '/downloads/%2E%2E/api/logout', '/downloads/file?token=secret', '/downloads/\\example'])('rejects an unsafe download URL %s', async url => {
    files = [{...file, url}]; mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('无法读取下载列表'); expect(screen.queryByRole('link')).toBeNull();
  });
});
