import { StrictMode } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BrowserControls } from './BrowserControls';
import { setCsrfToken } from './api';
import { renderMaterial } from './test-render';

class Socket {
  static instances: Socket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;
  send = vi.fn(); close = vi.fn(() => { this.readyState = 3; });
  open() { this.readyState = 1; this.onopen?.(); }
  constructor(public url: string) { Socket.instances.push(this); }
}
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const advance = async (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); await flush(); });
function expectUnauthenticatedSockets(count: number) {
  expect(Socket.instances).toHaveLength(count);
  for (const socket of Socket.instances) expect(socket.send).not.toHaveBeenCalled();
}
const statusFrame = (state: string) => JSON.stringify({type: 'status', state, message: `Helper ${state}`});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return {promise, resolve};
}
function fixture(override?: (path: string, init?: RequestInit) => Promise<Response> | undefined, initiallyActive = false, afterResponse?: (path: string, init: RequestInit | undefined, response: Response) => Promise<Response> | Response) {
  Socket.instances = []; vi.stubGlobal('WebSocket', Socket); setCsrfToken('csrf');
  let active = initiallyActive, generation = 1;
  let ready = false;
  let token = 0;
  const snapshot = () => ({mode: active ? 'native' : 'software', state: active ? (ready ? 'native' : 'switching') : 'software', generation, active, owned: active, control_connected: true});
  const server = async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input); const response = override?.(path, init); if (response) return response;
    if (path === '/api/browser/mode' && init?.method === 'GET') return Response.json(snapshot());
    if (path === '/api/browser/mode' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body));
      if (body.expected_generation !== generation || active) return Response.json({error: 'lease conflict'}, {status: 409});
      active = body.mode === 'native'; generation++;
      return Response.json({...snapshot(), session_id: `session-${generation}`, token: `secret-${++token}`, expires_in_ms: 120000, helper_url: 'ws://127.0.0.1:10233'});
    }
    if (path === '/api/helper/status') return Response.json({...snapshot(), remaining_ms: 120000});
    if (path === '/api/helper/stop') {
      if (!active || JSON.parse(String(init?.body)).session_id !== `session-${generation}`) return Response.json({error: 'stale lease'}, {status: 409});
      active = false; generation++; return Response.json({ok: true});
    }
    if (path === '/api/helper/refresh') return Response.json({session_id: `session-${generation}`, token: `secret-${++token}`, remaining_ms: 120000});
    if (path === '/api/browser/mode/renew') return Response.json({...snapshot(), remaining_ms: 120000});
    return Response.json({ok: true});
  };
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const response = await server(input, init);
    return afterResponse ? afterResponse(String(input), init, response) : response;
  });
  vi.stubGlobal('fetch', fetcher);
  const props = {authConnection: {state: 'connected' as const, message: '验证事件已连接'}, connected: true, reconnecting: false, onReconnect: vi.fn(), onCtrlAltDelete: vi.fn(), onFullscreen: vi.fn(), onUnauthorized: vi.fn()};
  const rendered = renderMaterial(<StrictMode><BrowserControls {...props} /></StrictMode>);
  const calls = (path: string, method?: string) => fetcher.mock.calls.filter(([url, init]) => String(url) === path && (!method || init?.method === method));
  return {rendered, calls, fetcher, props, snapshot, setReady: (value: boolean) => {ready = value;}, clearLease: () => {active = false; generation++;}};
}
async function select(name: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', {name: '模式'}));
  fireEvent.click(screen.getByRole('option', {name}));
  await act(flush);
}
function stylesFor(element: Element) {
  return Array.from(document.styleSheets).flatMap(sheet => Array.from(sheet.cssRules))
    .filter((rule): rule is CSSStyleRule => rule instanceof CSSStyleRule && Array.from(element.classList).some(name => rule.selectorText === `.${name}`))
    .map(rule => rule.style);
}
function responsiveStylesFor(element: Element) {
  const styles: {media: string; style: CSSStyleDeclaration}[] = [];
  const visit = (rules: CSSRuleList, media = '') => {
    for (const rule of Array.from(rules)) {
      if (rule instanceof CSSStyleRule) {
        // Ignore vendor pseudo-selectors that jsdom cannot parse.
        try { if (element.matches(rule.selectorText)) styles.push({media, style: rule.style}); } catch { /* unsupported selector */ }
      } else if ('cssRules' in rule) {
        visit((rule as CSSGroupingRule).cssRules, rule instanceof CSSMediaRule ? rule.conditionText : media);
      }
    }
  };
  for (const sheet of Array.from(document.styleSheets)) visit(sheet.cssRules);
  return styles;
}
// These are CSS/DOM contracts; jsdom cannot measure the panel's rendered height.
function expectPanelSpacing(bar: HTMLElement) {
  expect(bar).toHaveStyle({boxSizing: 'border-box', paddingTop: '8px', paddingBottom: '8px', paddingLeft: '12px', paddingRight: '12px'});
  expect(stylesFor(bar.firstElementChild!).map(style => style.gap)).toContain('calc(1.5 * var(--mui-spacing))');
  const toolbar = bar.querySelector('.browser-control-toolbar')!;
  expect(toolbar).toHaveStyle({height: '32px', minHeight: '32px', flexWrap: 'nowrap'});
  const chrome = toolbar.firstElementChild!;
  expect(chrome).toHaveStyle({height: '32px', flexShrink: '0'});
  for (const button of toolbar.querySelectorAll('button')) {
    expect(button).toHaveStyle({height: '32px', width: '32px'});
  }
}

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('global browser mode controls', () => {
  it('keeps software on one 32px toolbar with symmetric padding and no empty secondary-row spacing', async () => {
    fixture(); await act(flush);
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const secondary = document.getElementById('browser-control-secondary-content')!;
    expectPanelSpacing(bar); expect(bar).toHaveStyle({height: '50px'});
    expect(secondary).toBeEmptyDOMElement(); expect(secondary).toHaveAttribute('hidden');
    expect(secondary).toHaveStyle({display: 'none'});
    expect(document.getElementById('browser-control-content')).not.toHaveAttribute('hidden');
    expect(screen.getByRole('combobox', {name: '模式'})).toBeVisible();
  });
  it.each(['软件模拟', '原生中继'])('collapses %s to the same padded move/expand chrome without changing mode or transport', async modeName => {
    const f = fixture(); await act(flush);
    if (modeName === '原生中继') await select(modeName);
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const rows = bar.firstElementChild!;
    const toolbar = bar.querySelector('.browser-control-toolbar')!;
    const chrome = toolbar.firstElementChild!;
    const main = document.getElementById('browser-control-content')!;
    const secondary = document.getElementById('browser-control-secondary-content')!;
    const helperInput = screen.queryByRole('textbox', {name: '辅助程序连接地址'});
    const modePosts = f.calls('/api/browser/mode', 'POST').length;
    fireEvent.click(screen.getByRole('button', {name: '收起控制栏'}));
    expectPanelSpacing(bar); expect(bar).toHaveStyle({width: 'auto', height: '50px'});
    for (const content of [main, secondary]) {
      expect(content).toHaveAttribute('hidden'); expect(content).toHaveStyle({display: 'none'});
    }
    expect(Array.from(rows.children).filter(child => getComputedStyle(child).display !== 'none')).toEqual([toolbar]);
    expect(Array.from(toolbar.children).filter(child => getComputedStyle(child).display !== 'none')).toEqual([chrome]);
    expect(screen.getAllByRole('button').map(button => button.getAttribute('aria-label'))).toEqual(['移动控制栏', '展开控制栏']);
    expect(screen.getByRole('button', {name: '展开控制栏'})).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('button', {name: '展开控制栏'})).toHaveAttribute('aria-controls', `${main.id} ${secondary.id}`);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(modePosts);
    expect(f.calls('/api/helper/stop')).toHaveLength(0);
    if (helperInput) {
      expect(secondary).toContainElement(helperInput); expect(helperInput).not.toBeVisible();
      expect(Socket.instances).toHaveLength(1); expect(Socket.instances[0].close).not.toHaveBeenCalled();
    }
    fireEvent.click(screen.getByRole('button', {name: '展开控制栏'}));
    expectPanelSpacing(bar); expect(bar).toHaveStyle({height: modeName === '软件模拟' ? '50px' : 'auto'});
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent(modeName);
    if (helperInput) expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBe(helperInput);
    else expect(secondary).toHaveStyle({display: 'none'});
  });
  it('keeps software errors accessible outside the fixed-height panel, including while collapsed', async () => {
    let fail = true;
    fixture((path, init) => fail && path === '/api/browser/mode' && init?.method === 'GET' ? Promise.reject(new Error('mode unavailable')) : undefined);
    await act(flush);
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const secondary = document.getElementById('browser-control-secondary-content')!;
    expectPanelSpacing(bar); expect(bar).toHaveStyle({height: '50px'});
    expect(secondary).toBeEmptyDOMElement(); expect(secondary).toHaveAttribute('hidden'); expect(secondary).toHaveStyle({display: 'none'});
    expect(bar).not.toContainElement(screen.getByRole('alert'));
    expect(screen.getByRole('alert')).toHaveTextContent('mode unavailable');
    fireEvent.click(screen.getByRole('button', {name: '收起控制栏'}));
    expectPanelSpacing(bar); expect(bar).toHaveStyle({height: '50px'}); expect(screen.getByRole('alert')).toBeVisible();
    expect(secondary).toHaveStyle({display: 'none'});
    fail = false; fireEvent.click(screen.getByRole('button', {name: '重试'})); await act(flush);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(secondary).toBeEmptyDOMElement(); expect(secondary).toHaveAttribute('hidden'); expect(secondary).toHaveStyle({display: 'none'});
    fireEvent.click(screen.getByRole('button', {name: '展开控制栏'}));
    expectPanelSpacing(bar);
  });
  it('authors a single-line responsive toolbar with scrollable controls and room above the outlined notch', async () => {
    fixture(); await act(flush);
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    const toolbar = bar.querySelector('.browser-control-toolbar')!;
    const content = document.getElementById('browser-control-content')!;
    const scroller = screen.getByRole('group', {name: '浏览器操作'});
    const row = bar.querySelector('.browser-control-main-row')!;
    expect(toolbar).toHaveStyle({height: '32px', minHeight: '32px', flexWrap: 'nowrap'});
    expect(content).toHaveStyle({height: '32px', minWidth: '0'});
    expect(scroller).toHaveAttribute('tabindex', '0');
    expect(scroller).toHaveStyle({height: '44px', marginTop: '-6px', marginBottom: '-6px', paddingTop: '6px', paddingBottom: '6px', overflowX: 'auto', overflowY: 'hidden'});
    expect(row).toHaveStyle({height: '32px', width: 'max-content', minWidth: '100%'});
    expect(scroller).toContainElement(screen.getByRole('combobox', {name: '模式'}));
    for (const name of ['重新连接', 'Ctrl+Alt+Delete', '全屏']) expect(scroller).toContainElement(screen.getByRole('button', {name}));
    expect(scroller).not.toContainElement(screen.getByRole('button', {name: '移动控制栏'}));
    for (const element of [toolbar, row]) {
      const wrapping = responsiveStylesFor(element).map(({style}) => style.flexWrap).filter(Boolean);
      expect(wrapping).not.toContain('wrap');
    }
    // jsdom does not evaluate viewport media queries. Verify both authored
    // breakpoint declarations instead of pretending to measure narrow layout.
    const status = screen.getByRole('status', {name: '验证事件已连接'});
    const label = status.querySelector('.connection-label')!;
    const displayRules = responsiveStylesFor(label).filter(({style}) => style.display);
    expect(displayRules.map(({media, style}) => [media.replaceAll(' ', ''), style.display])).toEqual(expect.arrayContaining([
      ['(min-width:0px)', 'none'], ['(min-width:600px)', 'inline'],
    ]));
    expect(status).toHaveAttribute('aria-label', '验证事件已连接');
  });
  it('uses icon-only actions and independent movement/collapse without ending transport', async () => {
    const f = fixture(); await act(flush);
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    expect(bar).toHaveStyle({left: '16px'});
    const row = bar.querySelector('.browser-control-main-row')!;
    expect(row.firstElementChild).toContainElement(screen.getByRole('combobox', {name: '模式'}));
    for (const name of ['重新连接', 'Ctrl+Alt+Delete', '全屏']) {
      const button = screen.getByRole('button', {name}); expect(button).toHaveTextContent(/^$/); expect(button.querySelector('svg')).toBeInTheDocument(); fireEvent.click(button);
    }
    expect(f.props.onReconnect).toHaveBeenCalledOnce(); expect(f.props.onCtrlAltDelete).toHaveBeenCalledOnce(); expect(f.props.onFullscreen).toHaveBeenCalledOnce();
    await select('原生中继'); expect(Socket.instances).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', {name: '收起控制栏'})); expect(document.getElementById('browser-control-content')).toHaveAttribute('hidden');
    expect(Socket.instances[0].close).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', {name: '展开控制栏'})); expect(screen.getByRole('textbox', {name: '辅助程序连接地址'})).toBeVisible();
    expect(Socket.instances).toHaveLength(1);
  });
  it('uses compact floating-field typography and lets the helper row span the padded control panel', async () => {
    fixture(); await act(flush); await select('原生中继');
    const bar = screen.getByRole('region', {name: '浏览器控制栏'});
    expectPanelSpacing(bar);
    expect(screen.getByRole('combobox', {name: '模式'}).closest('.MuiInputBase-root')).toHaveClass('MuiInputBase-sizeSmall');
    const toolbar = bar.querySelector('.browser-control-toolbar')!;
    const secondary = document.getElementById('browser-control-secondary-content')!;
    expect(secondary).not.toHaveAttribute('hidden'); expect(secondary).toHaveStyle({display: 'flex'});
    expect(stylesFor(secondary).map(style => style.gap)).toContain('calc(1.5 * var(--mui-spacing))');
    expect(secondary.parentElement).toBe(toolbar.parentElement);
    expect(secondary).toContainElement(bar.querySelector('.browser-control-native-row') as HTMLElement);
    expect(bar.querySelector('.browser-control-native-row')).not.toHaveAttribute('title');
    expect(secondary.querySelector('.browser-control-toolbar')).toBeNull();
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    expect(getComputedStyle(input).fontFamily).toContain('monospace');
    expect(input).toHaveStyle({fontSize: '12px', height: '32px', boxSizing: 'border-box'});
    expect(input.closest('.MuiInputBase-root')).toHaveStyle({fontSize: '12px', height: '32px'});
    fireEvent.click(screen.getByRole('button', {name: '收起控制栏'}));
    expect(secondary).toHaveAttribute('hidden'); expect(document.getElementById('browser-control-content')).toHaveAttribute('hidden');
    expect(Socket.instances[0].close).not.toHaveBeenCalled();
  });
  it('starts native globally without create/get request IDs and confirms both helper and engine before green', async () => {
    vi.useFakeTimers(); const f = fixture(); await act(flush); await select('原生中继');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expect(JSON.parse(String(f.calls('/api/browser/mode', 'POST')[0][1]?.body))).toEqual({mode: 'native', expected_generation: 1});
    expect(f.calls('/api/helper/start')).toHaveLength(0);
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'}); expect(input).toHaveValue('ws://127.0.0.1:10233'); expect(getComputedStyle(input).fontFamily).toContain('monospace');
    const connect = screen.getByRole('button', {name: '连接'}); expect(connect).toBeEnabled();
    const ws = Socket.instances[0]; act(() => ws.onopen?.()); expect(connect).toBeEnabled();
    act(() => ws.onmessage?.({data: statusFrame('paired')})); expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    f.setReady(true); await advance(1000); expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
    expect(connect).toBeEnabled(); expect(input).toBeEnabled(); expect(input).toHaveAttribute('aria-invalid', 'false');
    expect(document.body).not.toHaveTextContent('secret-1');
  });
  it('keeps rejected pairing neutral and retries edited addresses automatically', async () => {
    vi.useFakeTimers(); const f = fixture(); await act(flush); await select('原生中继');
    const ws = Socket.instances[0]; act(() => ws.onopen?.()); act(() => ws.onmessage?.({data: statusFrame('denied')})); await act(flush);
    expect(screen.queryByRole('alert')).toBeNull();
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'}); expect(input).toBeEnabled(); expect(input).toHaveAttribute('aria-invalid', 'false');
    fireEvent.change(input, {target: {value: 'localhost:19001'}}); await advance(199); expect(Socket.instances).toHaveLength(1);
    await advance(1); expect(Socket.instances).toHaveLength(2); expect(Socket.instances[1].url).toBe('ws://localhost:19001/');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
  });
  it('constructs the actual helper socket before posting the backend native acquisition', async () => {
    let socketsAtAcquisition: Socket[] = [];
    const f = fixture((path, init) => {
      if (path === '/api/browser/mode' && init?.method === 'POST') socketsAtAcquisition = [...Socket.instances];
      return undefined;
    });
    await act(flush); await select('原生中继');
    expect(socketsAtAcquisition).toHaveLength(1); expect(Socket.instances).toEqual(socketsAtAcquisition);
    expectUnauthenticatedSockets(1); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    act(() => socketsAtAcquisition[0].open());
    expect(socketsAtAcquisition[0].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-1', session_id: 'session-2'}));
  });
  it('keeps address back-and-forth replacements isolated from stale callbacks and closes them all on mode exit', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let hold = true;
    const f = fixture(undefined, false, (path, init, value) => {
      if (hold && path === '/api/browser/mode' && init?.method === 'POST') { hold = false; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    const original = Socket.instances[0]; const oldOpen = original.onopen!; const oldClose = original.onclose!;
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    fireEvent.change(input, {target: {value: 'localhost:19001'}}); await advance(200);
    const alternate = Socket.instances[1]; const alternateOpen = alternate.onopen!; const alternateError = alternate.onerror!;
    fireEvent.change(input, {target: {value: 'ws://127.0.0.1:10233'}}); await advance(200);
    const current = Socket.instances[2];
    expectUnauthenticatedSockets(3);
    expect(Socket.instances.map(socket => socket.url)).toEqual(['ws://127.0.0.1:10233/', 'ws://localhost:19001/', 'ws://127.0.0.1:10233/']);
    expect(original.close).toHaveBeenCalledOnce(); expect(alternate.close).toHaveBeenCalledOnce();
    act(() => { oldOpen(); oldClose(); alternateOpen(); alternateError(); });
    expectUnauthenticatedSockets(3); expect(current.close).not.toHaveBeenCalled();
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(Socket.instances).toEqual([original, alternate, current]);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    expect(f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id)).toEqual(['session-2']);
    act(() => current.open());
    expect(current.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-2', session_id: 'session-4'}));
    const ownedOpen = current.onopen!; const ownedMessage = current.onmessage!;
    await select('软件模拟');
    for (const socket of Socket.instances) expect(socket.close).toHaveBeenCalledOnce();
    const stopIds = f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id);
    expect(stopIds).toContain('session-4'); expect(stopIds.every(id => ['session-2', 'session-4'].includes(id))).toBe(true);
    act(() => {
      oldOpen(); oldClose(); alternateOpen(); alternateError(); ownedOpen();
      ownedMessage({data: statusFrame('paired')});
      ownedMessage({data: JSON.stringify({type: 'advertisement', uuid: '0000fff9-0000-1000-8000-00805f9b34fb', data: 'AQID'})});
    });
    await advance(5000);
    expect(Socket.instances).toHaveLength(3); expect(original.send).not.toHaveBeenCalled(); expect(alternate.send).not.toHaveBeenCalled();
    expect(current.send).toHaveBeenCalledTimes(1); expect(f.calls('/api/helper/advertisement')).toHaveLength(0);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2); expect(f.snapshot().active).toBe(false);
  });
  it.each(['GET', 'POST'] as const)('constructs and retries unauthenticated sockets every second while acquisition %s stalls', async method => {
    vi.useFakeTimers(); let hold = false;
    const f = fixture((path, init) => hold && path === '/api/browser/mode' && init?.method === method ? new Promise(() => {}) : undefined);
    await act(flush); hold = true; await select('原生中继');
    expectUnauthenticatedSockets(1);
    expect(Socket.instances[0].url).toBe('ws://127.0.0.1:10233/');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(method === 'POST' ? 1 : 0);
    await advance(999); expectUnauthenticatedSockets(1);
    await advance(1); expectUnauthenticatedSockets(2);
    expect(Socket.instances[0].close).toHaveBeenCalledOnce();
    await advance(999); expectUnauthenticatedSockets(2);
    await advance(1); expectUnauthenticatedSockets(3);
    expect(Socket.instances[1].close).toHaveBeenCalledOnce();
    expect(Socket.instances[2].close).not.toHaveBeenCalled();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(method === 'POST' ? 1 : 0);
    expect(f.calls('/api/helper/refresh')).toHaveLength(0);
    expect(f.calls('/api/helper/advertisement')).toHaveLength(0);
    await select('软件模拟');
    for (const socket of Socket.instances) expect(socket.close).toHaveBeenCalledOnce();
    await advance(5000); expectUnauthenticatedSockets(3);
  });
  it.each([
    {method: 'GET', opened: false}, {method: 'GET', opened: true},
    {method: 'POST', opened: false}, {method: 'POST', opened: true},
  ])('hands the same $method-pending socket to its owner exactly once when opened=$opened', async ({method, opened}) => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let hold = false; let response!: Response;
    const f = fixture(undefined, false, (path, init, value) => {
      if (hold && path === '/api/browser/mode' && init?.method === method) { hold = false; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); hold = true; await select('原生中继');
    expectUnauthenticatedSockets(1); const socket = Socket.instances[0];
    if (opened) act(() => socket.open());
    expect(socket.onmessage).toBeNull();
    act(() => {
      socket.onmessage?.({data: statusFrame('paired')});
      socket.onmessage?.({data: JSON.stringify({type: 'advertisement', uuid: '0000fff9-0000-1000-8000-00805f9b34fb', data: 'AQID'})});
    });
    expect(f.calls('/api/helper/advertisement')).toHaveLength(0);
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    await advance(750); expectUnauthenticatedSockets(1);
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(Socket.instances).toEqual([socket]); expect(socket.close).not.toHaveBeenCalled();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    if (!opened) {
      expect(socket.send).not.toHaveBeenCalled();
      act(() => socket.open());
    }
    expect(socket.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-1', session_id: 'session-2'}));
    expect(screen.getByRole('progressbar', {name: '等待助手批准配对'})).toBeVisible();
    // OPEN ends the client establishment deadline; only the server controls
    // pre-pair expiry, and human approval is not a one-second handshake.
    await advance(6000);
    expect(Socket.instances).toEqual([socket]); expect(socket.close).not.toHaveBeenCalled();
    expect(socket.send).toHaveBeenCalledTimes(1); expect(f.calls('/api/helper/refresh')).toHaveLength(0);
    expect(f.calls('/api/helper/stop')).toHaveLength(0);
    f.setReady(true); await advance(1000);
    expect(screen.queryByRole('img', {name: '助手与原生引擎已连接'})).toBeNull();
    act(() => socket.onmessage?.({data: statusFrame('paired')}));
    expect(screen.getByRole('img', {name: '助手与原生引擎已连接'})).toBeVisible();
  });
  it('preserves the original one-second CONNECTING deadline across owner acquisition', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let hold = true;
    const f = fixture(undefined, false, (path, init, value) => {
      if (hold && path === '/api/browser/mode' && init?.method === 'POST') { hold = false; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    expectUnauthenticatedSockets(1); const socket = Socket.instances[0];
    await advance(850);
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(Socket.instances).toEqual([socket]); expect(socket.close).not.toHaveBeenCalled();
    await advance(149); expectUnauthenticatedSockets(1); expect(socket.close).not.toHaveBeenCalled();
    await advance(1); expectUnauthenticatedSockets(2); expect(socket.close).toHaveBeenCalledOnce();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expect(f.calls('/api/helper/refresh')).toHaveLength(0); expect(f.calls('/api/helper/stop')).toHaveLength(0);
    act(() => Socket.instances[1].open());
    expect(Socket.instances[1].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-1', session_id: 'session-2'}));
  });
  it.each([
    {opened: false, event: 'error', retryAt: 1000},
    {opened: true, event: 'close', retryAt: 1900},
  ])('preserves pending $event cooldown through capability handoff at 950ms (opened=$opened)', async ({opened, event, retryAt}) => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let hold = true;
    const f = fixture(undefined, false, (path, init, value) => {
      if (hold && path === '/api/browser/mode' && init?.method === 'POST') { hold = false; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    expectUnauthenticatedSockets(1); const socket = Socket.instances[0];
    if (opened) act(() => socket.open());
    const staleOpen = socket.onopen!; const staleFailure = event === 'error' ? socket.onerror! : socket.onclose!;
    await advance(900); act(() => staleFailure());
    expect(socket.close).toHaveBeenCalledOnce(); expectUnauthenticatedSockets(1);
    await advance(50);
    await act(async () => { delayed.resolve(response); await flush(); });
    // The owner has received its capability, but takes the outstanding retry
    // deadline rather than constructing a replacement in the cooldown gap.
    expect(f.calls('/api/helper/status')).toHaveLength(1);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expectUnauthenticatedSockets(1); expect(socket.close).toHaveBeenCalledOnce();
    act(() => { staleOpen(); staleFailure(); });
    await advance(retryAt - 951); expectUnauthenticatedSockets(1);
    await advance(1); expectUnauthenticatedSockets(2);
    const replacement = Socket.instances[1];
    expect(replacement.url).toBe(socket.url); expect(replacement.close).not.toHaveBeenCalled();
    expect(f.calls('/api/helper/refresh')).toHaveLength(0); expect(f.calls('/api/helper/stop')).toHaveLength(0);
    act(() => replacement.open());
    expect(replacement.send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-1', session_id: 'session-2'}));
    expect(socket.send).not.toHaveBeenCalled();
    await advance(1000);
    expect(Socket.instances).toHaveLength(2); expect(replacement.close).not.toHaveBeenCalled();
    expect(replacement.send).toHaveBeenCalledTimes(1); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
  });
  it('keeps an already OPEN unauthenticated socket until server pre-pair timeout and ignores late callbacks', async () => {
    vi.useFakeTimers(); let hold = false;
    const f = fixture((path, init) => hold && path === '/api/browser/mode' && init?.method === 'GET' ? new Promise(() => {}) : undefined);
    await act(flush); hold = true; await select('原生中继');
    const socket = Socket.instances[0]; const staleOpen = socket.onopen!; const staleClose = socket.onclose!;
    act(() => socket.open()); await advance(4999);
    expectUnauthenticatedSockets(1); expect(socket.close).not.toHaveBeenCalled();
    // Model the helper's five-second pre-pair close, rather than making the
    // browser invent a second OPEN-socket deadline.
    await advance(1); act(() => socket.onclose?.());
    expect(socket.close).toHaveBeenCalledOnce();
    await advance(999); expectUnauthenticatedSockets(1);
    await advance(1); expectUnauthenticatedSockets(2);
    act(() => { staleOpen(); staleClose(); });
    expectUnauthenticatedSockets(2); expect(Socket.instances[1].close).not.toHaveBeenCalled();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
  });
  it('interrupts a hung read immediately for the latest explicit Connect and ignores its late snapshot', async () => {
    const delayed = deferred<Response>(); let hold = false; let oldResponse!: Response; let oldSignal: AbortSignal | null | undefined;
    const f = fixture(undefined, false, (path, init, response) => {
      if (hold && path === '/api/browser/mode' && init?.method === 'GET') {
        hold = false; oldResponse = response; oldSignal = init.signal; return delayed.promise;
      }
      return response;
    });
    await act(flush); hold = true; await select('原生中继');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
    expectUnauthenticatedSockets(1);
    const pendingSocket = Socket.instances[0];
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19001'}});
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(oldSignal?.aborted).toBe(true); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expectUnauthenticatedSockets(2); expect(pendingSocket.close).toHaveBeenCalledOnce(); expect(Socket.instances[1].url).toBe('ws://localhost:19001/');
    await act(async () => { delayed.resolve(oldResponse); await flush(); });
    expectUnauthenticatedSockets(2); expect(f.snapshot().active).toBe(true);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('原生中继');
  });
  it('bounds a hung acquisition read and retries without needing another click', async () => {
    vi.useFakeTimers(); let hold = false; let oldSignal: AbortSignal | null | undefined;
    const f = fixture((path, init) => {
      if (hold && path === '/api/browser/mode' && init?.method === 'GET') { hold = false; oldSignal = init.signal; return new Promise(() => {}); }
    });
    await act(flush); hold = true; await select('原生中继');
    expectUnauthenticatedSockets(1);
    await advance(999); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0); expectUnauthenticatedSockets(1);
    await advance(1); expectUnauthenticatedSockets(2); expect(Socket.instances[0].close).toHaveBeenCalledOnce(); expect(oldSignal?.aborted).toBe(true); expect(screen.queryByRole('alert')).toBeNull();
    await advance(1000); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expectUnauthenticatedSockets(3);
  });
  it('queues sampled edits and repeated Connect during acquisition, then pairs only the latest address', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let held = false;
    const f = fixture(undefined, false, (path, init, value) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19001'}}); await advance(200);
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19002'}}); await advance(200);
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expectUnauthenticatedSockets(5);
    for (const socket of Socket.instances.slice(0, -1)) expect(socket.close).toHaveBeenCalledOnce();
    expect(f.calls('/api/browser/mode', 'POST')[0][1]?.signal).toBeUndefined();
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    expect(f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id)).toEqual(['session-2']);
    expectUnauthenticatedSockets(5); expect(Socket.instances[4].url).toBe('ws://localhost:19002/');
    act(() => Socket.instances[4].open());
    expect(Socket.instances[4].send).toHaveBeenCalledExactlyOnceWith(JSON.stringify({type: 'pair', token: 'secret-2', session_id: 'session-4'}));
    for (const socket of Socket.instances.slice(0, -1)) expect(socket.send).not.toHaveBeenCalled();
    expect(f.snapshot()).toMatchObject({active: true, generation: 4}); expect(screen.queryByRole('alert')).toBeNull();
  });
  it('lets a same-address explicit Connect supersede a hung uncommitted POST using a fresh CAS read', async () => {
    const delayed = deferred<Response>(); let held = false;
    const f = fixture((path, init) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; return delayed.promise; }
    });
    await act(flush); await select('原生中继');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expectUnauthenticatedSockets(1);
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2); expectUnauthenticatedSockets(2);
    expect(Socket.instances[0].close).toHaveBeenCalledOnce();
    expect(Socket.instances[1].url).toBe('ws://127.0.0.1:10233/');
    expect(f.calls('/api/browser/mode', 'POST').map(([, init]) => JSON.parse(String(init?.body)).expected_generation)).toEqual([1, 1]);
    await act(async () => { delayed.resolve(Response.json({error: 'lease conflict'}, {status: 409})); await flush(); });
    expect(f.calls('/api/helper/stop')).toHaveLength(0); expect(Socket.instances.at(-1)!.close).not.toHaveBeenCalled();
    expect(f.snapshot()).toMatchObject({active: true, generation: 2});
  });
  it('keeps an uncertain committed POST neutral until expiry and cleans its late exact ID without stopping a newer lease', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let held = false;
    const f = fixture(undefined, false, (path, init, value) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继'); await advance(5000);
    expect(f.calls('/api/browser/mode', 'GET').length).toBeGreaterThan(2);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expect(f.calls('/api/helper/stop')).toHaveLength(0);
    expectUnauthenticatedSockets(6); expect(screen.queryByRole('alert')).toBeNull();
    for (const socket of Socket.instances.slice(0, -1)) expect(socket.close).toHaveBeenCalledOnce();
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19003'}});
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    f.clearLease(); await advance(1000);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    expectUnauthenticatedSockets(8); expect(Socket.instances.at(-1)!.url).toBe('ws://localhost:19003/');
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id)).toEqual(['session-2']);
    expect(f.snapshot()).toMatchObject({active: true, generation: 4}); expect(Socket.instances.at(-1)!.close).not.toHaveBeenCalled();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
  });
  it('retains a stale acquisition capability when cleanup fails, then releases it before the latest acquisition', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let held = false; let failStop = true;
    const f = fixture(path => path === '/api/helper/stop' && failStop ? Promise.reject(new Error('stop offline')) : undefined, false, (path, init, value) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(f.calls('/api/helper/stop')).toHaveLength(1); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expectUnauthenticatedSockets(2); expect(screen.queryByRole('alert')).toBeNull();
    failStop = false; await advance(1000);
    expect(f.calls('/api/helper/stop')).toHaveLength(2); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    expectUnauthenticatedSockets(3); expect(f.snapshot()).toMatchObject({active: true, generation: 4});
  });
  it('does not let a delayed old stop acknowledgment block or erase a newer Connect', async () => {
    vi.useFakeTimers(); const acquisition = deferred<Response>(); const stopped = deferred<Response>();
    let acquisitionResponse!: Response; let stopResponse!: Response; let heldAcquisition = false; let heldStop = false;
    const f = fixture(undefined, false, (path, init, value) => {
      if (!heldAcquisition && path === '/api/browser/mode' && init?.method === 'POST') { heldAcquisition = true; acquisitionResponse = value; return acquisition.promise; }
      if (!heldStop && path === '/api/helper/stop') { heldStop = true; stopResponse = value; return stopped.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    await act(async () => { acquisition.resolve(acquisitionResponse); await flush(); });
    expect(f.calls('/api/helper/stop')).toHaveLength(1); expectUnauthenticatedSockets(2);
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19004'}});
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expectUnauthenticatedSockets(3); expect(Socket.instances[2].url).toBe('ws://localhost:19004/');
    expect(f.calls('/api/helper/stop')[0][1]?.signal).toBeUndefined();
    await act(async () => { stopped.resolve(stopResponse); await flush(); });
    expect(f.snapshot()).toMatchObject({active: true, generation: 4}); expect(Socket.instances.at(-1)!.close).not.toHaveBeenCalled();
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
  });
  it('invalidates pending acquisition on an invalid sampled address and waits for a valid one', async () => {
    vi.useFakeTimers(); const delayed = deferred<Response>(); let response!: Response; let held = false;
    const f = fixture(undefined, false, (path, init, value) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'https://untrusted.example:19001'}}); await advance(200);
    await act(async () => { delayed.resolve(response); await flush(); });
    expect(f.calls('/api/helper/stop')).toHaveLength(1); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    expectUnauthenticatedSockets(1); expect(Socket.instances[0].close).toHaveBeenCalledOnce(); expect(f.snapshot().active).toBe(false);
    const input = screen.getByRole('textbox', {name: '辅助程序连接地址'});
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.closest('.MuiInputBase-root')).toContainElement(screen.getByRole('img', {name: '地址无效'}));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByText('地址无效', {selector: 'p, div'})).toBeNull();
    fireEvent.change(screen.getByRole('textbox', {name: '辅助程序连接地址'}), {target: {value: 'localhost:19005'}}); await advance(200);
    expectUnauthenticatedSockets(2); expect(Socket.instances[1].url).toBe('ws://localhost:19005/'); expect(screen.queryByRole('alert')).toBeNull();
  });
  it.each(['unmount', 'pagehide'])('releases retained late-acquisition capabilities on %s even while the next status read hangs', async event => {
    const delayed = deferred<Response>(); let response!: Response; let held = false; let hangRead = false;
    const f = fixture((path, init) => hangRead && path === '/api/browser/mode' && init?.method === 'GET' ? new Promise(() => {}) : undefined, false, (path, init, value) => {
      if (!held && path === '/api/browser/mode' && init?.method === 'POST') { held = true; response = value; return delayed.promise; }
      return value;
    });
    await act(flush); await select('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    hangRead = true; await act(async () => { delayed.resolve(response); await flush(); });
    expect(f.calls('/api/helper/stop')).toHaveLength(0);
    if (event === 'unmount') f.rendered.unmount(); else fireEvent(window, new Event('pagehide'));
    await act(flush);
    expect(f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id)).toEqual(['session-2']);
    expect(f.snapshot().active).toBe(false); expectUnauthenticatedSockets(2);
    for (const socket of Socket.instances) expect(socket.close).toHaveBeenCalledOnce();
  });
  it('releases a malformed acquired session capability on teardown instead of losing its only stop ID', async () => {
    vi.useFakeTimers();
    const f = fixture(undefined, false, async (path, init, value) => {
      if (path === '/api/browser/mode' && init?.method === 'POST') return Response.json({...await value.json(), token: ''});
      return value;
    });
    await act(flush); await select('原生中继');
    expectUnauthenticatedSockets(1); expect(f.snapshot().active).toBe(true);
    f.rendered.unmount(); await act(flush);
    expect(f.calls('/api/helper/stop').map(([, init]) => JSON.parse(String(init?.body)).session_id)).toEqual(['session-2']);
    expect(f.snapshot().active).toBe(false);
  });
  it('retries native mode network failures silently once per second and cancels on mode exit', async () => {
    vi.useFakeTimers();
    const f = fixture((path, init) => path === '/api/browser/mode' && init?.method === 'POST' && JSON.parse(String(init.body)).mode === 'native'
      ? Promise.reject(new Error('network unavailable')) : undefined);
    await act(flush); await select('原生中继');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('progressbar')).toBeVisible();
    await advance(999); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    await advance(1); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    await select('软件模拟'); await advance(5000); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
  });

  it('retains the owning capability if an expired transport stop fails and retries safely', async () => {
    vi.useFakeTimers(); let fail = true; let expired = false;
    const f = fixture((path) => path === '/api/helper/stop' && fail ? Promise.reject(new Error('stop offline'))
      : path === '/api/helper/status' && expired ? Promise.resolve(Response.json({active: false, generation: 2})) : undefined);
    await act(flush); await select('原生中继');
    expired = true; await advance(2000);
    expect(screen.queryByRole('alert')).toBeNull(); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    fail = false; expired = false; await advance(1000);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2); expectUnauthenticatedSockets(3);
    expect(screen.queryByText(/另一页面正在使用/)).toBeNull();
  });
  it('preserves software preference and never adopts another tab native lease or exposes its token', async () => {
    const f = fixture(undefined, true); await act(flush);
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0); expect(f.calls('/api/helper/stop')).toHaveLength(0);
    await select('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0); expectUnauthenticatedSockets(2);
    act(() => Socket.instances[1].open());
    expectUnauthenticatedSockets(2);
    expect(screen.getByRole('alert')).toHaveTextContent('另一页面');
    f.clearLease(); fireEvent.click(screen.getByRole('button', {name: '连接'})); await act(flush);
    expectUnauthenticatedSockets(3);
  });
  it.each(['exit', 'unmount', 'pagehide'])('revokes a late native start after %s and never pairs its early socket', async event => {
    let resolve!: (response: Response) => void;
    const f = fixture((path, init) => path === '/api/browser/mode' && init?.method === 'POST' ? new Promise(done => {resolve = done;}) : undefined);
    await act(flush); await select('原生中继');
    fireEvent.click(screen.getByRole('button', {name: '连接'})); fireEvent.click(screen.getByRole('button', {name: '连接'}));
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1);
    if (event === 'exit') await select('软件模拟'); else if (event === 'unmount') f.rendered.unmount(); else fireEvent(window, new Event('pagehide'));
    await act(async () => {resolve(Response.json({mode: 'native', state: 'switching', generation: 2, active: true, owned: true, session_id: 'late', token: 'late-secret', expires_in_ms: 120000, helper_url: 'ws://127.0.0.1:10233'})); await flush();});
    expectUnauthenticatedSockets(3);
    for (const socket of Socket.instances) expect(socket.close).toHaveBeenCalledOnce();
    expect(f.calls('/api/helper/stop').some(([,init]) => init?.body === JSON.stringify({session_id: 'late'}))).toBe(true);
  });
  it('stops transport and forwarding on mode exit while leaving the control panel available', async () => {
    vi.useFakeTimers(); const f = fixture(); await act(flush); await select('原生中继');
    const ws = Socket.instances[0]; const lateOpen = ws.onopen!;
    await select('软件模拟'); expect(ws.close).toHaveBeenCalledOnce(); await advance(5000); act(() => lateOpen());
    expect(Socket.instances).toHaveLength(1); expect(ws.send).not.toHaveBeenCalled(); expect(screen.queryByLabelText('辅助程序连接地址')).toBeNull();
    expect(screen.getByRole('region', {name: '浏览器控制栏'})).toBeVisible();
  });
  it('reconciles a concurrent completed stop instead of showing a false 409 failure', async () => {
    let racing = false, staleGet = false;
    const f = fixture((path, init) => {
      if (racing && path === '/api/browser/mode' && init?.method === 'GET' && !staleGet) {
        staleGet = true; f.clearLease();
        return Promise.resolve(Response.json({mode: 'native', state: 'native', generation: 2, active: true, owned: true, control_connected: true}));
      }
      if (racing && path === '/api/helper/stop') return Promise.resolve(Response.json({error: 'already stopped'}, {status: 409}));
    });
    await act(flush); await select('原生中继'); racing = true; await select('软件模拟');
    expect(screen.queryByRole('alert')).toBeNull(); expect(screen.queryByLabelText('辅助程序连接地址')).toBeNull();
    expect(screen.getByRole('combobox', {name: '模式'})).toHaveTextContent('软件模拟');
  });
  it('retries an unready software rollback instead of treating mode intent as confirmed readiness', async () => {
    let rollbackError = false;
    const f = fixture((path, init) => {
      if (rollbackError && path === '/api/browser/mode' && init?.method === 'GET') return Promise.resolve(Response.json({mode: 'software', state: 'error', generation: 50, active: false, owned: false, control_connected: true}));
      if (rollbackError && path === '/api/browser/mode' && init?.method === 'POST') return Promise.resolve(Response.json({mode: 'software', state: 'switching', generation: 51, active: false, owned: false, control_connected: true}));
    });
    await act(flush); await select('原生中继'); rollbackError = true; await select('软件模拟');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(2);
    expect(JSON.parse(String(f.calls('/api/browser/mode', 'POST')[1][1]?.body))).toEqual({mode: 'software', expected_generation: 50});
  });
  it('waits for software restoration acknowledgment before creating a new native lease', async () => {
    vi.useFakeTimers(); let switching = false;
    const f = fixture((path, init) => switching && path === '/api/browser/mode' && init?.method === 'GET' ? Promise.resolve(Response.json({mode: 'software', state: 'switching', generation: 9, active: false, owned: false, control_connected: true})) : undefined);
    await act(flush); switching = true; await select('原生中继');
    expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0); expectUnauthenticatedSockets(1);
    await advance(2000); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(0);
    switching = false; await advance(1000); expect(f.calls('/api/browser/mode', 'POST')).toHaveLength(1); expectUnauthenticatedSockets(4);
  });
  it('updates fullscreen icon only when the actual document state changes', async () => {
    fixture(); await act(flush);
    Object.defineProperty(document, 'fullscreenElement', {configurable: true, value: document.documentElement});
    fireEvent(document, new Event('fullscreenchange'));
    expect(screen.getByRole('button', {name: '退出全屏'})).toHaveTextContent(/^$/);
    Object.defineProperty(document, 'fullscreenElement', {configurable: true, value: null}); fireEvent(document, new Event('fullscreenchange'));
    expect(screen.getByRole('button', {name: '全屏'})).toBeVisible();
  });
});
