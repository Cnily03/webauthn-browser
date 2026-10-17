import { useEffect, useRef, useState } from 'react';
import { Box, IconButton, Tooltip } from '@mui/material';
import ContentPasteIcon from '@mui/icons-material/ContentPaste';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import WarningAmberOutlinedIcon from '@mui/icons-material/WarningAmberOutlined';
import { LiveClipboard, type ClipboardState } from './clipboard';
import { ApiError, browserTransportUrl } from './api';
import { browserProfileName, profileViewerHeaders } from './profiles';

export function ClipboardSync({ connected, copyAgain, sessionKey = '' }: { connected: boolean; copyAgain: () => void; sessionKey?: string }) {
  const controller = useRef<LiveClipboard | null>(null);
  const canUseController = useRef<() => boolean>(() => false);
  const [state, setState] = useState<ClipboardState>({ kind: 'ready', message: '' });
  useEffect(() => {
    if (!connected) return;
    setState({ kind: 'ready', message: '' });
    let disposed = false;
    let stopped = false;
    let retryDelay = 500;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let closeConnection = () => {};
    // A retry must not silently adopt a successor's viewer capability while a
    // stale component is still mounted. React replaces this effect on ownership.
    const identity = JSON.stringify([browserProfileName(), profileViewerHeaders()]);
    const current = () => !disposed && !stopped && identity === JSON.stringify([browserProfileName(), profileViewerHeaders()]);
    canUseController.current = current;
    const close = () => {
      disposed = true;
      clearTimeout(retryTimer);
      closeConnection();
    };
    const retry = () => {
      if (!current()) return;
      retryTimer = setTimeout(start, retryDelay);
      retryDelay = Math.min(retryDelay * 2, 10000);
    };
    const start = () => {
      if (!current()) return;
      const sequence = ++attempt;
      const admission = new AbortController();
      let socket: WebSocket | undefined;
      let clipboard: LiveClipboard | undefined;
      let ended = false;
      let openedAt: number | undefined;
      const active = () => current() && !ended && sequence === attempt;
      const release = () => {
        ended = true;
        clearTimeout(timeout);
        admission.abort();
        clipboard?.dispose();
        if (controller.current === clipboard) controller.current = null;
        if (socket) {
          socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null;
          socket.close();
        }
      };
      const failed = (message: string, terminal = false) => {
        if (!active()) return;
        // A handshake alone does not mean the private bridge is ready. Avoid
        // tight reconnect loops when it accepts WS and immediately closes.
        if (openedAt !== undefined && Date.now() - openedAt >= 30000) retryDelay = 500;
        release();
        setState({kind: 'unavailable', message});
        if (terminal) stopped = true;
        else retry();
      };
      // Both ticket admission and a socket that never opens need a deadline.
      let timeout = setTimeout(() => failed('剪贴板连接不可用'), 10000);
      closeConnection = release;
      const connect = (url: URL) => {
        if (!active()) return;
        clearTimeout(timeout);
        timeout = setTimeout(() => failed('剪贴板连接不可用'), 1000);
        try { socket = new WebSocket(url); }
        catch { failed('剪贴板连接不可用'); return; }
        const transport = socket;
        const live = new LiveClipboard(frame => {
          if (active() && transport.readyState === WebSocket.OPEN) transport.send(JSON.stringify(frame));
        }, next => { if (active()) setState({...next}); });
        clipboard = live;
        controller.current = live;
        transport.onopen = () => {
          if (!active()) return;
          clearTimeout(timeout);
          openedAt = Date.now();
          setState(window.isSecureContext ? {kind: 'ready', message: ''} : {kind: 'unavailable', message: '剪贴板不可用'});
        };
        transport.onmessage = event => {
          if (!active() || typeof event.data !== 'string') return;
          try { live.receive(JSON.parse(event.data)); }
          catch { failed('剪贴板连接异常'); }
        };
        transport.onclose = () => failed('剪贴板已断开');
        transport.onerror = () => failed('剪贴板连接不可用');
      };
      if (browserProfileName()) {
        // Tickets are single-use. Each transport attempt gets fresh admission.
        void browserTransportUrl('/api/clipboard/ws', 'clipboard', admission.signal).then(connect)
          .catch(error => failed('剪贴板连接不可用', error instanceof ApiError && [401, 403].includes(error.status)));
      } else {
        const url = new URL('/api/clipboard/ws', window.location.href);
        url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        connect(url);
      }
    };
    start();
    const suspend = () => { close(); setState({kind: 'ready', message: ''}); };
    window.addEventListener('pagehide', suspend);
    return () => { window.removeEventListener('pagehide', suspend); close(); };
  }, [connected, sessionKey]);
  if (!connected) return null;
  if (state.kind === 'read') return <Tooltip title="粘贴剪贴板内容"><IconButton size="small" aria-label="粘贴剪贴板内容" onClick={() => { if (canUseController.current()) controller.current?.retryRead(); }} sx={{ alignSelf: 'flex-start' }}><ContentPasteIcon fontSize="small" /></IconButton></Tooltip>;
  if (!state.message) return null;
  if (state.kind === 'copy') return <Tooltip title={state.message}><IconButton size="small" aria-label="重新复制选中内容" onClick={() => { if (canUseController.current()) controller.current?.copyAgain(copyAgain); }} sx={{alignSelf: 'flex-start'}}><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>;
  return <Tooltip title={state.message}><Box component="span" role="img" aria-label={state.message} tabIndex={0} sx={{display: 'inline-flex', alignSelf: 'flex-start', p: '5px'}}><WarningAmberOutlinedIcon color={state.kind === 'error' ? 'error' : 'action'} fontSize="small" /></Box></Tooltip>;
}
