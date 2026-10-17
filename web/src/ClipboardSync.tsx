import { useEffect, useRef, useState } from 'react';
import { Box, IconButton, Tooltip } from '@mui/material';
import ContentPasteIcon from '@mui/icons-material/ContentPaste';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import WarningAmberOutlinedIcon from '@mui/icons-material/WarningAmberOutlined';
import { LiveClipboard, type ClipboardState } from './clipboard';
import { browserTransportUrl } from './api';
import { browserProfileName } from './profiles';

export function ClipboardSync({ connected, copyAgain }: { connected: boolean; copyAgain: () => void }) {
  const controller = useRef<LiveClipboard | null>(null);
  const [state, setState] = useState<ClipboardState>({ kind: 'ready', message: '' });
  useEffect(() => {
    if (!connected) return;
    setState({ kind: 'ready', message: '' });
    let disposed = false;
    const admission = new AbortController();
    let closeConnection = () => {};
    const close = () => { disposed = true; admission.abort(); closeConnection(); };
    const connect = (url: URL) => {
      if (disposed) return;
      let socket: WebSocket;
      try { socket = new WebSocket(url); }
      catch { setState({kind: 'unavailable', message: '剪贴板连接不可用'}); return; }
      const clipboard = new LiveClipboard(frame => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame)); }, next => setState({...next}));
      controller.current = clipboard;
      closeConnection = () => { clipboard.dispose(); if (controller.current === clipboard) controller.current = null; socket.close(); };
      socket.onopen = () => { if (!disposed) setState(window.isSecureContext ? {kind: 'ready', message: ''} : {kind: 'unavailable', message: '剪贴板不可用'}); };
      socket.onmessage = event => {
        if (disposed || typeof event.data !== 'string') return;
        try { clipboard.receive(JSON.parse(event.data)); } catch { close(); setState({kind: 'unavailable', message: '剪贴板连接异常'}); }
      };
      socket.onclose = () => { if (!disposed) { clipboard.dispose(); controller.current = null; setState({kind: 'unavailable', message: '剪贴板已断开'}); } };
      socket.onerror = () => { /* onclose provides the same non-sensitive error. */ };
    };
    if (browserProfileName()) {
      void browserTransportUrl('/api/clipboard/ws', 'clipboard', admission.signal).then(connect)
        .catch(() => { if (!disposed) setState({kind: 'unavailable', message: '剪贴板连接不可用'}); });
    } else {
      const url = new URL('/api/clipboard/ws', window.location.href);
      url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      connect(url);
    }
    const suspend = () => { close(); setState({kind: 'ready', message: ''}); };
    window.addEventListener('pagehide', suspend);
    return () => { window.removeEventListener('pagehide', suspend); close(); };
  }, [connected]);
  if (!connected) return null;
  if (state.kind === 'read') return <Tooltip title="粘贴剪贴板内容"><IconButton size="small" aria-label="粘贴剪贴板内容" onClick={() => controller.current?.retryRead()} sx={{ alignSelf: 'flex-start' }}><ContentPasteIcon fontSize="small" /></IconButton></Tooltip>;
  if (!state.message) return null;
  if (state.kind === 'copy') return <Tooltip title={state.message}><IconButton size="small" aria-label="重新复制选中内容" onClick={() => controller.current?.copyAgain(copyAgain)} sx={{alignSelf: 'flex-start'}}><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>;
  return <Tooltip title={state.message}><Box component="span" role="img" aria-label={state.message} tabIndex={0} sx={{display: 'inline-flex', alignSelf: 'flex-start', p: '5px'}}><WarningAmberOutlinedIcon color={state.kind === 'error' ? 'error' : 'action'} fontSize="small" /></Box></Tooltip>;
}
