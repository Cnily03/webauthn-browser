import { useEffect, useRef, useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, LinearProgress, Stack, Typography,
} from '@mui/material';
import { request, requestBlob } from './api';
import { errorMessage, statusCode } from './requestStream';

interface Props {
  csrfToken: string;
  onRestored: () => Promise<void>;
  onUnauthorized: () => void;
  notify: (message: string, error?: boolean) => void;
}
interface Preview {
  key_count: number;
  credential_count: number;
  current_key_count: number;
  current_credential_count: number;
  warnings?: string[];
}
interface PreviewResponse extends Preview { token: string }
const MAX_BACKUP_SIZE = 2 * 1024 * 1024;

export function downloadBackup(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  try { link.click(); }
  finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
}

export function BackupDialogs({csrfToken, onRestored, onUnauthorized, notify}: Props) {
  const [mode, setMode] = useState<'export' | 'import' | null>(null);
  const [working, setWorking] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [filename, setFilename] = useState('');
  const [downloaded, setDownloaded] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const [inputKey, setInputKey] = useState(0);
  const secret = useRef({source: '', token: ''});
  const file = useRef<HTMLInputElement | null>(null);
  const operation = useRef(0);
  const busy = useRef(false);
  const confirming = useRef(false);
  const mounted = useRef(true);
  const clearSecrets = () => {
    secret.current = {source: '', token: ''};
    if (file.current) file.current.value = '';
  };
  const reset = () => {
    operation.current += 1;
    clearSecrets();
    busy.current = false; confirming.current = false; setWorking(false);
    setPreview(null); setFilename(''); setDownloaded(false); setSaved(false); setError('');
    setInputKey(value => value + 1);
  };
  const close = () => {
    if (confirming.current) return;
    reset();
    busy.current = false;
    setWorking(false);
    setMode(null);
  };
  const open = (next: 'export' | 'import') => { reset(); setMode(next); };
  useEffect(() => {
    mounted.current = true;
    const pagehide = () => { reset(); setMode(null); };
    window.addEventListener('pagehide', pagehide);
    return () => {
      mounted.current = false;
      operation.current += 1;
      clearSecrets();
      window.removeEventListener('pagehide', pagehide);
    };
  }, []);
  useEffect(() => {
    // A rotated session must not retain a restore token or any imported key material.
    operation.current += 1;
    clearSecrets();
    setMode(null); setPreview(null); setDownloaded(false); setSaved(false);
    busy.current = false; confirming.current = false; setWorking(false);
  }, [csrfToken]);

  const perform = async (action: (current: () => boolean) => Promise<void>, isConfirmation = false) => {
    if (busy.current) return;
    busy.current = true;
    confirming.current = isConfirmation;
    setWorking(true); setError('');
    const version = operation.current;
    const current = () => mounted.current && version === operation.current;
    try { await action(current); }
    catch (failure) {
      if (!current()) return;
      if (statusCode(failure) === 401) {
        confirming.current = false;
        close(); onUnauthorized();
      } else if (statusCode(failure) === 409) {
        reset();
        setError('预览已失效，或当前验证器 / 文件已经变化。请重新选择文件并验证，再下载新的安全备份。');
      } else if (isConfirmation) {
        // The server may have committed even if its response was lost. Never replay.
        reset();
        setError(`恢复结果未能确认：${errorMessage(failure)}。请先重新加载设置，核对当前验证器。此操作不会自动重试。`);
      } else {
        setError(errorMessage(failure));
      }
    } finally {
      if (mounted.current && version === operation.current) {
        busy.current = false; confirming.current = false; setWorking(false);
      }
    }
  };

  const selectFile = (selected?: File) => {
    if (!selected || busy.current) return;
    reset();
    void perform(async current => {
      if (selected.size > MAX_BACKUP_SIZE) throw new Error('备份文件不能超过 2 MiB。');
      let source = await selected.text();
      if (!current()) { source = ''; return; }
      try { JSON.parse(source); } catch { source = ''; throw new Error('这不是有效的 JSON 备份文件，请重新选择。'); }
      let result: PreviewResponse;
      secret.current.source = source;
      source = '';
      const payload: {backup?: string} = {backup: secret.current.source};
      try {
        const pending = request<PreviewResponse>('/api/restore/preview', 'POST', payload);
        delete payload.backup;
        result = await pending;
      } catch (failure) { if (current()) clearSecrets(); throw failure; }
      finally { delete payload.backup; }
      if (!current()) { source = ''; return; }
      if (!result || typeof result.token !== 'string' || !result.token ||
          ![result.key_count, result.credential_count, result.current_key_count, result.current_credential_count].every(value => Number.isSafeInteger(value) && value >= 0)) {
        clearSecrets(); throw new Error('备份预览格式无效，请重新选择文件。');
      }
      secret.current.token = result.token;
      setPreview({key_count: result.key_count, credential_count: result.credential_count, current_key_count: result.current_key_count, current_credential_count: result.current_credential_count, warnings: Array.isArray(result.warnings) ? result.warnings.filter(text => typeof text === 'string') : []});
      setFilename(selected.name);
    });
  };
  const downloadSafety = () => void perform(async current => {
    if (!preview || !secret.current.token) return;
    const blob = await requestBlob('/api/restore/backup', 'POST', {token: secret.current.token});
    if (!current()) return;
    downloadBackup(blob, 'webauthn-browser-before-restore.json');
    setDownloaded(true);
  });
  const restore = () => {
    if (!preview || !downloaded || !saved || !secret.current.token || !secret.current.source) return;
    void perform(async current => {
      const payload: {token?: string; backup?: string} = {token: secret.current.token, backup: secret.current.source};
      clearSecrets();
      try {
        const pending = request('/api/restore/confirm', 'POST', payload);
        delete payload.token; delete payload.backup;
        await pending;
      } finally { delete payload.token; delete payload.backup; }
      if (!current()) return;
      confirming.current = false;
      close();
      notify('验证器备份已恢复。浏览器数据与两种访问密码保持原样；请妥善保存恢复前的安全备份。');
      try { await onRestored(); }
      catch (failure) {
        if (!mounted.current) return;
        if (statusCode(failure) === 401) onUnauthorized();
        else notify(`恢复已完成，但设置刷新失败：${errorMessage(failure)}`, true);
      }
    }, true);
  };
  const exportKeys = () => void perform(async current => {
    const blob = await requestBlob('/api/backup');
    if (!current()) return;
    downloadBackup(blob, 'webauthn-browser-backup.json');
    close();
    notify('备份下载已发起。文件包含未加密的私钥，请安全保存。');
  });

  return <>
    <Stack direction="row" spacing={1} useFlexGap sx={{flexWrap: 'wrap'}}>
      <Button variant="outlined" onClick={() => open('export')}>导出验证器备份</Button>
      <Button variant="outlined" onClick={() => open('import')}>从备份恢复</Button>
    </Stack>
    <Dialog open={mode === 'export'} onClose={close} fullWidth maxWidth="sm" aria-labelledby="backup-export-title" aria-describedby="backup-export-warning">
      <DialogTitle id="backup-export-title">导出验证器备份</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Alert severity="warning" color="info" id="backup-export-warning">下载的备份包含所有虚拟验证器的未加密私钥。持有此文件的人可能使用你的通行密钥。请将它保存在安全位置，不要分享或上传到不可信服务。</Alert>
          {error && <Alert severity="error">{error}</Alert>}
          {working && <LinearProgress aria-label="正在导出备份" />}
        </Stack>
      </DialogContent>
      <DialogActions><Button onClick={close}>取消</Button><Button variant="contained" onClick={exportKeys} disabled={working}>下载未加密备份</Button></DialogActions>
    </Dialog>
    <Dialog open={mode === 'import'} onClose={close} fullWidth maxWidth="sm" aria-labelledby="restore-title" aria-describedby="restore-scope">
      <DialogTitle id="restore-title">从备份恢复验证器</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Alert severity="warning" color="info" id="restore-scope">只替换验证器及通行密钥。不会修改浏览器资料、浏览器访问密码或设置管理密码。备份含未加密私钥，请勿分享。</Alert>
          {!preview ? <>
            <Box component="label" sx={{display: 'flex', flexDirection: 'column', gap: 1}}>
              <Typography variant="subtitle2">选择验证器备份文件</Typography>
              <Box component="input" key={inputKey} ref={file} type="file" name="restore-file" accept=".json,application/json" aria-label="选择验证器备份文件" disabled={working}
                onChange={event => selectFile(event.target.files?.[0])} sx={{maxWidth: '100%', font: 'inherit', '&::file-selector-button': {border: 0, borderRadius: 1, padding: '8px 12px', mr: 1, cursor: 'pointer'}}} />
            </Box>
            <Typography variant="body2" color="text.secondary">仅接受本应用导出的 JSON，最大 2 MiB。文件会提交到当前服务进行验证；下一步只显示数量，不显示私钥或密码。</Typography>
          </> : <>
            <Typography variant="subtitle2" sx={{overflowWrap: 'anywhere'}}>{filename}</Typography>
            <Box sx={{p: 2, borderRadius: 2, bgcolor: 'action.hover'}}>
              <Typography>备份内：{preview.key_count} 个验证器 · {preview.credential_count} 个通行密钥</Typography>
              <Typography>将替换：{preview.current_key_count} 个当前验证器 · {preview.current_credential_count} 个通行密钥</Typography>
            </Box>
            <Typography variant="body2">这是整体替换，不是合并。备份中没有的当前验证器会被移除，相关网站可能无法登录。较旧的备份可能回退通行密钥状态；服务会为相同通行密钥保留当前较高的签名计数。</Typography>
            {preview.warnings?.map((warning, index) => <Typography key={index} variant="body2" color="text.secondary">{warning}</Typography>)}
            <Button variant="outlined" onClick={downloadSafety} disabled={working}>下载恢复前的安全备份</Button>
            {downloaded && <Alert severity="info" role="status">下载已发起。请确认文件已安全保存，再允许替换。</Alert>}
            <FormControlLabel control={<Checkbox name="restore-backup-saved" checked={saved} disabled={!downloaded || working} onChange={event => setSaved(event.target.checked)} />}
              label="我已保存恢复前的安全备份，并确认替换当前验证器" />
          </>}
          {error && <Alert severity="error">{error}</Alert>}
          {working && <LinearProgress aria-label="正在处理备份" />}
        </Stack>
      </DialogContent>
      <DialogActions sx={{flexWrap: 'wrap', gap: 1}}>
        <Button onClick={close} disabled={confirming.current}>取消</Button>
        {preview && <><Button onClick={reset} disabled={working}>返回选文件</Button><Button color="error" variant="contained" disabled={working || !downloaded || !saved} onClick={restore}>替换当前验证器</Button></>}
      </DialogActions>
    </Dialog>
  </>;
}
