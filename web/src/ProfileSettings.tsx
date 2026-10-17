import { useCallback, useEffect, useRef, useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, FormControlLabel, IconButton, Stack, Switch, TextField, Tooltip, Typography } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import CleaningServicesOutlinedIcon from '@mui/icons-material/CleaningServicesOutlined';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlined';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { ApiError, request } from './api';

import { validProfileName, type BrowserProfile, type ProfileConfiguration } from './profiles';
export type { BrowserProfile, ProfileConfiguration } from './profiles';
type Notify = (message: string, error?: boolean) => void;
interface Props { notify: Notify; onUnauthorized: () => void; onChanged: () => void }
interface Editor { session: number; profile?: BrowserProfile; name: string; enabled: boolean; timeout: string; passwordEnabled: boolean }
interface RetainedEditor { draft: Editor; error: string }
interface RuntimeCleanupResult { ok: true; profile_count?: number; cleaned: number; pending: number; skipped: number; deleted_profiles?: number; browser_data_retained: boolean; pending_details?: Array<{ profile_id: string; reason: string }> }
const editorKey = (draft: Editor) => draft.profile?.id ?? 'create';

function EditorFields({ draft, disabled, multiProfile, error, passwords, onChange }: {
  draft: Editor; disabled: boolean; multiProfile: boolean; error: string;
  passwords: React.RefObject<Map<number, HTMLInputElement>>;
  onChange: (session: number, changes: Partial<Editor>) => void;
}) {
  const password = useRef<HTMLInputElement | null>(null);
  const passwordRef = useCallback((node: HTMLInputElement | null) => {
    // Each retained form owns its DOM secret. A departing ref cannot touch a
    // newly opened editor, including a new session for the same profile.
    if (password.current) password.current.value = '';
    if (node) passwords.current.set(draft.session, node);
    else passwords.current.delete(draft.session);
    password.current = node;
  }, [draft.session, passwords]);
  return <Stack spacing={2}>
    <TextField label="配置名称" autoFocus={!draft.profile} value={draft.name} disabled={disabled || draft.profile?.id === 'default'} onChange={event => onChange(draft.session, { name: event.target.value })} slotProps={{ htmlInput: { maxLength: 100, spellCheck: false, autoCapitalize: 'none' } }} />
    <TextField label="空闲超时（秒）" type="number" value={draft.timeout} disabled={disabled} onChange={event => onChange(draft.session, { timeout: event.target.value })} slotProps={{ htmlInput: { min: 1, max: 86400, step: 1 } }} />
    <FormControlLabel label="启用配置" control={<Switch checked={Boolean(multiProfile ? draft.enabled : draft.profile?.effective_enabled)} disabled={disabled || !multiProfile} onChange={event => onChange(draft.session, { enabled: event.target.checked })} />} />
    <FormControlLabel label="设置访问密码" control={<Switch checked={draft.passwordEnabled} disabled={disabled} onChange={event => { if (password.current) password.current.value = ''; onChange(draft.session, { passwordEnabled: event.target.checked }); }} />} />
    <TextField label="访问密码" type="password" inputRef={passwordRef} autoComplete="new-password" slotProps={{ htmlInput: { required: draft.passwordEnabled } }} disabled={disabled || !draft.passwordEnabled} />
    {error && <Alert severity="error">{error}</Alert>}
  </Stack>;
}

export default function ProfileSettings({ notify, onUnauthorized, onChanged }: Props) {
  const [configuration, setConfiguration] = useState<ProfileConfiguration | null>(null);
  const [loadError, setLoadError] = useState('');
  const [busy, setBusy] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [editor, setEditor] = useState<Editor | null>(null);
  const [retained, setRetained] = useState<Record<string, RetainedEditor>>({});
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState<BrowserProfile | null>(null);
  const passwords = useRef(new Map<number, HTMLInputElement>());
  const editorSession = useRef(0);
  const activeEditor = useRef(editor);
  activeEditor.current = editor;
  const mounted = useRef(false);
  const serial = useRef(0);
  const busyRef = useRef(false);
  const controller = useRef<AbortController | null>(null);
  const unauthorized = useRef(onUnauthorized);
  unauthorized.current = onUnauthorized;
  const clearPassword = useCallback(() => { for (const input of passwords.current.values()) input.value = ''; }, []);
  const retainEditor = () => {
    // Preserve only the non-secret layout until Collapse finishes. Authority
    // remains with the active session, never with these departing snapshots.
    const draft = activeEditor.current;
    if (draft) setRetained(current => ({ ...current, [editorKey(draft)]: { draft, error } }));
  };
  const selectEditor = (draft: Editor | null) => { activeEditor.current = draft; setEditor(draft); };
  const removeExited = (key: string, session?: number) => {
    if (!mounted.current || session === undefined) return;
    setRetained(current => {
      // A late exit must not remove a newer close/reopen cycle for this row.
      if (current[key]?.draft.session !== session || activeEditor.current?.session === session) return current;
      const next = { ...current };
      delete next[key];
      return next;
    });
  };

  const load = useCallback(async (signal?: AbortSignal) => {
    const current = ++serial.current;
    const result = await request<ProfileConfiguration>('/api/profiles', 'GET', undefined, { signal });
    if (!mounted.current || current !== serial.current) return;
    if (!Array.isArray(result.profiles) || typeof result.multi_profile !== 'boolean') throw new Error('浏览器设置无效。');
    setConfiguration(result);
    setLoadError('');
  }, []);
  useEffect(() => {
    mounted.current = true;
    const pending = new AbortController();
    controller.current = pending;
    void load(pending.signal).catch(reason => {
      if (!mounted.current || pending.signal.aborted) return;
      setLoadError(reason instanceof Error ? reason.message : '读取浏览器设置失败。');
      if (reason instanceof ApiError && reason.status === 401) unauthorized.current();
    });
    window.addEventListener('pagehide', clearPassword);
    return () => {
      mounted.current = false;
      serial.current += 1;
      controller.current?.abort();
      clearPassword();
      window.removeEventListener('pagehide', clearPassword);
    };
  }, [clearPassword, load]);

  const mutate = async (path: string, method: string, body?: unknown) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError('');
    controller.current?.abort();
    const pending = new AbortController();
    controller.current = pending;
    try {
      // Never retry an interrupted mutation: the server may already have saved it.
      const result = request(path, method, body, { signal: pending.signal });
      clearPassword();
      const acknowledgement = await result;
      if (method === 'DELETE' && (!acknowledgement || acknowledgement.ok !== true || acknowledgement.browser_data_retained !== false)) {
        throw new Error('无法确认配置数据已删除，请稍后检查。');
      }
      await load(pending.signal);
      if (!mounted.current || pending.signal.aborted) return;
      retainEditor();
      selectEditor(null);
      setDeleting(null);
      notify(method === 'DELETE' ? '配置及其浏览器数据已永久删除。' : '浏览器设置已保存。');
      window.dispatchEvent(new Event('browser-profiles-changed'));
      onChanged();
    } catch (reason) {
      if (!mounted.current || pending.signal.aborted) return;
      if (reason instanceof ApiError && reason.status === 401) unauthorized.current();
      const message = reason instanceof Error ? reason.message : '保存失败，请重试。';
      setError(message);
      if (!editor && !deleting) notify(message, true);
    } finally {
      clearPassword();
      busyRef.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  const cleanupResources = async () => {
    if (busyRef.current || !configuration) return;
    busyRef.current = true;
    setBusy(true);
    setCleaning(true);
    controller.current?.abort();
    const pending = new AbortController();
    controller.current = pending;
    try {
      // Cleanup has no profile payload and must not save, reload or clear an
      // unrelated editor. An interrupted request is never retried automatically.
      const result = await request<RuntimeCleanupResult>('/api/runtime/cleanup', 'POST', {}, { signal: pending.signal, scope: 'global' });
      if (!mounted.current || pending.signal.aborted) return;
      const deletedProfiles = result?.deleted_profiles === undefined && result?.browser_data_retained === true ? 0 : result?.deleted_profiles ?? NaN;
      if (!result || result.ok !== true || typeof result.browser_data_retained !== 'boolean' || result.browser_data_retained !== (deletedProfiles === 0) || [result.cleaned, result.pending, result.skipped, deletedProfiles].some(value => !Number.isSafeInteger(value) || value < 0)) {
        throw new Error('无法确认资源清理结果，请稍后检查。');
      }
      if (result.profile_count !== undefined && (!Number.isSafeInteger(result.profile_count) || result.profile_count < 0 || result.cleaned + result.pending + result.skipped !== result.profile_count)) {
        throw new Error('无法确认资源清理结果，请稍后检查。');
      }
      const details = result.pending_details === undefined ? [] : result.pending_details;
      if (!Array.isArray(details) || details.length > 64 || (result.pending === 0 && details.length > 0) || details.some(detail => !detail || typeof detail.profile_id !== 'string' || !detail.profile_id || detail.profile_id.length > 100 || typeof detail.reason !== 'string' || !detail.reason.trim() || detail.reason.length > 512)) {
        throw new Error('无法确认资源清理结果，请稍后检查。');
      }
      const reasons = [...new Set(details.map(detail => detail.reason.trim().replace(/[。；]+$/, '')))];
      const pendingNotice = reasons.length ? `待处理原因：${reasons.slice(0, 2).join('；')}${reasons.length > 2 ? '等' : ''}。` : '';
      const deletionNotice = deletedProfiles > 0 ? `已完成此前请求的 ${deletedProfiles} 个配置数据删除。` : '';
      notify(`清理结果：已清理 ${result.cleaned} 项，待处理 ${result.pending} 项，跳过 ${result.skipped} 项。${deletionNotice}${pendingNotice}`, result.pending > 0);
    } catch (reason) {
      if (!mounted.current || pending.signal.aborted) return;
      if (reason instanceof ApiError && reason.status === 401) unauthorized.current();
      notify(reason instanceof Error ? reason.message : '清理资源失败，请重试。', true);
    } finally {
      busyRef.current = false;
      if (mounted.current) { setBusy(false); setCleaning(false); }
    }
  };
  const openEditor = (profile?: BrowserProfile) => {
    if (busyRef.current) return;
    clearPassword();
    retainEditor();
    setError('');
    selectEditor({ session: ++editorSession.current, profile, name: profile?.name ?? '', enabled: profile?.enabled ?? true,
      timeout: String(profile?.idle_timeout_seconds ?? 180),
      passwordEnabled: profile?.password_enabled ?? false });
  };
  const closeEditor = () => { if (!busyRef.current) { clearPassword(); retainEditor(); selectEditor(null); setError(''); } };
  const updateEditor = (session: number, changes: Partial<Editor>) => {
    if (busyRef.current || activeEditor.current?.session !== session) return;
    selectEditor({ ...activeEditor.current, ...changes });
  };
  const submit = (event: React.FormEvent<HTMLFormElement>, session: number) => {
    event.preventDefault();
    if (!editor || activeEditor.current?.session !== session || busyRef.current || !configuration) return;
    const name = editor.name;
    const timeout = Number(editor.timeout);
    if (!validProfileName(name)) { setError('配置名称无效。'); return; }
    if (configuration.profiles.some(profile => profile.id !== editor.profile?.id && profile.name.toLowerCase() === name.toLowerCase())) { setError('此名称已存在。'); return; }
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 86400) { setError('空闲超时须为 1–86400 秒。'); return; }
    const body: Record<string, unknown> = { idle_timeout_seconds: timeout };
    if (editor.profile?.id !== 'default') body.name = name;
    // Multi-profile mode changes effective availability, never saved toggles.
    if (configuration.multi_profile || !editor.profile) body.enabled = editor.enabled;
    const password = passwords.current.get(session);
    const value = password?.value || '';
    if (editor.passwordEnabled) {
      // Every protected save requires an explicit replacement, never a secret
      // read back from the server or an implicit preservation of a blank input.
      if (!value) { setError('请输入非空密码。'); password?.focus(); return; }
      body.password = value;
    } else if (!editor.profile || editor.profile.password_enabled) {
      // Only an explicit enabled-to-disabled edit removes existing protection.
      body.password = null;
    }
    void mutate(editor.profile ? `/api/profiles/${encodeURIComponent(editor.profile.id)}` : '/api/profiles', editor.profile ? 'PATCH' : 'POST', body);
  };

  const fields = (view: RetainedEditor) => <EditorFields draft={view.draft} error={view.error} disabled={busy || editor?.session !== view.draft.session} multiProfile={Boolean(configuration?.multi_profile)} passwords={passwords} onChange={updateEditor} />;
  const actions = (draft: Editor) => <>
    <Button onClick={() => { if (activeEditor.current?.session === draft.session) closeEditor(); }} disabled={busy || editor?.session !== draft.session}>取消</Button>
    <Button type="submit" variant="contained" disabled={busy || editor?.session !== draft.session}>保存</Button>
  </>;
  const creation = editor && !editor.profile ? { draft: editor, error } : retained.create;

  return <Box component="section" id="browser" aria-labelledby="browser-settings-title">
    <Stack direction="row" className="section-heading" sx={{ alignItems: 'center', justifyContent: 'space-between', gap: 2 }}>
      <Typography id="browser-settings-title" variant="h2">浏览器设置</Typography>
      <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
        <Button startIcon={cleaning ? <CircularProgress size={16} color="inherit" /> : <CleaningServicesOutlinedIcon />} variant="outlined" onClick={() => void cleanupResources()} disabled={busy || !configuration} aria-busy={cleaning}>{cleaning ? '正在清理…' : '清理资源'}</Button>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => openEditor()} disabled={busy || !configuration?.multi_profile || configuration.profiles.length >= 16}>添加配置</Button>
      </Stack>
    </Stack>
    {!configuration ? loadError ? <Alert severity="error" action={<Button onClick={() => { setLoadError(''); void load().catch(reason => setLoadError(String(reason.message || reason))); }}>重试</Button>}>{loadError}</Alert> : <Box role="status" sx={{ p: 2 }}><CircularProgress size={20} aria-label="正在读取浏览器设置" /></Box> : <Stack spacing={2} useFlexGap>
      <FormControlLabel control={<Switch checked={configuration.multi_profile} disabled={busy} onChange={event => void mutate('/api/profiles/config', 'PUT', { multi_profile: event.target.checked })} />} label="多配置模式" />
      {configuration.profiles.map(profile => {
        const active = editor?.profile?.id === profile.id;
        const view = active ? { draft: editor, error } : retained[profile.id];
        return <Accordion key={profile.id} variant="outlined" component="article" aria-label={`浏览器配置 ${profile.name}`} expanded={active} onChange={(_event, expanded) => { if (expanded) openEditor(profile); else if (activeEditor.current?.session === view?.draft.session) closeEditor(); }} slotProps={{ transition: { onExited: () => removeExited(profile.id, view?.draft.session) } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />} disabled={busy} id={`profile-${profile.id}-summary`} aria-controls={`profile-${profile.id}-details`} aria-label={`${profile.name} 配置设置`}>
          <Stack component="span" direction="row" sx={{ width: '100%', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
            <Typography component="span" variant="h3" sx={{ flex: 1, overflowWrap: 'anywhere' }}>{profile.name}</Typography>
            <Chip component="span" size="small" label={profile.password_enabled ? '已设置密码' : '无密码'} />
            <Chip component="span" size="small" label={`空闲 ${profile.idle_timeout_seconds} 秒`} />
            <Chip component="span" size="small" label={profile.effective_enabled ? '已启用' : '已停用'} />
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          {view && <Box component="form" noValidate key={view.draft.session} aria-label={`${view.draft.name} 设置表单`} aria-hidden={!active} inert={!active} onSubmit={event => submit(event, view.draft.session)}>
            {fields(view)}
            <Stack direction="row" sx={{ mt: 2, gap: 1, justifyContent: 'flex-end', alignItems: 'center' }}>
              {profile.id !== 'default' && <Tooltip title="删除配置"><IconButton aria-label={`删除 ${profile.name}`} color="error" disabled={busy || !active} sx={{ mr: 'auto' }} onClick={() => { if (activeEditor.current?.session === view.draft.session) { closeEditor(); setDeleting(profile); } }}><DeleteOutlineIcon /></IconButton></Tooltip>}
              {actions(view.draft)}
            </Stack>
          </Box>}
        </AccordionDetails>
      </Accordion>;
      })}
    </Stack>}
    <Dialog open={Boolean(editor && !editor.profile)} onClose={closeEditor} fullWidth maxWidth="xs" aria-labelledby="profile-editor-title" slotProps={{ transition: { onExited: () => removeExited('create', creation?.draft.session) } }}>
      {creation && <Box component="form" noValidate key={creation.draft.session} aria-label="新配置 设置表单" aria-hidden={editor?.session !== creation.draft.session} inert={editor?.session !== creation.draft.session} onSubmit={event => submit(event, creation.draft.session)}><DialogTitle id="profile-editor-title">添加浏览器配置</DialogTitle><DialogContent><Box sx={{ pt: 1 }}>{fields(creation)}</Box></DialogContent><DialogActions>{actions(creation.draft)}</DialogActions></Box>}
    </Dialog>
    <Dialog open={Boolean(deleting)} onClose={() => { if (!busyRef.current) setDeleting(null); }} fullWidth maxWidth="xs" aria-labelledby="delete-profile-title"><DialogTitle id="delete-profile-title">删除配置？</DialogTitle><DialogContent><DialogContentText>{deleting?.name}：断开连接并永久删除此配置的全部浏览器数据，无法恢复。</DialogContentText>{error && <Alert severity="error">{error}</Alert>}</DialogContent><DialogActions><Button disabled={busy} onClick={() => setDeleting(null)}>取消</Button><Button color="error" variant="contained" disabled={busy} onClick={() => deleting && void mutate(`/api/profiles/${encodeURIComponent(deleting.id)}`, 'DELETE')}>删除配置</Button></DialogActions></Dialog>
  </Box>;
}
