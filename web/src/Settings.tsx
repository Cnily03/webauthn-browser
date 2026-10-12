import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { Accordion, AccordionActions, AccordionDetails, AccordionSummary, Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Divider, FormControlLabel, IconButton, List, ListItemButton, ListItemText, Paper, Stack, Switch, TextField, Tooltip, Typography } from '@mui/material';
import UsbIcon from '@mui/icons-material/Usb';
import DevicesIcon from '@mui/icons-material/Devices';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutlined';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import AddIcon from '@mui/icons-material/Add';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import VerifiedUserOutlinedIcon from '@mui/icons-material/VerifiedUserOutlined';
import KeyOutlinedIcon from '@mui/icons-material/KeyOutlined';
import { ApiError, request } from './api';
import type { AppStatus, Credential, VirtualKey } from './types';
import KeyForm, { attestationLabel, attestationRequestLabel, KeyIdentity, type KeyFields } from './KeyForm';
import { BackupDialogs } from './BackupDialogs';
import { useGuardedNavigation, type NavigationGuard } from './useGuardedNavigation';

type Notify = (message: string, error?: boolean) => void;
interface SettingsProps { status: AppStatus; refreshStatus: () => Promise<AppStatus>; onUnauthorized: () => void; notify: Notify; registerNavigationGuard?: (guard: NavigationGuard | null) => void; navigation?: {url: string; navigate: (destination: string) => void} }
interface Confirmation { title: string; message: string; label: string; danger?: boolean; action: () => void | Promise<void> }

function SecurityCard({ scope, title, description, enabled, busy, onSave, onDisable }: { scope: 'vnc' | 'settings'; title: string; description: string; enabled: boolean; busy: boolean; onSave: (password: string) => Promise<void>; onDisable: () => void }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const password = useRef<HTMLInputElement>(null);
  const confirmation = useRef<HTMLInputElement>(null);
  const passwordRef = useCallback((node: HTMLInputElement | null) => { if (!node && password.current) password.current.value = ''; password.current = node; }, []);
  const confirmationRef = useCallback((node: HTMLInputElement | null) => { if (!node && confirmation.current) confirmation.current.value = ''; confirmation.current = node; }, []);
  const submitting = useRef(false);
  const [saving, setSaving] = useState(false);
  const clear = () => { if (password.current) password.current.value = ''; if (confirmation.current) confirmation.current.value = ''; };
  const close = () => { if (submitting.current) return; clear(); setOpen(false); setError(''); };
  useEffect(() => { window.addEventListener('pagehide', clear); return () => { window.removeEventListener('pagehide', clear); clear(); }; }, []);
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current) return;
    if (password.current?.value !== confirmation.current?.value) { setError('两次输入的密码不一致。'); confirmation.current?.focus(); return; }
    submitting.current = true;
    setSaving(true);
    setError('');
    try {
      const savingPassword = onSave(password.current?.value || '');
      clear();
      await savingPassword;
      setOpen(false);
    } catch (err) { setError(err instanceof Error ? err.message : '密码保存失败。'); }
    finally { clear(); submitting.current = false; setSaving(false); }
  }
  return <>
    <Paper variant="outlined" className="security-card"><Stack spacing={2}><Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 1 }}><Typography variant="h3">{title}</Typography><Chip label={enabled ? '已启用' : '未设置'} color={enabled ? 'success' : 'default'} variant="outlined" /></Stack><Typography variant="body2" color="text.secondary">{description}</Typography><Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: "wrap" }}><Button variant="outlined" onClick={() => { setError(''); setOpen(true); }} disabled={busy}>{enabled ? '更改密码' : '设置密码'}</Button>{enabled && <Button color="error" onClick={onDisable} disabled={busy}>停用密码</Button>}</Stack></Stack></Paper>
    <Dialog open={open} onClose={close} fullWidth maxWidth="xs" aria-labelledby={`${scope}-password-title`}>
      <Box component="form" onSubmit={submit}><DialogTitle id={`${scope}-password-title`}>{enabled ? '更改' : '设置'}{title}</DialogTitle><DialogContent><Stack spacing={2.5} sx={{ pt: 1 }}><TextField inputRef={passwordRef} autoFocus label="新密码" name={`${scope}-new-password`} type="password" autoComplete="new-password" disabled={saving} /><TextField inputRef={confirmationRef} label="再次输入" name={`${scope}-password-confirmation`} type="password" autoComplete="new-password" disabled={saving} /><Typography variant="body2" color="text.secondary">支持任意字符，不限制长度或复杂度。空密码也会启用密码验证；要关闭验证，请使用“停用密码”。</Typography>{error && <Alert severity="error">{error}</Alert>}</Stack></DialogContent><DialogActions><Button onClick={close} disabled={saving}>取消</Button><Button type="submit" variant="contained" disabled={saving}>{saving ? '正在保存…' : '保存密码'}</Button></DialogActions></Box>
    </Dialog>
  </>;
}

function CredentialDetails({ credential, busy, onDelete, notify }: { credential: Credential; busy: boolean; onDelete: () => void; notify: Notify }) {
  const prefix = useId();
  const proof = credential.registration_attestation ? attestationLabel(credential.registration_attestation) : '未记录';
  const username = credential.user_name || '未记录';
  const identity = credential.registration_identity && typeof credential.registration_identity === 'object' ? credential.registration_identity as Record<string, unknown> : {};
  const identityText = (name: string) => typeof identity[name] === 'string' ? identity[name] as string : '未记录';
  const dateValue = credential.registered_at;
  const parsedDate = dateValue !== undefined && dateValue !== null ? new Date(dateValue) : null;
  const registeredAt = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '未记录';
  const accountValues: Array<[string, string, boolean?]> = [
    ['RP ID', credential.rp_id || '未记录'],
    ['用户名', username],
    ['显示名称', credential.user_display_name || '未记录'],
    ['签名计数', typeof credential.sign_count === 'number' ? String(credential.sign_count) : '未记录'],
    ['可发现凭据', typeof credential.resident === 'boolean' ? (credential.resident ? '是' : '否') : '未记录'],
    ['用户 ID（Base64）', credential.user_handle || '未记录', Boolean(credential.user_handle)],
    ['凭证 ID（Base64）', credential.credential_id || '未记录', Boolean(credential.credential_id)],
  ];
  const registrationValues: Array<[string, string, boolean?]> = [
    ['注册时间', registeredAt],
    ['网站要求的注册证明', attestationRequestLabel(credential.registration_requested_attestation)],
    ['注册时 AAGUID', credential.registration_aaguid || '未记录'],
    ['注册时提供的证明', proof],
  ];
  if (Object.keys(identity).length > 0) {
    registrationValues.push(['注册时 Provider', identityText('providerLabel')]);
    registrationValues.push(['注册时配置 AAGUID', identityText('modelAaguid')]);
    if (typeof identity.attachment === 'string') registrationValues.push(['注册时类型', identity.attachment === 'cross-platform' ? 'USB 验证器' : '设备验证器']);
    registrationValues.push(['注册时可发现能力', typeof identity.residentKeySupported === 'boolean' ? identity.residentKeySupported ? '支持' : '不支持新注册' : '未记录']);
    registrationValues.push(['注册时配置证明方式', typeof identity.attestationMode === 'string' ? attestationLabel(identity.attestationMode) : '未记录']);
  }
  const groups = [{ title: '凭据信息', values: accountValues }, { title: '注册记录', values: registrationValues }];
  const copy = async (label: string, value: string) => { try { if (!navigator.clipboard?.writeText) throw new Error('当前浏览器不支持复制，请选中文字手动复制。'); await navigator.clipboard.writeText(value); notify(`${label}已复制。`); } catch (error) { notify(error instanceof Error ? error.message : '复制失败，请手动选择文字复制。', true); } };
  return <Accordion className="credential">
    <AccordionSummary id={`${prefix}-summary`} aria-controls={`${prefix}-details`} expandIcon={<ExpandMoreIcon />} aria-label={`RP ID：${credential.rp_id || '未知网站'}，用户名：${username}`}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}>
        <KeyOutlinedIcon color="action" sx={{ flexShrink: 0 }} />
        <Box sx={{ minWidth: 0 }}><Typography variant="subtitle1" sx={{ fontWeight: 'fontWeightBold', overflowWrap: 'anywhere' }}>{credential.rp_id || '未知网站'}</Typography><Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'fontWeightRegular', overflowWrap: 'anywhere' }}>{username}</Typography></Box>
      </Stack>
    </AccordionSummary>
    <AccordionDetails>
      <Stack spacing={2.5} divider={<Divider />}>
        {groups.map(({ title, values }) => <Box component="section" key={title} aria-label={title}>
          <Typography variant="subtitle2" sx={{ mb: 2 }}>{title}</Typography>
          <Box component="dl" className="credential-grid detail-grid">{values.map(([name, value, canCopy]) => <Box key={name} sx={name.includes('Base64') || name.includes('AAGUID') ? { gridColumn: '1 / -1' } : undefined}>
            <Stack direction="row" sx={{ alignItems: 'flex-start', justifyContent: 'space-between', gap: 1 }}><Box sx={{ minWidth: 0 }}><Typography component="dt" variant="body2" color="text.secondary" sx={{ display: 'inline', fontWeight: 'fontWeightBold' }}>{name}：</Typography><Typography component="dd" variant="body2" sx={{ display: 'inline', fontWeight: 'fontWeightRegular' }}>{value}</Typography></Box>{canCopy && <Tooltip title={`复制${name}`}><IconButton aria-label={`复制${name}`} size="small" onClick={event => { event.stopPropagation(); void copy(name, value); }}><ContentCopyIcon fontSize="small" /></IconButton></Tooltip>}</Stack>
          </Box>)}</Box>
        </Box>)}
      </Stack>
    </AccordionDetails>
    <Divider />
    <AccordionActions><Button color="error" onClick={onDelete} disabled={busy} startIcon={<DeleteOutlineIcon />}>删除此通行密钥</Button></AccordionActions>
  </Accordion>;
}

function KeyHeader({ keyData, compact = false }: { keyData: VirtualKey; compact?: boolean }) {
  return <Stack className="key-header" direction="row" useFlexGap sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
    <Box sx={{ flex: '1 1 auto', minWidth: 0, maxWidth: '100%' }}>
      <Stack className="key-name" direction="row" sx={{ alignItems: 'center', gap: 1 }}>
        {keyData.attachment === 'cross-platform' ? <UsbIcon fontSize="small" color="primary" titleAccess="USB 验证器" sx={{ flexShrink: 0 }} /> : <DevicesIcon fontSize="small" color="primary" titleAccess="设备验证器" sx={{ flexShrink: 0 }} />}
        <Typography id={compact ? undefined : 'selected-key-title'} component={compact ? 'span' : 'h3'} variant={compact ? 'body2' : 'h3'} sx={{ fontWeight: 'fontWeightBold', minWidth: 0, overflowWrap: 'anywhere' }}>{keyData.name || '未命名验证器'}</Typography>
      </Stack>
      {!compact && <Typography variant="body2" color="text.secondary" sx={{ mt: .75, overflowWrap: 'anywhere' }}>{keyData.provider_label || keyData.provider || 'webauthn-browser'}</Typography>}
    </Box>
    <Stack className="key-badges" direction="row" useFlexGap sx={{ ml: 'auto', justifyContent: 'flex-end', flexWrap: 'wrap', gap: .5, maxWidth: '100%' }}>
      <Chip label={keyData.attachment === 'cross-platform' ? 'USB 密钥' : '设备密钥'} color={keyData.attachment === 'cross-platform' ? 'primary' : 'info'} />
      <Chip label={keyData.enabled ? '已启用' : '已停用'} color={keyData.enabled ? 'success' : 'default'} />
    </Stack>
  </Stack>;
}

function KeyDetails({ keyData, busy, onEdit, onToggle, onDelete, onDeleteCredential, notify }: { keyData: VirtualKey; busy: boolean; onEdit: () => void; onToggle: (enabled: boolean) => void; onDelete: () => void; onDeleteCredential: (credential: Credential) => void; notify: Notify }) {
  const prefix = useId();
  const credentials = Array.isArray(keyData.credentials) ? keyData.credentials : [];
  const certificate = keyData.attestation_certificate;
  return <Paper variant="outlined" component="article" className="key-card" aria-labelledby="selected-key-title">
    <Stack spacing={2.5}>
      <KeyHeader keyData={keyData} />
      <Stack direction="row" spacing={2} className="key-controls" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
        <FormControlLabel control={<Switch checked={Boolean(keyData.enabled)} onChange={e => onToggle(e.target.checked)} disabled={busy} />} label="启用验证器" />
        <Box className="key-actions"><Button variant="outlined" onClick={onEdit} disabled={busy}>编辑设置</Button><Tooltip title="删除验证器"><IconButton color="error" aria-label="删除" onClick={onDelete} disabled={busy}><DeleteOutlineIcon fontSize="small" /></IconButton></Tooltip></Box>
      </Stack>
      <Stack direction="row" useFlexGap sx={{ flexWrap: 'wrap', gap: .75 }}>{[`确认 ${keyData.presence_timeout_seconds ?? 120} 秒`, keyData.resident_key_supported === false ? '不可发现' : '可发现', attestationLabel(keyData.attestation_mode), keyData.pin_configured ? '已设置验证器密码' : '按网站要求设密码'].map(text => <Chip key={text} label={text} />)}</Stack>
      {certificate?.registration_usable === false && <Alert severity="warning" color="info"><Typography variant="subtitle2">证明证书需要处理</Typography>{certificate.warning || '此证书无法用于新的证书证明注册。请创建新的证书身份；保留旧验证器可继续登录已有凭据。'}</Alert>}
      <Box>
        <Accordion>
          <AccordionSummary id={`${prefix}-identity-summary`} aria-controls={`${prefix}-identity-details`} expandIcon={<ExpandMoreIcon />}><Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}><FingerprintIcon color="action" /><Typography variant="subtitle2">验证器身份</Typography></Stack></AccordionSummary>
          <AccordionDetails><KeyIdentity keyData={keyData} /></AccordionDetails>
        </Accordion>
        {certificate && <Accordion>
          <AccordionSummary id={`${prefix}-certificate-summary`} aria-controls={`${prefix}-certificate-details`} expandIcon={<ExpandMoreIcon />}><Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}><VerifiedUserOutlinedIcon color="action" /><Typography variant="subtitle2">证明证书</Typography></Stack></AccordionSummary>
          <AccordionDetails><Box component="dl" className="certificate-grid detail-grid">
            <Box sx={{ gridColumn: '1 / -1' }}><Typography component="dt" variant="body2" color="text.secondary" sx={{ display: 'inline', fontWeight: 'fontWeightBold' }}>证书主题：</Typography><Typography component="dd" variant="body2" sx={{ display: 'inline', fontWeight: 'fontWeightRegular' }}>{certificate.subject || '已配置'}</Typography></Box>
            {certificate.not_after && <Box><Typography component="dt" variant="body2" color="text.secondary" sx={{ display: 'inline', fontWeight: 'fontWeightBold' }}>到期时间：</Typography><Typography component="dd" variant="body2" sx={{ display: 'inline', fontWeight: 'fontWeightRegular' }}>{certificate.not_after}</Typography></Box>}
          </Box></AccordionDetails>
        </Accordion>}
      </Box>
      <Box><Typography variant="subtitle2" sx={{ mb: 1.5 }}>{credentials.length} 个通行密钥</Typography>{credentials.length ? credentials.map(credential => <CredentialDetails key={credential.credential_id} credential={credential} busy={busy} notify={notify} onDelete={() => onDeleteCredential(credential)} />) : <Typography variant="body2" color="text.secondary">在浏览器中向网站注册后，通行密钥会显示在这里。</Typography>}</Box>
    </Stack>
  </Paper>;
}

// Keep existing bookmarks working; all navigation emits the canonical anchor.
function readSettingsSection(url: string) {
  return ['#authenticator', '#keys'].includes(new URL(url).hash) ? 'authenticator' : 'security';
}

export default function Settings({ status, refreshStatus, onUnauthorized, notify, registerNavigationGuard, navigation }: SettingsProps) {
  const [keys, setKeys] = useState<VirtualKey[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<'create' | 'edit' | null>(null);
  const [security, setSecurity] = useState(status);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const dirtyRef = useRef(false);
  const mounted = useRef(true);
  const generation = useRef(0);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [confirming, setConfirming] = useState(false);
  const confirmBusy = useRef(false);
  const addButton = useRef<HTMLButtonElement>(null);
  const editButtonReturn = useRef(false);
  const loadData = useCallback(async () => {
    const current = ++generation.current;
    const [securityResult, keyResult] = await Promise.all([
      request<Partial<AppStatus>>('/api/security'),
      request<{ keys: VirtualKey[] }>('/api/keys'),
    ]);
    if (!mounted.current || current !== generation.current) return;
    const latestKeys = Array.isArray(keyResult.keys) ? keyResult.keys : [];
    setSecurity(previous => ({ ...previous, ...securityResult }));
    setKeys(latestKeys);
    setSelectedId(previous => latestKeys.some(key => key.id === previous) ? previous : latestKeys[0]?.id ?? null);
    setLoadError('');
  }, []);
  useEffect(() => {
    mounted.current = true;
    loadData().catch(error => { if (!mounted.current) return; setLoadError(error instanceof Error ? error.message : '读取设置失败。'); if (error instanceof ApiError && error.status === 401) onUnauthorized(); }).finally(() => { if (mounted.current) setLoading(false); });
    return () => { mounted.current = false; generation.current += 1; };
  }, [loadData, onUnauthorized]);
  useEffect(() => { setSecurity(status); }, [status]);
  useEffect(() => {
    const unload = (event: BeforeUnloadEvent) => { if (dirtyRef.current) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', unload);
    return () => { window.removeEventListener('beforeunload', unload); };
  }, []);
  const failure = (error: unknown) => { if (error instanceof ApiError && error.status === 401) onUnauthorized(); notify(error instanceof Error ? error.message : '操作失败，请重试。', true); };
  const guarded = useCallback<NavigationGuard>((action) => {
    if (busyRef.current) return false;
    if (dirtyRef.current) {
      setConfirmation({ title: '放弃尚未保存的更改？', message: '验证器设置尚未保存。离开编辑后，输入的证书和私钥也会清空。', label: '放弃更改', action: () => { dirtyRef.current = false; action(); } });
      return false;
    }
    action(); return true;
  }, []);
  const guardNavigation = useCallback<NavigationGuard>(action => guarded(() => { setEditor(null); action(); }), [guarded]);
  const standaloneNavigation = useGuardedNavigation(guardNavigation, !navigation);
  const acceptedNavigation = navigation || standaloneNavigation;
  const section = readSettingsSection(acceptedNavigation.url);
  useEffect(() => { if (section !== 'authenticator') { setEditor(null); dirtyRef.current = false; } }, [section]);
  useEffect(() => {
    registerNavigationGuard?.(guardNavigation);
    return () => registerNavigationGuard?.(null);
  }, [guardNavigation, registerNavigationGuard]);
  const mutate = async (action: () => Promise<void>, message: string) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try { await action(); await loadData(); notify(message); }
    catch (error) { failure(error); }
    finally { busyRef.current = false; if (mounted.current) setBusy(false); }
  };
  const savePassword = async (scope: 'vnc' | 'settings', password: string) => {
    if (busyRef.current) throw new Error('请等待当前操作完成。');
    busyRef.current = true;
    setBusy(true);
    try { const pending = request('/api/security', 'PUT', { scope, password }); password = ''; await pending; const latest = await refreshStatus(); if (latest.settings_authenticated) await loadData(); notify('密码已保存。该范围的已有会话已失效；需要时请重新解锁。'); }
    catch (error) { if (error instanceof ApiError && error.status === 401) onUnauthorized(); throw error; }
    finally { password = ''; busyRef.current = false; if (mounted.current) setBusy(false); }
  };
  const disablePassword = (scope: 'vnc' | 'settings', title: string) => setConfirmation({ title: `停用${title}？`, message: '可以访问此服务的人将无需该密码即可进入。此操作只影响对应范围。', label: '停用密码', danger: true, action: () => mutate(async () => { await request('/api/security', 'PUT', { scope, password: null }); await refreshStatus(); }, `${title}已停用。`) });
  const selected = keys.find(key => key.id === selectedId);
  const saveKey = async (fields: KeyFields) => {
    if (busyRef.current) throw new Error('请等待当前操作完成。');
    busyRef.current = true;
    setBusy(true);
    try {
      if (editor === 'edit' && selected) await request(`/api/keys/${encodeURIComponent(selected.id)}`, 'PATCH', fields);
      else { const created = await request<{ key?: VirtualKey }>('/api/keys', 'POST', { ...fields, enabled: true, automatic_presence: false, simulated_uv: false }); if (created.key?.id) setSelectedId(created.key.id); }
      dirtyRef.current = false;
      await loadData();
      setEditor(null);
      editButtonReturn.current = true;
      notify(editor === 'edit' ? '验证器设置已更新。' : '虚拟验证器已添加。');
    } catch (error) { if (error instanceof ApiError && error.status === 401) onUnauthorized(); throw error; }
    finally { busyRef.current = false; if (mounted.current) setBusy(false); }
  };
  useEffect(() => { if (!editor && editButtonReturn.current) { editButtonReturn.current = false; document.querySelector<HTMLButtonElement>('.key-controls button')?.focus(); } }, [editor]);
  const onRestored = async () => { setEditor(null); dirtyRef.current = false; await loadData(); };
  const confirm = async () => {
    if (!confirmation || confirmBusy.current) return;
    confirmBusy.current = true;
    setConfirming(true);
    try { await confirmation.action(); setConfirmation(null); }
    catch (error) { failure(error); }
    finally { confirmBusy.current = false; if (mounted.current) setConfirming(false); }
  };
  return <Box className="settings-page">
    <Box component="header" className="settings-heading"><Typography variant="overline" color="text.secondary">浏览器与验证器</Typography><Typography variant="h1">设置</Typography></Box>
    <Box className="settings-layout" sx={{ display: { xs: 'block', md: 'grid' }, gridTemplateColumns: '176px minmax(0, 1fr)', alignItems: 'start', gap: 3 }}>
      <Paper component="nav" className="section-nav" variant="outlined" aria-label="设置分类"><List disablePadding>{[['security', '安全设置'], ['authenticator', '验证器管理']].map(([id, label]) => <ListItemButton key={id} component="a" href={`#${id}`} selected={section === id} aria-current={section === id ? 'page' : undefined} onClick={event => { event.preventDefault(); acceptedNavigation.navigate(`#${id}`); }}><ListItemText primary={label} /></ListItemButton>)}</List></Paper>
      <Box className="settings-sections">
        {loading ? <Stack className="settings-loading" role="status" direction="row" spacing={2} sx={{ alignItems: "center" }}><CircularProgress size={22} /><Typography>正在读取设置…</Typography></Stack> : loadError ? <Alert severity="error" action={<Button onClick={() => { setLoading(true); loadData().catch(failure).finally(() => setLoading(false)); }}>重试</Button>}>{loadError}</Alert> : <>
          {section === 'security' && <Box component="section" id="security" aria-labelledby="security-title">
            <Box className="section-heading"><Typography id="security-title" variant="h2">安全设置</Typography><Typography variant="body2" color="text.secondary">分别保护浏览器和设置页。两种密码独立，按需开启。</Typography></Box>
            <Box className="security-grid" sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', sm: 'repeat(2, minmax(0, 1fr))', md: 'minmax(0, 1fr)', lg: 'repeat(2, minmax(0, 1fr))' }, gap: 2 }}><SecurityCard scope="vnc" title="浏览器访问密码" description="控制远程桌面与浏览器连接。" enabled={Boolean(security.vnc_password_enabled)} busy={busy} onSave={value => savePassword('vnc', value)} onDisable={() => disablePassword('vnc', '浏览器访问密码')} /><SecurityCard scope="settings" title="设置管理密码" description="控制安全设置、验证器与通行密钥管理。" enabled={Boolean(security.settings_password_enabled)} busy={busy} onSave={value => savePassword('settings', value)} onDisable={() => disablePassword('settings', '设置管理密码')} /></Box>
          </Box>}
          {section === 'authenticator' && <Box component="section" id="authenticator" aria-labelledby="authenticator-title">
            <Stack direction="row" className="section-heading" sx={{ alignItems: "flex-start", justifyContent: "space-between", gap: 2 }}><Box><Stack direction="row" sx={{ alignItems: "center", gap: 1 }}><Typography id="authenticator-title" variant="h2">验证器管理</Typography><Chip label={`${keys.length} 个`} /></Stack><Typography variant="body2" color="text.secondary" sx={{ mt: .7 }}>选择验证器查看通行密钥，或编辑日常设置。</Typography></Box><Button ref={addButton} variant="contained" onClick={() => { if (editor === 'create') { document.querySelector<HTMLInputElement>('[name="key-name"]')?.focus(); return; } guarded(() => { setEditor('create'); dirtyRef.current = false; }); }} startIcon={<AddIcon />} aria-controls="key-detail" aria-expanded={editor === 'create'} disabled={busy}>添加验证器</Button></Stack>
            <Box className={`keys-workspace${keys.length ? '' : ' is-empty'}`} sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', sm: keys.length ? '176px minmax(0, 1fr)' : 'minmax(0, 1fr)', lg: keys.length ? '208px minmax(0, 1fr)' : 'minmax(0, 1fr)' }, alignItems: 'start', gap: 2 }}>
              {keys.length > 0 && <Paper variant="outlined" className="keys-list"><List disablePadding aria-label="选择验证器">{keys.map(key => <ListItemButton key={key.id} selected={editor !== 'create' && selectedId === key.id} aria-pressed={editor !== 'create' && selectedId === key.id} aria-controls="key-detail" disabled={busy} onClick={() => guarded(() => { setSelectedId(key.id); setEditor(null); })}><ListItemText disableTypography primary={<KeyHeader keyData={key} compact />} secondary={<><Typography component="span" variant="caption" sx={{ display: 'block', mt: .75 }}>{key.credentials?.length ?? 0} 个通行密钥</Typography>{key.attestation_certificate?.registration_usable === false && <Typography component="span" variant="caption" color="info.main">证书需处理</Typography>}</>} /></ListItemButton>)}</List></Paper>}
              <Box id="key-detail" className="key-detail" role="region" aria-label="验证器详情">
                {editor ? <KeyForm key={editor === 'create' ? 'new-key' : selectedId} keyData={editor === 'edit' ? selected : undefined} onSave={saveKey} onDirtyChange={value => { dirtyRef.current = value; }} onCancel={() => { setEditor(null); dirtyRef.current = false; if (editor === 'create') addButton.current?.focus(); else editButtonReturn.current = true; }} /> : selected ? <KeyDetails key={selected.id} keyData={selected} busy={busy} notify={notify} onEdit={() => setEditor('edit')} onToggle={enabled => void mutate(async () => { await request(`/api/keys/${encodeURIComponent(selected.id)}`, 'PATCH', { enabled }); }, '验证器设置已更新。')} onDelete={() => setConfirmation({ title: `删除“${selected.name || '未命名验证器'}”？`, message: '删除验证器会同时移除其通行密钥。', label: '删除验证器', danger: true, action: () => mutate(async () => { await request(`/api/keys/${encodeURIComponent(selected.id)}`, 'DELETE'); }, '验证器已删除。') })} onDeleteCredential={credential => setConfirmation({ title: '删除此通行密钥？', message: `删除 ${credential.rp_id || '此网站'} 的通行密钥后可能无法登录，且无法撤销。`, label: '删除此通行密钥', danger: true, action: () => mutate(async () => { await request(`/api/keys/${encodeURIComponent(selected.id)}/credentials`, 'DELETE', { credential_id: credential.credential_id }); }, '通行密钥已删除。') })} /> : <Paper variant="outlined" className="empty-keys"><Typography className="empty-key-symbol" aria-hidden="true">⚿</Typography><Typography variant="h3">还没有验证器</Typography><Typography variant="body2" color="text.secondary">添加一个设备验证器或 USB 验证器，开始在网站注册通行密钥。</Typography></Paper>}
              </Box>
            </Box>
            <Divider sx={{ my: 2.5 }} />
            <Box className="backup-row"><Box><Typography variant="h3">备份与恢复</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: .5 }}>备份含未加密私钥，请离线妥善保存。恢复前会预览并要求下载安全备份。</Typography></Box><BackupDialogs csrfToken={status.csrf_token} onRestored={onRestored} onUnauthorized={onUnauthorized} notify={notify} /></Box>
          </Box>}
        </>}
      </Box>
    </Box>
    <Dialog open={Boolean(confirmation)} onClose={() => { if (!confirmBusy.current) setConfirmation(null); }} fullWidth maxWidth="xs" aria-labelledby="confirmation-title"><DialogTitle id="confirmation-title">{confirmation?.title}</DialogTitle><DialogContent><DialogContentText>{confirmation?.message}</DialogContentText></DialogContent><DialogActions><Button onClick={() => setConfirmation(null)} disabled={confirming}>取消</Button><Button onClick={() => void confirm()} variant="contained" color={confirmation?.danger ? 'error' : 'primary'} disabled={confirming}>{confirming ? '正在处理…' : confirmation?.label}</Button></DialogActions></Dialog>
  </Box>;
}
