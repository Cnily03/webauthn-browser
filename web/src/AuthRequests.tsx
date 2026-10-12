import { useEffect, useRef, useState } from 'react';
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControl, InputLabel, LinearProgress, MenuItem, Select, Stack, TextField, Typography,
} from '@mui/material';
import DevicesOutlinedIcon from '@mui/icons-material/DevicesOutlined';
import UsbOutlinedIcon from '@mui/icons-material/UsbOutlined';
import { request } from './api';
import type { AppStatus } from './types';
import { useLocalNavigationToast } from './LocalNavigationToast';
import {
  errorMessage, requestIdentity, RequestStream, statusCode,
  type ApprovalTicket, type ConnectionState, type PendingRequest, type RequestCandidate, type RequestSnapshot,
} from './requestStream';

export type AuthConnection = { state: ConnectionState; message: string };

interface Props {
  status: AppStatus;
  refreshStatus: () => Promise<AppStatus>;
  onUnauthorized: () => void;
  notify: (message: string, error?: boolean) => void;
  onConnectionChange?: (connection: AuthConnection) => void;
  navigationEpoch?: number | string;
}
interface RequestView {
  key: number;
  pending: PendingRequest;
  identity: string;
  ticket: ApprovalTicket;
  receivedAt: number;
  expiresAt: number;
}
// Keep the ledger across browser reconnect/remounts. It contains IDs only, never secrets.
const decidedRequests = new Set<string>();
const decidedStages = new Set<string>();
const stageKey = (pending: PendingRequest) => `${pending.id}:${pending.stage || 'select_key'}`;
const deadline = (remaining: number | undefined, now: number) =>
  typeof remaining === 'number' && Number.isFinite(remaining) ? now + Math.max(0, remaining) : Infinity;
const titles: Record<string, string> = {
  select_key: '选择验证器和账户', setup_password: '设置验证器密码', verify_password: '输入验证器密码',
  touch: '触摸确认', setting_password: '正在保存密码', verifying_password: '正在验证密码', signing: '正在完成验证',
};
const labels: Record<string, string> = {
  select_key: '继续', setup_password: '保存密码', verify_password: '验证密码', touch: '触摸并允许',
  setting_password: '正在保存…', verifying_password: '正在验证…', signing: '正在签名…',
};
const attestationLabel = (value?: string) => ({
  none: '无', self: '凭据自签名', basic: '证书证明', 'packed-self': '凭据自签名', 'packed-basic': '证书证明',
}[value || ''] || '未记录');
const attestationRequestLabel = (value?: string) => ({
  none: '不要求 (none)', direct: '直接证明 (direct)', indirect: '间接证明 (indirect)', enterprise: '企业证明 (enterprise)',
}[value || ''] || value || '未记录');
function Detail({ label, value }: { label: string; value: string }) {
  return <Typography variant="body2" sx={{fontWeight: 'fontWeightRegular', overflowWrap: 'anywhere'}}>
    <Box component="span" sx={{fontWeight: 'fontWeightBold'}}>{label}</Box>：{value}
  </Typography>;
}

export function AuthRequests(props: Props) {
  const localNavigation = useLocalNavigationToast();
  const latest = useRef(props);
  latest.current = props;
  const streamRef = useRef<RequestStream | null>(null);
  const active = useRef<RequestView | null>(null);
  const clearSecrets = useRef<(() => void) | null>(null);
  const serial = useRef(0);
  const [view, setView] = useState<RequestView | null>(null);

  const dismiss = () => {
    clearSecrets.current?.();
    clearSecrets.current = null;
    active.current = null;
    setView(null);
  };
  useEffect(() => {
    if (!props.status.vnc_authenticated) { localNavigation.receive(null); dismiss(); return; }
    let mounted = true;
    const stream = new RequestStream({
      refreshStatus: () => latest.current.refreshStatus(),
      onUnauthorized: () => { if (mounted) { dismiss(); latest.current.onUnauthorized(); } },
      onConnection: (state, message) => { if (mounted) latest.current.onConnectionChange?.({state, message}); },
      onLocalNavigation: event => { if (mounted) localNavigation.receive(event); },
      onSnapshot: snapshot => {
        if (!mounted) return;
        if (!snapshot) { dismiss(); return; }
        const now = Date.now();
        const pending = snapshot.connected ? snapshot.requests.filter(item =>
          typeof item?.id === 'string' && !decidedRequests.has(item.id)
          && !decidedStages.has(stageKey(item))
          && deadline(item.remaining_ms, now) > now) : [];
        let next = pending.find(item => item.id === active.current?.pending.id) || pending[0];
        if (!next) { dismiss(); return; }
        const identity = requestIdentity(next);
        const previous = active.current;
        if (previous && previous.identity === identity) {
          // Keep fields and focus on countdown-only updates, without extending expiry.
          const updated = {...previous, expiresAt: Math.min(previous.expiresAt, deadline(next.remaining_ms, now))};
          active.current = updated;
          setView(updated);
          return;
        }
        dismiss();
        if (decidedRequests.has(next.id)) {
          next = pending.find(item => !decidedRequests.has(item.id) && !decidedStages.has(stageKey(item)))!;
          if (!next) return;
        }
        const updated: RequestView = {key: ++serial.current, pending: next, identity: requestIdentity(next), ticket: stream.ticket(), receivedAt: now, expiresAt: deadline(next.remaining_ms, now)};
        active.current = updated;
        setView(updated);
      },
    });
    streamRef.current = stream;
    stream.start();
    const pagehide = () => stream.stop();
    const pageshow = (event: PageTransitionEvent) => { if (event.persisted) stream.start(); };
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('pageshow', pageshow);
    return () => {
      mounted = false;
      window.removeEventListener('pagehide', pagehide);
      window.removeEventListener('pageshow', pageshow);
      clearSecrets.current?.();
      clearSecrets.current = null;
      active.current = null;
      stream.stop();
      if (streamRef.current === stream) streamRef.current = null;
    };
  }, [props.status.vnc_authenticated, props.navigationEpoch, localNavigation.receive]);

  const expire = (shown: RequestView) => {
    if (active.current?.key !== shown.key) return;
    decidedRequests.add(shown.pending.id);
    dismiss();
  };
  const decide = async (shown: RequestView, payload: Record<string, unknown>) => {
    const stream = streamRef.current;
    if (!stream || !stream.accepts(shown.ticket) || active.current?.key !== shown.key
        || Date.now() >= (active.current?.expiresAt ?? 0) || decidedStages.has(stageKey(shown.pending))) {
      delete payload.password; delete payload.password_confirmation;
      return;
    }
    const action = payload.action;
    decidedStages.add(stageKey(shown.pending));
    if (action === 'touch' || action === 'deny') decidedRequests.add(shown.pending.id);
    clearSecrets.current?.();
    try {
      const sent = request(`/api/requests/${encodeURIComponent(shown.pending.id)}/decision`, 'POST', payload);
      delete payload.password; delete payload.password_confirmation;
      await sent;
      if (!stream.accepts(shown.ticket)) return;
      if (active.current?.key === shown.key) dismiss();
      // A GET can recover a missed stage event; the POST is never replayed.
      const cursor = stream.cursor;
      const snapshot = await request<RequestSnapshot>('/api/requests');
      stream.applyRecoverySnapshot({...snapshot, cursor: snapshot.cursor || cursor}, shown.ticket, cursor);
    } catch (error) {
      decidedRequests.add(shown.pending.id);
      if (!stream.accepts(shown.ticket)) return;
      if (active.current?.pending.id === shown.pending.id) dismiss();
      if (statusCode(error) === 401) latest.current.onUnauthorized();
      else latest.current.notify(`本次请求已关闭：${errorMessage(error)}。如需重试，请在网站重新发起请求。`, true);
    } finally {
      delete payload.password; delete payload.password_confirmation;
    }
  };

  return <>
    {props.status.vnc_authenticated && localNavigation.toast}
    {view && props.status.vnc_authenticated && <RequestDialog key={view.key} view={view} onDecision={decide} onExpire={expire} registerClear={clear => { clearSecrets.current = clear; }} />}
  </>;
}

interface DialogProps {
  view: RequestView;
  onDecision: (view: RequestView, payload: Record<string, unknown>) => Promise<void>;
  onExpire: (view: RequestView) => void;
  registerClear: (clear: (() => void) | null) => void;
}
function RequestDialog({view, onDecision, onExpire, registerClear}: DialogProps) {
  const {pending} = view;
  const stage = pending.stage || 'select_key';
  const candidates = Array.isArray(pending.candidates) ? pending.candidates : [];
  const firstEligible = () => {
    const index = candidates.findIndex(candidate => deadline(candidate.remaining_ms, view.receivedAt) > Date.now());
    return index >= 0 ? String(index) : '';
  };
  const [choice, setChoice] = useState(firstEligible);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const submittingRef = useRef(false);
  const password = useRef<HTMLInputElement | null>(null);
  const confirmation = useRef<HTMLInputElement | null>(null);
  const [now, setNow] = useState(Date.now());
  const setup = stage === 'setup_password';
  const selected = stage === 'select_key' ? (choice === '' ? undefined : candidates[Number(choice)])
    : candidates.find(item => item.key_id === pending.selected_key_id && (item.credential_id ?? null) === (pending.selected_credential_id ?? null));
  const clear = () => {
    if (password.current) password.current.value = '';
    if (confirmation.current) confirmation.current.value = '';
  };
  useEffect(() => {
    registerClear(clear);
    const passwordElement = password.current;
    const confirmationElement = confirmation.current;
    return () => {
      if (passwordElement) passwordElement.value = '';
      if (confirmationElement) confirmationElement.value = '';
      registerClear(null);
    };
  }, []);
  useEffect(() => {
    const tick = () => {
      const time = Date.now();
      setNow(time);
      if (time >= view.expiresAt) onExpire(view);
    };
    tick();
    const timer = setInterval(tick, 250);
    return () => clearInterval(timer);
  }, [view.expiresAt]);
  const expiredCandidate = (candidate: RequestCandidate) => deadline(candidate.remaining_ms, view.receivedAt) <= now;
  useEffect(() => {
    if (stage === 'select_key' && (!candidates[Number(choice)] || expiredCandidate(candidates[Number(choice)]))) setChoice(firstEligible());
  }, [now, choice, stage]);
  const busy = Boolean(pending.busy) || ['signing', 'setting_password', 'verifying_password'].includes(stage);
  const disabled = submitting || busy || !titles[stage] || now >= view.expiresAt
    || (['select_key', 'setup_password', 'verify_password', 'touch'].includes(stage) && !selected) || (Boolean(selected) && expiredCandidate(selected!));
  const submit = (action: string) => {
    if (submittingRef.current || (action !== 'deny' && disabled)) return;
    const payload: Record<string, unknown> = {action};
    if (action === 'select') {
      if (!selected || deadline(selected.remaining_ms, view.receivedAt) <= Date.now()) return;
      payload.key_id = selected.key_id;
      payload.credential_id = selected.credential_id ?? null;
    }
    if (action === 'setup_password' || action === 'verify_password') {
      const secret = password.current?.value || '';
      const repeated = confirmation.current?.value || '';
      if (action === 'setup_password' && (Array.from(secret).length < 6 || secret !== repeated)) {
        setError('验证器密码至少 6 个字符，且两次输入必须一致。'); password.current?.focus(); return;
      }
      if (action === 'verify_password' && !secret) { setError('请输入验证器密码。'); password.current?.focus(); return; }
      payload.password = secret;
      if (action === 'setup_password') payload.password_confirmation = repeated;
    }
    submittingRef.current = true;
    setSubmitting(true);
    clear();
    void onDecision(view, payload);
  };
  return <Dialog open fullWidth maxWidth="sm" aria-labelledby="request-title" aria-describedby="request-source"
    onClose={(_, reason) => { if (reason === 'escapeKeyDown') submit('deny'); }}>
    <Box component="form" noValidate onSubmit={event => { event.preventDefault(); submit(stage === 'select_key' ? 'select' : stage); }}>
      <DialogTitle id="request-title">
        <Typography component="span" variant="overline" color="text.secondary" sx={{display: 'block'}}>{pending.kind === 'create' ? '注册通行密钥' : '通行密钥登录'}</Typography>
        {titles[stage] || '等待请求同步'}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Alert severity="info" id="request-source" sx={{overflowWrap: 'anywhere'}}>
            <Detail label="RP ID" value={pending.rp_id || '未记录'} />
            <Detail label="请求来源" value={pending.origin || '未记录'} />
          </Alert>
          {stage === 'select_key' ? <FormControl fullWidth>
            <InputLabel id="request-key-label">选择验证器和账户</InputLabel>
            <Select labelId="request-key-label" label="选择验证器和账户" name="request-key" value={choice} displayEmpty autoFocus
              renderValue={() => selected ? selected.key_name || '未命名验证器' : '没有可用的验证器或账户'}
              disabled={submitting || busy} onChange={event => setChoice(event.target.value)}>
              <MenuItem value="" disabled>{candidates.length ? '请选择验证器和账户' : '没有可用的验证器或账户'}</MenuItem>
              {candidates.map((candidate, index) => <MenuItem key={`${candidate.key_id}:${candidate.credential_id || index}`} value={String(index)} disabled={expiredCandidate(candidate)} sx={{whiteSpace: 'normal', overflowWrap: 'anywhere'}}>
                <Stack spacing={.5} sx={{width: '100%', minWidth: 0}}>
                  <Stack direction="row" useFlexGap sx={{alignItems: 'center', flexWrap: 'wrap', gap: 1}}>
                    {candidate.attachment === 'platform' ? <DevicesOutlinedIcon fontSize="small" /> : candidate.attachment === 'cross-platform' ? <UsbOutlinedIcon fontSize="small" /> : null}
                    <Typography variant="body2" sx={{overflowWrap: 'anywhere', minWidth: 0}}>{candidate.key_name || '未命名验证器'}</Typography>
                    <Chip size="small" label={candidate.attachment === 'platform' ? '设备验证器' : candidate.attachment === 'cross-platform' ? 'USB 验证器' : '类型未记录'} sx={{ml: 'auto'}} />
                  </Stack>
                  {candidate.user_name && <Detail label="用户名" value={candidate.user_name} />}
                  {candidate.display_name && <Detail label="显示名" value={candidate.display_name} />}
                  {!candidate.user_name && !candidate.display_name && (candidate.user_handle || candidate.credential_id) && <Detail label={candidate.user_handle ? '用户 ID（Base64）' : '凭证 ID（Base64）'} value={candidate.user_handle || candidate.credential_id!} />}
                </Stack>
              </MenuItem>)}
            </Select>
          </FormControl> : null}
          {selected && <Stack spacing={.75} aria-label="当前验证器详情" aria-live="polite" sx={{overflowWrap: 'anywhere'}}>
            <Stack direction="row" useFlexGap sx={{alignItems: 'center', flexWrap: 'wrap', gap: 1}}>
              <Stack direction="row" spacing={1} sx={{alignItems: 'center', minWidth: 0, flex: '1 1 auto'}}>
                {selected.attachment === 'platform' ? <DevicesOutlinedIcon color="action" /> : selected.attachment === 'cross-platform' ? <UsbOutlinedIcon color="action" /> : null}
                <Detail label="当前验证器" value={selected.key_name || '未命名验证器'} />
              </Stack>
              <Chip size="small" label={selected.attachment === 'platform' ? '设备验证器' : selected.attachment === 'cross-platform' ? 'USB 验证器' : '类型未记录'} sx={{ml: 'auto'}} />
            </Stack>
            {selected.provider_label && <Detail label="Provider" value={selected.provider_label} />}
            {(selected.model_aaguid || selected.attestation_aaguid) && <Detail label="AAGUID" value={selected.model_aaguid || selected.attestation_aaguid!} />}
            {selected.user_name && <Detail label="用户名" value={selected.user_name} />}
            {selected.display_name && <Detail label="显示名" value={selected.display_name} />}
            {!selected.user_name && !selected.display_name && (selected.user_handle || selected.credential_id) && <Detail label={selected.user_handle ? '用户 ID（Base64）' : '凭证 ID（Base64）'} value={selected.user_handle || selected.credential_id!} />}
          </Stack>}
          {pending.kind === 'create' && <Stack spacing={.75}>
            <Detail label="网站要求的注册证明" value={attestationRequestLabel(pending.attestation_requested)} />
            <Detail label="本次提供的注册证明" value={selected ? attestationLabel(selected.attestation_effective) : '选择验证器后显示'} />
          </Stack>}
          {(setup || stage === 'verify_password') && <>
            <TextField autoFocus fullWidth type="password" inputRef={password} name="request-password" label={setup ? '新验证器密码（至少 6 个字符）' : '验证器密码'} autoComplete={setup ? 'new-password' : 'current-password'} disabled={submitting || busy} required />
            {setup && <TextField fullWidth type="password" inputRef={confirmation} name="request-password-confirmation" label="再次输入验证器密码" autoComplete="new-password" disabled={submitting || busy} required />}
          </>}
          {!titles[stage] && <Alert severity="error">暂时无法识别验证阶段，请拒绝并重新发起请求。</Alert>}
          <Stack direction="row" spacing={1} sx={{flexWrap: 'wrap', gap: 1}}>
            {Number.isFinite(view.expiresAt) && <Chip size="small" label={`剩余 ${Math.max(0, Math.ceil((view.expiresAt - now) / 1000))} 秒`} />}
          </Stack>
          {error && <Alert severity="error">{error}</Alert>}
          {selected && expiredCandidate(selected) && <Alert severity="warning" color="info">此验证器的确认时间已过，请在网站重新发起请求。</Alert>}
          {(busy || submitting) && <LinearProgress aria-label="正在处理验证请求" />}
        </Stack>
      </DialogContent>
      <DialogActions sx={{px: 3, pb: 2}}>
        <Button onClick={() => submit('deny')} disabled={submitting} autoFocus={stage === 'touch'}>拒绝请求</Button>
        <Button type="submit" variant="contained" disabled={disabled}>{pending.busy ? '正在处理…' : labels[stage] || '等待同步'}</Button>
      </DialogActions>
    </Box>
  </Dialog>;
}
