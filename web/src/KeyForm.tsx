import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, TextField, Tooltip, Typography } from '@mui/material';
import UsbIcon from '@mui/icons-material/Usb';
import DevicesIcon from '@mui/icons-material/Devices';
import RefreshIcon from '@mui/icons-material/Refresh';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import type { VirtualKey } from './types';
import { monospaceFontFamily, monospaceInputSx } from './controlTypography';

export const anonymousAaguid = '00000000-0000-0000-0000-000000000000';
export const attestationLabel = (mode?: string) => ({ none: '无证明', self: '凭据自签名', basic: '证书证明', 'packed-self': '凭据自签名', 'packed-basic': '证书证明' }[mode || 'none'] || '未记录');
export const attestationRequestLabel = (mode?: string | null) => ({ none: '不要求 (none)', direct: '直接证明 (direct)', indirect: '间接证明 (indirect)', enterprise: '企业证明 (enterprise)' }[mode || ''] || mode || '未记录');
export function normalizeAaguid(input: string): string | null {
  const value = input.trim();
  if (!/^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.test(value)) return null;
  const hex = value.replace(/-/g, '').toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export function KeyIdentity({ keyData }: { keyData: Partial<VirtualKey> }) {
  const entries = [
    ['Provider', keyData.provider_label || keyData.provider || 'webauthn-browser'],
    ['类型', keyData.attachment === 'cross-platform' ? 'USB 验证器' : '设备验证器'],
    ['AAGUID', keyData.model_aaguid || keyData.aaguid || anonymousAaguid],
    ['可发现凭据', keyData.resident_key_supported === false ? '不支持新注册' : '支持'],
    ['注册证明', attestationLabel(keyData.attestation_mode)],
  ];
  return <Box component="dl" className="identity-grid detail-grid">{entries.map(([label, value]) => <Box key={label} sx={label === 'AAGUID' ? { gridColumn: '1 / -1' } : undefined}><Typography component="dt" variant="body2" color="text.secondary" sx={{ display: 'inline', fontWeight: 'fontWeightBold' }}>{label}：</Typography><Typography component="dd" variant="body2" sx={{ display: 'inline', fontWeight: 'fontWeightRegular', fontFamily: label === 'AAGUID' ? monospaceFontFamily : undefined }}>{value}</Typography></Box>)}</Box>;
}
export type KeyFields = {
  name: string;
  provider_label: string;
  presence_timeout_seconds: number;
  model_aaguid?: string;
  attachment?: string;
  resident_key_supported?: boolean;
  attestation_mode?: string;
  attestation?: { kind: 'generate' | 'import'; country?: string; organization?: string; common_name?: string; valid_days?: number; certificate_chain_pem?: string; private_key_pem?: string };
};
interface KeyFormProps {
  keyData?: VirtualKey;
  onSave: (fields: KeyFields) => Promise<void>;
  onCancel: () => void;
  onDirtyChange?: (dirty: boolean) => void;
}
export default function KeyForm({ keyData, onSave, onCancel, onDirtyChange }: KeyFormProps) {
  const creating = !keyData;
  const prefix = useId();
  const [name, setName] = useState(keyData?.name || '');
  const [provider, setProvider] = useState(keyData?.provider_label ?? keyData?.provider ?? '');
  const [timeout, setTimeoutValue] = useState(String(keyData?.presence_timeout_seconds ?? 120));
  const [model, setModel] = useState(keyData?.model_aaguid || keyData?.aaguid || anonymousAaguid);
  const [attachment, setAttachment] = useState(keyData?.attachment || 'platform');
  const [resident, setResident] = useState(keyData?.resident_key_supported !== false);
  const [attestation, setAttestation] = useState(keyData?.attestation_mode || 'none');
  const [source, setSource] = useState('generate');
  const [country, setCountry] = useState('');
  const [organization, setOrganization] = useState('');
  const [commonName, setCommonName] = useState('');
  const [validity, setValidity] = useState('365');
  const chain = useRef<HTMLTextAreaElement>(null);
  const secret = useRef<HTMLTextAreaElement>(null);
  const chainRef = useCallback((node: HTMLTextAreaElement | null) => { if (!node && chain.current) chain.current.value = ''; chain.current = node; }, []);
  const secretRef = useCallback((node: HTMLTextAreaElement | null) => { if (!node && secret.current) secret.current.value = ''; secret.current = node; }, []);
  const submitting = useRef(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState('');
  const dirtyCallback = useRef(onDirtyChange);
  dirtyCallback.current = onDirtyChange;
  const clearSecrets = () => { if (chain.current) chain.current.value = ''; if (secret.current) secret.current.value = ''; };
  useEffect(() => { window.addEventListener('pagehide', clearSecrets); return () => { window.removeEventListener('pagehide', clearSecrets); clearSecrets(); dirtyCallback.current?.(false); }; }, []);
  useEffect(() => { if (attestation !== 'basic' || source !== 'import') clearSecrets(); }, [attestation, source]);
  const dirty = () => dirtyCallback.current?.(true);
  const randomize = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    setModel(normalizeAaguid([...bytes].map(byte => byte.toString(16).padStart(2, '0')).join(''))!);
    dirty();
  };
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting.current) return;
    setError('');
    const seconds = Number(timeout);
    if (!name.trim()) { setError('请输入验证器昵称。'); return; }
    if (!Number.isInteger(seconds) || seconds < 1 || seconds > 120) { setError('确认时限必须为 1 至 120 秒的整数。'); return; }
    if (!provider.trim() || /[\u0000-\u001f\u007f]/.test(provider)) { setError('请输入有效的 Provider 本地标签。'); return; }
    const fields: KeyFields = { name, provider_label: provider.trim(), presence_timeout_seconds: seconds };
    if (creating) {
      const aaguid = normalizeAaguid(model);
      if (!aaguid) { setError('请输入 32 位十六进制或标准 36 字符 AAGUID UUID。'); return; }
      Object.assign(fields, { model_aaguid: aaguid, attachment, resident_key_supported: resident, attestation_mode: attestation });
      if (attestation === 'basic') {
        if (source === 'generate') {
          const days = Number(validity);
          if (!/^[a-z]{2}$/i.test(country) || !organization.trim() || !commonName.trim() || !Number.isInteger(days) || days < 1 || days > 3650) { setError('请完整填写证书主题，国家代码为两位字母，有效期为 1 至 3650 天。'); return; }
          fields.attestation = { kind: 'generate', country: country.toUpperCase(), organization: organization.trim(), common_name: commonName.trim(), valid_days: days };
        } else {
          if (!chain.current?.value.trim() || !secret.current?.value.trim()) { setError('请填写证书链及对应的签名私钥。'); return; }
          fields.attestation = { kind: 'import', certificate_chain_pem: chain.current.value, private_key_pem: secret.current.value };
        }
      }
    }
    submitting.current = true;
    setWorking(true);
    try {
      const saving = onSave(fields);
      clearSecrets();
      await saving;
      dirtyCallback.current?.(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : '保存失败，请重试。');
    } finally {
      clearSecrets();
      if (fields.attestation) { delete fields.attestation.private_key_pem; delete fields.attestation.certificate_chain_pem; }
      submitting.current = false;
      setWorking(false);
    }
  };
  return <Paper component="form" variant="outlined" className="key-form" onSubmit={submit} onChange={dirty} aria-labelledby={`${prefix}-title`}>
    <Stack spacing={3}>
      <Box><Typography id={`${prefix}-title`} variant="h3">{creating ? '添加虚拟验证器' : '编辑验证器'}</Typography>{!creating && <Typography variant="body2" color="text.secondary" sx={{ mt: .5 }}>{keyData.name || '未命名验证器'}</Typography>}</Box>
      <Box className="form-grid">
        <TextField autoFocus label="昵称" name="key-name" value={name} onChange={e => setName(e.target.value)} required disabled={working} slotProps={{ htmlInput: { maxLength: 200 } }} placeholder="日常登录" />
        <TextField label="确认时限（秒）" name="presence-timeout-seconds" type="number" value={timeout} onChange={e => setTimeoutValue(e.target.value)} required disabled={working} slotProps={{ htmlInput: { min: 1, max: 120, step: 1 } }} />
      </Box>
      <TextField label="Provider（本地标签）" name="provider-label" placeholder="YubiKey 5A" value={provider} onChange={e => setProvider(e.target.value)} required disabled={working} slotProps={{ htmlInput: { maxLength: 120 } }} />
      {creating ? <>
        <Divider />
        <Stack component="fieldset" className="form-fieldset" spacing={2.5}>
          <Typography component="legend" variant="h3">验证器身份</Typography>
          <TextField select label="类型" name="attachment" value={attachment} onChange={e => setAttachment(e.target.value)} disabled={working}><MenuItem value="platform"><DevicesIcon fontSize="small" />设备验证器（internal）</MenuItem><MenuItem value="cross-platform"><UsbIcon fontSize="small" />USB 验证器（FIDO2）</MenuItem></TextField>
          <Stack direction="row" className="aaguid-field" spacing={1} sx={{ alignItems: 'center' }}>
            <TextField label="AAGUID" name="model-aaguid" placeholder={anonymousAaguid} sx={monospaceInputSx} value={model} onChange={e => setModel(e.target.value)} disabled={working} required slotProps={{ htmlInput: { spellCheck: false, style: {fontFamily: monospaceFontFamily} } }} />
            <Tooltip title="随机生成 AAGUID"><IconButton aria-label="随机生成 AAGUID" onClick={randomize} disabled={working}><RefreshIcon fontSize="small" /></IconButton></Tooltip>
            <Tooltip title="重置为全零 AAGUID"><IconButton aria-label="重置为全零 AAGUID" onClick={() => { setModel(anonymousAaguid); dirty(); }} disabled={working}><RestartAltIcon fontSize="small" /></IconButton></Tooltip>
          </Stack>
          <FormControlLabel control={<Switch name="resident-key-supported" checked={resident} onChange={e => setResident(e.target.checked)} disabled={working} />} label="可发现凭据" />

        </Stack>
        <Divider />
        <Stack component="fieldset" className="form-fieldset" spacing={2.5}>
          <Typography component="legend" variant="h3">注册证明</Typography>
          <TextField select label="证明方式" name="attestation-mode" value={attestation} onChange={e => { clearSecrets(); setAttestation(e.target.value); }} disabled={working}><MenuItem value="none">无证明</MenuItem><MenuItem value="self">凭据自签名</MenuItem><MenuItem value="basic">证书证明</MenuItem></TextField>
          {attestation === 'basic' && <Stack spacing={2.5}>
            <TextField select label="证书来源" name="certificate-source" value={source} onChange={e => { clearSecrets(); setSource(e.target.value); }} disabled={working}><MenuItem value="generate">生成自签名证书</MenuItem><MenuItem value="import">导入证书</MenuItem></TextField>
            {source === 'generate' ? <Box className="form-grid"><TextField label="国家代码（C）" name="certificate-country" value={country} onChange={e => setCountry(e.target.value)} required disabled={working} slotProps={{ htmlInput: { maxLength: 2, pattern: '[A-Za-z]{2}' } }} placeholder="CN" autoComplete="off" /><TextField label="组织（O）" name="certificate-organization" value={organization} onChange={e => setOrganization(e.target.value)} required disabled={working} slotProps={{ htmlInput: { maxLength: 120 } }} autoComplete="off" /><TextField label="组织单位（OU）" name="certificate-organizational-unit" value="Authenticator Attestation" disabled sx={{ gridColumn: '1 / -1' }} /><TextField label="名称（CN）" name="certificate-common-name" value={commonName} onChange={e => setCommonName(e.target.value)} required disabled={working} slotProps={{ htmlInput: { maxLength: 120 } }} autoComplete="off" /><TextField label="有效期（天）" name="certificate-valid-days" type="number" value={validity} onChange={e => setValidity(e.target.value)} required disabled={working} slotProps={{ htmlInput: { min: 1, max: 3650, step: 1 } }} /></Box> : <Stack spacing={2.5}>
              <TextField label="证书链（PEM）" name="certificate-chain-pem" multiline minRows={4} inputRef={chainRef} defaultValue="" required disabled={working} autoComplete="off" slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: 'off' } }} placeholder="-----BEGIN CERTIFICATE-----" />
              <TextField label="签名私钥（PKCS#8）" name="attestation-private-key" multiline minRows={4} inputRef={secretRef} defaultValue="" required disabled={working} autoComplete="off" slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: 'off' } }} placeholder="-----BEGIN PRIVATE KEY-----" helperText="P-256 未加密私钥；证书从叶证书到根证书排列。提交到当前服务保存，请使用 HTTPS。" />
            </Stack>}

          </Stack>}

        </Stack>
      </> : <Accordion>
        <AccordionSummary id={`${prefix}-identity-summary`} aria-controls={`${prefix}-identity-details`} expandIcon={<ExpandMoreIcon />}>
          <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}><FingerprintIcon color="action" /><Typography variant="subtitle2">验证器身份</Typography></Stack>
        </AccordionSummary>
        <AccordionDetails><KeyIdentity keyData={keyData} /></AccordionDetails>
      </Accordion>}
      {error && <Alert severity="error" role="alert">{error}</Alert>}
      <Stack direction="row" spacing={1} className="form-actions"><Button type="submit" variant="contained" disabled={working}>{working ? '正在保存…' : creating ? '添加验证器' : '保存验证器设置'}</Button><Button onClick={() => { clearSecrets(); onCancel(); }} disabled={working}>取消</Button></Stack>
    </Stack>
  </Paper>;
}
