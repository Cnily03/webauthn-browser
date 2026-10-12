import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import KeyForm, { normalizeAaguid } from './KeyForm';
import type { KeyFields } from './KeyForm';
import type { VirtualKey } from './types';
import { renderMaterial } from './test-render';

async function select(label: string, option: RegExp) {
  await userEvent.click(screen.getByRole('combobox', { name: label }));
  await userEvent.click(await screen.findByRole('option', { name: option }));
}
const nameField = () => screen.getByRole('textbox', { name: /^昵称/ });
const providerField = () => screen.getByRole('textbox', { name: /^Provider/ });
const modelField = () => screen.getByRole('textbox', { name: /^AAGUID/ });
const key: VirtualKey = { id: 'key-a', name: 'Daily key', provider_label: 'Original provider', enabled: true, attachment: 'platform', model_aaguid: '00000000-0000-0000-0000-000000000000', presence_timeout_seconds: 120, resident_key_supported: true, attestation_mode: 'none', credentials: [] };

describe('Material UI key form', () => {
  it('normalizes accepted compact/hyphenated UUIDs and rejects malformed identities', () => {
    expect(normalizeAaguid(' 0123456789ABCDEF0123456789ABCDEF ')).toBe('01234567-89ab-cdef-0123-456789abcdef');
    expect(normalizeAaguid('01234567-89AB-CDEF-0123-456789ABCDEF')).toBe('01234567-89ab-cdef-0123-456789abcdef');
    for (const invalid of ['bad', '0'.repeat(31), 'g'.repeat(32), '012345678-9abc-def0-1234-56789abcdef']) expect(normalizeAaguid(invalid)).toBeNull();
  });

  it('renders real MUI controls and emits canonical creation fields with safe text', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const { container } = renderMaterial(<KeyForm onSave={save} onCancel={vi.fn()} />);
    expect(container.querySelector('.MuiTextField-root')).toBeInTheDocument();
    expect(providerField()).toHaveValue('');
    expect(providerField()).toHaveAttribute('placeholder', 'YubiKey 5A');
    expect(nameField()).toHaveAttribute('placeholder', '日常登录');
    expect(modelField()).toHaveAccessibleName('AAGUID');
    expect(getComputedStyle(modelField()).fontFamily).toContain('monospace');
    expect(modelField()).toHaveAttribute('placeholder', '00000000-0000-0000-0000-000000000000');
    expect(nameField().style.fontFamily).toBe('');
    await userEvent.type(nameField(), '<img src=x> 🔑');
    await userEvent.clear(providerField());
    await userEvent.type(providerField(), ' Personal label ');
    await userEvent.clear(modelField());
    await userEvent.type(modelField(), ' 01234567-89AB-CDEF-0123-456789ABCDEF ');
    await userEvent.click(screen.getByRole('button', { name: '添加验证器' }));
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ name: '<img src=x> 🔑', provider_label: 'Personal label', presence_timeout_seconds: 120, model_aaguid: '01234567-89ab-cdef-0123-456789abcdef', attachment: 'platform', resident_key_supported: true, attestation_mode: 'none' });
    expect(container.querySelector('img')).toBeNull();
  });

  it('edits only mutable name, provider and timeout fields', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    renderMaterial(<KeyForm keyData={key} onSave={save} onCancel={vi.fn()} />);
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /^AAGUID/ })).not.toBeInTheDocument();
    expect(providerField()).toHaveValue('Original provider');
    await userEvent.clear(providerField());
    await userEvent.type(providerField(), 'Updated label');
    await userEvent.clear(screen.getByRole('spinbutton', { name: /^确认时限/ }));
    await userEvent.type(screen.getByRole('spinbutton', { name: /^确认时限/ }), '30');
    await userEvent.click(screen.getByRole('button', { name: '保存验证器设置' }));
    expect(save).toHaveBeenCalledWith({ name: 'Daily key', provider_label: 'Updated label', presence_timeout_seconds: 30 });
  });

  it('keeps edit identity in a standard named Material accordion without changing form inputs', async () => {
    const save = vi.fn();
    renderMaterial(<KeyForm keyData={key} onSave={save} onCancel={vi.fn()} />);
    const summary = screen.getByRole('button', { name: '验证器身份', expanded: false });
    expect(summary.closest('.MuiAccordion-root')).toHaveClass('MuiPaper-elevation1', 'MuiAccordion-gutters');
    expect(summary).toHaveClass('MuiAccordionSummary-gutters');
    const region = document.getElementById(summary.getAttribute('aria-controls')!);
    expect(region).toHaveAttribute('aria-labelledby', summary.id);
    expect(region).not.toBeVisible();
    await userEvent.type(nameField(), ' unsaved');
    summary.focus();
    for (let repeat = 0; repeat < 2; repeat++) {
      await userEvent.keyboard('{Enter}');
      expect(region).toBeVisible();
      for (const label of region!.querySelectorAll('dt')) {
        expect(label).toHaveStyle({ display: 'inline', fontWeight: '700' });
        expect(label.textContent).toMatch(/：$/);
      }
      for (const value of region!.querySelectorAll('dd')) expect(value).toHaveStyle({ display: 'inline', fontWeight: '400' });
      expect(region).not.toHaveTextContent(/·|软件模拟/);
      expect(region).toHaveTextContent(`AAGUID：${key.model_aaguid}`);
      await userEvent.keyboard(' ');
      expect(summary).toHaveAttribute('aria-expanded', 'false');
    }
    expect(nameField()).toHaveValue('Daily key unsaved');
    expect(providerField()).toHaveValue('Original provider');
    expect(save).not.toHaveBeenCalled();
  });

  it('uses readable proof choices and certificate labels without middle-dot concatenation', async () => {
    const { container } = renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByText('注册证明')).toBeVisible();
    await userEvent.click(screen.getByRole('combobox', { name: '证明方式' }));
    expect(screen.getAllByRole('option').map(option => option.textContent)).toEqual(['无证明', '凭据自签名', '证书证明']);
    await userEvent.click(screen.getByRole('option', { name: '证书证明' }));
    expect(container).not.toHaveTextContent('·');
    expect(screen.getByRole('textbox', { name: '组织单位（OU）' })).toHaveValue('Authenticator Attestation');
    await select('证书来源', /导入证书/);
    expect(screen.getByRole('textbox', { name: /^证书链（PEM）/ })).toBeVisible();
    expect(screen.getByRole('textbox', { name: /^签名私钥（PKCS#8）/ })).toBeVisible();
    expect(container).not.toHaveTextContent('·');
  });

  it('requires an explicit Provider for new keys instead of silently restoring a preset', async () => {
    const save = vi.fn();
    const { container } = renderMaterial(<KeyForm onSave={save} onCancel={vi.fn()} />);
    await userEvent.type(nameField(), 'New key');
    expect(providerField()).toHaveValue('');
    fireEvent.submit(container.querySelector('form')!);
    expect(await screen.findByRole('alert')).toHaveTextContent('请输入有效的 Provider 本地标签');
    expect(save).not.toHaveBeenCalled();
    expect(providerField()).toHaveValue('');
  });

  it('validates timeout and identity before any request', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const { container } = renderMaterial(<KeyForm onSave={save} onCancel={vi.fn()} />);
    await userEvent.type(nameField(), 'Validation key');
    await userEvent.type(providerField(), 'Test provider');
    fireEvent.change(screen.getByRole('spinbutton', { name: /^确认时限/ }), { target: { value: '0' } });
    fireEvent.submit(container.querySelector('form')!);
    expect(await screen.findByRole('alert')).toHaveTextContent('1 至 120');
    expect(save).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('spinbutton', { name: /^确认时限/ }), { target: { value: '120' } });
    fireEvent.change(modelField(), { target: { value: 'invalid' } });
    fireEvent.submit(container.querySelector('form')!);
    expect(await screen.findByRole('alert')).toHaveTextContent('AAGUID');
    expect(save).not.toHaveBeenCalled();
  });

  it('generates a v4 UUID and permits explicit zero identity', async () => {
    renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: '随机生成 AAGUID' }));
    expect((modelField() as HTMLInputElement).value).toMatch(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
    await userEvent.click(screen.getByRole('button', { name: '重置为全零 AAGUID' }));
    expect(modelField()).toHaveValue('00000000-0000-0000-0000-000000000000');
  });

  it('normalizes generated certificate fields', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    renderMaterial(<KeyForm onSave={save} onCancel={vi.fn()} />);
    await userEvent.type(nameField(), 'Certificate key');
    await userEvent.type(providerField(), 'Test provider');
    await select('证明方式', /证书证明/);
    await userEvent.type(screen.getByRole('textbox', { name: /^国家代码/ }), 'cn');
    await userEvent.type(screen.getByRole('textbox', { name: /^组织（O）/ }), ' Personal ');
    await userEvent.type(screen.getByRole('textbox', { name: /^名称/ }), ' Test Authenticator ');
    await userEvent.click(screen.getByRole('button', { name: '添加验证器' }));
    expect(save.mock.calls[0][0].attestation).toEqual({ kind: 'generate', country: 'CN', organization: 'Personal', common_name: 'Test Authenticator', valid_days: 365 });
  });

  it('clears imported PEM on source switch, cancel and unmount, including detached DOM nodes', async () => {
    const cancel = vi.fn();
    const { unmount } = renderMaterial(<KeyForm onSave={vi.fn()} onCancel={cancel} />);
    await select('证明方式', /证书证明/);
    await select('证书来源', /导入证书/);
    const first = screen.getByRole('textbox', { name: /^签名私钥/ });
    await userEvent.type(first, 'discard on source switch');
    await select('证书来源', /生成自签名证书/);
    expect(first).toHaveValue('');
    await select('证书来源', /导入证书/);
    const second = screen.getByRole('textbox', { name: /^签名私钥/ });
    expect(second).toHaveValue('');
    await userEvent.type(second, 'discard on cancel');
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(second).toHaveValue('');
    expect(cancel).toHaveBeenCalledTimes(1);
    await userEvent.type(second, 'discard on route change');
    unmount();
    expect(second).toHaveValue('');
  });

  it('sends PEM once, clears fields immediately and blocks repeated submissions while pending', async () => {
    let finish!: () => void;
    let submitted: KeyFields | undefined;
    const save = vi.fn((fields: KeyFields) => {
      submitted = structuredClone(fields);
      return new Promise<void>(resolve => { finish = resolve; });
    });
    const { container } = renderMaterial(<KeyForm onSave={save} onCancel={vi.fn()} />);
    await userEvent.type(nameField(), 'Import key');
    await userEvent.type(providerField(), 'Test provider');
    await select('证明方式', /证书证明/);
    await select('证书来源', /导入证书/);
    const secret = screen.getByRole('textbox', { name: /^签名私钥/ });
    const chain = screen.getByRole('textbox', { name: /^证书链/ });
    await userEvent.type(secret, 'TEST PRIVATE KEY');
    await userEvent.type(chain, 'TEST CERTIFICATE');
    fireEvent.submit(container.querySelector('form')!);
    fireEvent.submit(container.querySelector('form')!);
    expect(save).toHaveBeenCalledTimes(1);
    expect(submitted?.attestation).toEqual({ kind: 'import', private_key_pem: 'TEST PRIVATE KEY', certificate_chain_pem: 'TEST CERTIFICATE' });
    expect(secret).toHaveValue('');
    expect(chain).toHaveValue('');
    expect(screen.getByRole('button', { name: '正在保存…' })).toBeDisabled();
    finish();
    await waitFor(() => expect(screen.getByRole('button', { name: '添加验证器' })).toBeEnabled());
  });
});
