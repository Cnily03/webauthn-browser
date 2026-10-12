import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FormControl, InputAdornment, InputLabel, MenuItem, Select, TextField } from '@mui/material';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserControls } from './BrowserControls';
import { compactControlSx } from './controlTypography';
import { DEFAULT_HELPER_ADDRESS, HelperSetup } from './Helper';
import KeyForm from './KeyForm';
import Settings from './Settings';
import { renderMaterial } from './test-render';
import type { AppStatus, VirtualKey } from './types';

const key: VirtualKey = {
  id: 'typography-key', name: 'Daily key', provider_label: 'Local provider', enabled: true,
  attachment: 'platform', presence_timeout_seconds: 120,
  model_aaguid: '01234567-89ab-cdef-0123-456789abcdef',
  resident_key_supported: true, attestation_mode: 'none', credentials: [],
};
const status: AppStatus = {
  csrf_token: 'typography-csrf', vnc_authenticated: true, settings_authenticated: true,
  vnc_password_enabled: false, settings_password_enabled: false, engine_connected: true,
};
const fontProperties = ['font-family', 'font-size', 'font-weight', 'letter-spacing', 'line-height'];
const paddingProperties = ['padding-top', 'padding-right', 'padding-bottom', 'padding-left'];
const computed = (element: Element, properties: string[]) => properties.map(property => getComputedStyle(element).getPropertyValue(property));
const typography = (element: Element) => computed(element, fontProperties);
const inputRoot = (input: Element) => input.closest('.MuiInputBase-root')!;
const inputLabel = (input: Element) => input.closest('.MuiFormControl-root')!.querySelector('.MuiInputLabel-root')!;

function outlineGeometry(input: Element) {
  const root = inputRoot(input);
  const outline = root.querySelector('.MuiOutlinedInput-notchedOutline')!;
  const legend = outline.querySelector('legend')!;
  return {
    inputPadding: computed(input, paddingProperties),
    rootPadding: computed(root, paddingProperties),
    outlinePadding: computed(outline, paddingProperties),
    legendScale: Number.parseFloat(getComputedStyle(legend).fontSize) / Number.parseFloat(getComputedStyle(root).fontSize),
    legendPadding: computed(legend, paddingProperties),
  };
}

function freshMaterialReference() {
  const reference = renderMaterial(<ThemeProvider theme={createTheme({ cssVariables: true })}>
    <TextField label="Default input" size="small" value="Ordinary text" onChange={() => {}} />
    <TextField label="Default adorned input" size="small" value="Address" onChange={() => {}}
      slotProps={{ input: { startAdornment: <InputAdornment position="start">@</InputAdornment> } }} />
    <FormControl size="small"><InputLabel id="default-mode-label">Default mode</InputLabel>
      <Select size="small" labelId="default-mode-label" label="Default mode" value="software">
        <MenuItem value="software">Software</MenuItem>
      </Select>
    </FormControl>
  </ThemeProvider>);
  const input = screen.getByRole('textbox', { name: 'Default input' });
  const adorned = screen.getByRole('textbox', { name: 'Default adorned input' });
  const select = screen.getByRole('combobox', { name: 'Default mode' });
  const result = {
    rootTypography: typography(inputRoot(input)), inputTypography: typography(input),
    labelTypography: typography(inputLabel(input)),
    inputGeometry: outlineGeometry(input), adornedGeometry: outlineGeometry(adorned), selectGeometry: outlineGeometry(select),
  };
  reference.unmount();
  return result;
}

function expectBody2(element: Element, fontWeight = '400') {
  // jsdom may retain rem values while a browser resolves them to px.
  const style = getComputedStyle(element);
  expect(['0.875rem', '14px']).toContain(style.fontSize);
  expect(style.fontWeight).toBe(fontWeight);
  expect(style.lineHeight === '1.43' ? 1.43 : Number.parseFloat(style.lineHeight) / 14).toBeCloseTo(1.43);
}

function expectCompactTypography(element: Element) {
  expect(element).toHaveStyle({fontSize: '12px', lineHeight: '18px'});
}

// These assertions inspect authored/computed CSS. jsdom has no layout engine,
// so rendered border-box heights need separate real-browser verification.
function expectCompactOutlinedGeometry(input: Element, kind: 'input' | 'select') {
  const root = inputRoot(input);
  expectCompactTypography(root);
  expectCompactTypography(input);
  expect(root).toHaveStyle({height: '32px', boxSizing: 'border-box'});
  if (kind === 'input') expect(root).toHaveStyle({paddingLeft: '10px'});
  expect(input).toHaveStyle({boxSizing: 'border-box', height: '32px', minHeight: '0', paddingTop: '7px', paddingBottom: '7px'});
  expect(input).toHaveStyle(kind === 'select' ? {paddingLeft: '10px', paddingRight: '28px'} : {paddingLeft: '0px', paddingRight: '10px'});
  const label = inputLabel(input);
  expectCompactTypography(label);
  expect(label).toHaveAttribute('data-shrink', 'true');
  expect(getComputedStyle(label).transform.replaceAll(' ', '')).toBe('translate(10px,-6px)scale(0.75)');
  const outline = root.querySelector('.MuiOutlinedInput-notchedOutline')!;
  expect(outline).toHaveStyle({paddingLeft: '5px', paddingRight: '5px'});
  const legend = outline.querySelector('legend')!;
  // Browsers resolve this relative 0.75em notch to 9px; jsdom can retain em.
  expect(['0.75em', '9px']).toContain(getComputedStyle(legend).fontSize);
}

function placeholderDeclarations(input: Element) {
  const declarations: CSSStyleDeclaration[] = [];
  const visit = (rules: CSSRuleList) => {
    for (const rule of Array.from(rules)) {
      if (rule instanceof CSSStyleRule) {
        const matchesInput = rule.selectorText.split(',').some(selector =>
          selector.includes('::placeholder') && input.matches(selector.replaceAll('::placeholder', '').trim()));
        if (matchesInput) declarations.push(rule.style);
      } else if ('cssRules' in rule) visit((rule as CSSGroupingRule).cssRules);
    }
  };
  for (const sheet of Array.from(document.styleSheets)) visit(sheet.cssRules);
  return declarations;
}

function expectMonospaceInputAndPlaceholder(input: Element, compact = false) {
  expect(input).toBeInstanceOf(HTMLInputElement);
  expect(input).toHaveClass('MuiInputBase-input');
  expect(getComputedStyle(input).fontFamily).toMatch(/\bmonospace\b/);
  // Pseudo-element computed styles are not implemented by jsdom. Check rules
  // that match this actual input, rather than an unrelated ancestor's styles.
  const declarations = placeholderDeclarations(input);
  const families = declarations.map(style => style.getPropertyValue('font-family')).filter(Boolean);
  expect(families.at(-1)).toMatch(/\bmonospace\b/);
  if (compact) {
    expectCompactTypography(input);
    const sizes = declarations.map(style => style.getPropertyValue('font-size')).filter(Boolean);
    const size = sizes.at(-1);
    expect(!size || size === 'inherit' ? getComputedStyle(input).fontSize : size).toBe('12px');
  }
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(init?.method ?? 'GET').toBe('GET');
    switch (String(input)) {
      case '/api/browser/mode': return Response.json({ mode: 'software', state: 'software', generation: 1, active: false, owned: false, control_connected: true });
      case '/api/security': return Response.json(status);
      case '/api/keys': return Response.json({ keys: [key] });
      case '/api/runtime': return Response.json({ state: 'ready', sandbox_enabled: false });
      default: throw new Error(`Unexpected typography-test request: ${String(input)}`);
    }
  }));
});

describe('scoped control typography', () => {
  it('makes the create AAGUID input and its placeholder monospace without changing ordinary key fields or outlined geometry', () => {
    const reference = freshMaterialReference();
    renderMaterial(<KeyForm onSave={vi.fn()} onCancel={vi.fn()} />);
    const aaguid = screen.getByRole('textbox', { name: /^AAGUID/ });
    expect(aaguid).toHaveAttribute('placeholder', '00000000-0000-0000-0000-000000000000');
    expectMonospaceInputAndPlaceholder(aaguid);
    expect(outlineGeometry(aaguid)).toEqual(reference.inputGeometry);
    expect(typography(inputLabel(aaguid))).toEqual(reference.labelTypography);
    for (const name of [/^昵称/, /^Provider/]) {
      const input = screen.getByRole('textbox', { name });
      expect(typography(inputRoot(input))).toEqual(reference.rootTypography);
      expect(typography(input)).toEqual(reference.inputTypography);
      expect(typography(inputLabel(input))).toEqual(reference.labelTypography);
      expect(outlineGeometry(input)).toEqual(reference.inputGeometry);
    }
  });

  it('uses monospace only for the immutable AAGUID value in the edit identity accordion', async () => {
    renderMaterial(<KeyForm keyData={key} onSave={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByRole('textbox', { name: /^AAGUID/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: '验证器身份' }));
    const value = screen.getByText(key.model_aaguid!);
    expect(value.tagName).toBe('DD');
    expect(getComputedStyle(value).fontFamily).toMatch(/\bmonospace\b/);
    expectBody2(value);
    const identity = value.closest('dl')!;
    for (const label of identity.querySelectorAll('dt')) {
      expect(getComputedStyle(label).fontFamily).not.toMatch(/\bmonospace\b/);
      expectBody2(label, '700');
    }
    for (const otherValue of identity.querySelectorAll('dd')) {
      if (otherValue !== value) expect(getComputedStyle(otherValue).fontFamily).not.toMatch(/\bmonospace\b/);
      expectBody2(otherValue);
    }
  });

  it('centers an empty compact label and scales it proportionally when focused', () => {
    renderMaterial(<TextField label="Compact empty field" value="" onChange={vi.fn()} sx={compactControlSx} />);
    const input = screen.getByRole('textbox', {name: 'Compact empty field'});
    const label = inputLabel(input);
    expectCompactTypography(label);
    expect(label).toHaveAttribute('data-shrink', 'false');
    expect(getComputedStyle(label).transform.replaceAll(' ', '')).toBe('translate(10px,7px)scale(1)');
    fireEvent.focus(input);
    expect(label).toHaveAttribute('data-shrink', 'true');
    expect(getComputedStyle(label).transform.replaceAll(' ', '')).toBe('translate(10px,-6px)scale(0.75)');
    expect(inputRoot(input)).toHaveStyle({height: '32px'});
    expect(input).toHaveStyle({height: '32px', fontSize: '12px'});
  });

  it('uses a 32px helper address field with 12px monospace text and a proportionally positioned label/notch', () => {
    renderMaterial(<HelperSetup address={DEFAULT_HELPER_ADDRESS} onAddress={vi.fn()} onConnect={vi.fn()} />);
    const input = screen.getByRole('textbox', { name: '辅助程序连接地址' });
    expect(input).toHaveValue(DEFAULT_HELPER_ADDRESS);
    expect(input).toHaveAttribute('placeholder', DEFAULT_HELPER_ADDRESS);
    expect(inputRoot(input)).toHaveClass('MuiInputBase-sizeSmall');
    expectMonospaceInputAndPlaceholder(input, true);
    expectCompactOutlinedGeometry(input, 'input');
    expect(getComputedStyle(inputLabel(input)).fontFamily).not.toMatch(/\bmonospace\b/);
  });

  it('uses a 32px mode select with 12px text and proportionally compact label, notch and portaled options', async () => {
    const { container } = renderMaterial(<BrowserControls authConnection={{ state: 'connected', message: '验证事件已连接' }} connected reconnecting={false}
      onReconnect={vi.fn()} onCtrlAltDelete={vi.fn()} onFullscreen={vi.fn()} onUnauthorized={vi.fn()} />);
    await act(async () => {});
    const select = screen.getByRole('combobox', { name: '模式' });
    expect(inputRoot(select)).toHaveClass('MuiInputBase-sizeSmall');
    expectCompactOutlinedGeometry(select, 'select');
    expect(getComputedStyle(select).fontFamily).not.toMatch(/\bmonospace\b/);
    expect(getComputedStyle(inputLabel(select)).fontFamily).not.toMatch(/\bmonospace\b/);
    fireEvent.mouseDown(select);
    const listbox = await screen.findByRole('listbox');
    expect(container).not.toContainElement(listbox);
    const options = within(listbox).getAllByRole('option');
    expect(options.map(option => option.textContent)).toEqual(['原生中继', '软件模拟']);
    for (const option of options) {
      expectCompactTypography(option);
      expect(option).toHaveStyle({minHeight: '32px'});
      expect(getComputedStyle(option).fontFamily).not.toMatch(/\bmonospace\b/);
    }
    await userEvent.keyboard('{Escape}');
  });

  it('keeps actual Settings password input and label typography at fresh Material defaults', async () => {
    const reference = freshMaterialReference();
    window.history.replaceState({}, '', '/settings#security');
    renderMaterial(<Settings status={status} refreshStatus={vi.fn().mockResolvedValue(status)} onUnauthorized={vi.fn()} notify={vi.fn()} />);
    await waitFor(() => expect(screen.queryByText('正在读取设置…')).not.toBeInTheDocument());
    await userEvent.click(screen.getAllByRole('button', { name: '设置密码' })[0]);
    const dialog = screen.getByRole('dialog');
    for (const name of ['新密码', '再次输入']) {
      const input = within(dialog).getByLabelText(name);
      expect(typography(inputRoot(input))).toEqual(reference.rootTypography);
      expect(typography(input)).toEqual(reference.inputTypography);
      expect(typography(inputLabel(input))).toEqual(reference.labelTypography);
      expect(outlineGeometry(input)).toEqual(reference.inputGeometry);
    }
  });
});
