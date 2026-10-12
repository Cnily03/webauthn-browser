"""Source contracts for MUI isolation; these do not assert browser pixels."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MuiStyleContracts(unittest.TestCase):
    def test_placeholders_do_not_prefix_examples_and_form_labels_keep_default_size(self):
        sources = '\n'.join(path.read_text() for path in (ROOT / 'web/src').glob('*.tsx') if '.test.' not in path.name)
        placeholders = re.findall(r'placeholder="([^"]*)"', sources)
        self.assertTrue(placeholders)
        for placeholder in placeholders:
            self.assertNotRegex(placeholder, r'(?i)例如|比如|示例|e\.g\.|for example')
        css = (ROOT / 'web/src/styles.css').read_text()
        self.assertNotRegex(css, r'\.MuiFormControlLabel-label\s*\{[^}]*font-')
        form = (ROOT / 'web/src/KeyForm.tsx').read_text()
        self.assertIn('name="provider-label" placeholder="YubiKey 5A"', form)
        self.assertIn('sx={monospaceInputSx}', form)
        typography = (ROOT / 'web/src/controlTypography.ts').read_text()
        self.assertIn("'& .MuiInputBase-input'", typography)
        self.assertIn("'&::placeholder'", typography)
        self.assertIn('fontFamily: monospaceFontFamily', typography)
        self.assertIn("fontSize: '12px'", typography)
        self.assertNotRegex(css, r'\.Mui(?:InputBase|InputLabel|OutlinedInput)[^{}]*\{[^}]*font-size:')

    def test_group_legend_rules_cannot_match_mui_notch_legends(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        # MUI's outline contains its own nested legend. A descendant selector
        # applies float/width to that legend and breaks the native label notch.
        self.assertIn('.form-fieldset > legend {', css)
        self.assertIn('.form-fieldset > legend + * {', css)
        self.assertNotRegex(css, r'\.form-fieldset\s+legend\b')
        self.assertNotRegex(css, r'(?:^|})\s*(?:fieldset|legend|input|select)\s*\{')

    def test_icon_actions_have_bounded_size_without_input_width_overrides(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        rule = re.search(r'\.aaguid-field > \.MuiIconButton-root\s*\{([^}]+)}', css)
        self.assertIsNotNone(rule)
        self.assertIn('flex-shrink: 0', rule[1])
        self.assertIn('width: 36px', rule[1])
        self.assertIn('height: 36px', rule[1])
        self.assertIn('.aaguid-field > .MuiTextField-root { min-width: 0; }', css)

    def test_palette_and_navigation_use_material_tokens(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        theme = (ROOT / 'web/src/theme.ts').read_text()
        app = (ROOT / 'web/src/App.tsx').read_text()
        self.assertNotRegex(css + theme, r'#[0-9a-fA-F]{3,8}\b')
        self.assertNotIn('palette:', theme)
        self.assertIn('cssVariables: true', theme)
        self.assertNotIn('.brand', css)
        self.assertNotIn('title={connection.label}', app)
        self.assertIn('KeyboardDoubleArrowLeftIcon', app)
        self.assertIn('KeyboardDoubleArrowRightIcon', app)
        self.assertIn("aria-controls={!isBrowser ? undefined : 'navigation-group'}", app)
        self.assertIn("visibility: !isBrowser ? 'hidden' : 'visible'", app)
        controls = (ROOT / 'web/src/BrowserControls.tsx').read_text()
        self.assertIn('id="browser-controls"', controls)
        self.assertIn('id="browser-control-content"', controls)
        self.assertIn('theme.zIndex.appBar', controls)
        self.assertIn('place-items: center; padding: 24px;', css)

    def test_remote_cursor_layers_are_scoped_below_outer_ui(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        app = (ROOT / 'web/src/App.tsx').read_text()
        guard = (ROOT / 'web/src/remoteCursor.ts').read_text()
        self.assertIn('body > canvas[data-vnc-cursor] { z-index: 2 !important;', css)
        self.assertIn('body > canvas[data-vnc-cursor]:not([data-vnc-cursor-active]) { visibility: hidden !important; }', css)
        self.assertIn('#noVNC_mouse_capture_elem[data-vnc-capture] { z-index: 1 !important; }', css)
        self.assertIn('.desktop { position: fixed; inset: 0; z-index: 0;', css)
        self.assertIn('.request-status { position: fixed;', css)
        self.assertIn('z-index: 10;', css)
        self.assertNotRegex(css, r'cursor:\s*none')
        self.assertNotRegex(css, r'body > canvas\s*\{')
        self.assertIn('installRemoteCursorGuard(screen.current)', app)
        self.assertIn('cursor?.dispose()', app)
        # The status controls must escape the desktop stacking context, so the
        # body-level remote cursor cannot cover them despite their local z-index.
        self.assertIn('</Box><Stack spacing={1} className="request-status">', app)
        self.assertNotIn('._cursor', guard)
        self.assertNotIn('stopPropagation', guard)
        self.assertNotIn('preventDefault', guard)

    def test_connecting_overlay_is_light_text_without_a_surface(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        rule = re.search(r'\.vnc-placeholder\s*\{([^}]+)}', css)
        self.assertIsNotNone(rule)
        for declaration in ('place-items: center', 'pointer-events: none',
                            'color: var(--mui-palette-grey-300)',
                            'background: transparent', 'border: 0', 'box-shadow: none'):
            self.assertIn(declaration, rule[1])
        self.assertIn('.vnc-placeholder > .MuiTypography-root { max-width: 440px; text-align: center; }', css)
        self.assertNotIn('.vnc-placeholder .MuiPaper-root', css)

    def test_narrow_connection_status_retains_accessible_text(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        self.assertIn('.browser-controls .connection-label { position: absolute;', css)
        self.assertIn('clip-path: inset(50%)', css)
        self.assertNotIn('.browser-controls .connection { display: none;', css)

    def test_admin_accordions_keep_material_surfaces_and_typography(self):
        css = (ROOT / 'web/src/styles.css').read_text()
        theme = (ROOT / 'web/src/theme.ts').read_text()
        settings = (ROOT / 'web/src/Settings.tsx').read_text()
        self.assertIn('MuiAccordion: { defaultProps: { elevation: 1 } }', theme)
        self.assertNotIn('MuiAccordionSummary:', theme)
        self.assertNotIn('MuiAccordionDetails:', theme)
        self.assertNotIn('disableGutters', theme)
        self.assertNotRegex(css, r'\.credential(?::first-child)?\s*\{')
        self.assertNotRegex(css, r'\.detail-grid dd\s*\{[^}]*font-size:')
        self.assertIn('.detail-grid { grid-template-columns: minmax(0, 1fr); }', css)
        self.assertIn('<AccordionActions>', settings)
        self.assertNotIn('用户名 · {username}', settings)


if __name__ == '__main__':
    unittest.main()
