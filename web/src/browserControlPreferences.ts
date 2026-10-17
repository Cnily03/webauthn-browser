import { browserProfileName, canonicalProfileName } from './profiles';

export type BrowserMode = 'native' | 'software';
const MODE_KEY = 'webauthn-browser.mode';
const ADDRESS_KEY = 'webauthn-browser.helper-address';

function preferenceKey(key: string) {
  const name = browserProfileName();
  return name && canonicalProfileName(name) !== 'default' ? `${key}.name.${canonicalProfileName(name)}` : key;
}

// Preferences only. Session capabilities and pair tokens never enter storage.
export function readBrowserControlPreferences(defaultAddress: string): {mode: BrowserMode; address: string} {
  let mode: BrowserMode = 'software';
  let address = defaultAddress;
  try {
    const stored = localStorage.getItem(preferenceKey(MODE_KEY));
    if (stored === 'native' || stored === 'software') mode = stored;
  } catch { /* Storage may be unavailable in private or restricted contexts. */ }
  try { address = localStorage.getItem(preferenceKey(ADDRESS_KEY)) ?? defaultAddress; }
  catch { /* Keep the in-memory default. */ }
  return {mode, address};
}
export function saveBrowserMode(mode: BrowserMode): void {
  try { localStorage.setItem(preferenceKey(MODE_KEY), mode); } catch { /* In-memory controls still work. */ }
}
export function saveHelperAddress(address: string): void {
  try { localStorage.setItem(preferenceKey(ADDRESS_KEY), address); } catch { /* In-memory controls still work. */ }
}
