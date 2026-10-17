export interface BrowserProfile {
  id: string;
  name: string;
  enabled: boolean;
  effective_enabled: boolean;
  password_enabled: boolean;
  password_required?: boolean;
  idle_timeout_seconds: number;
}
export interface ProfileConfiguration { multi_profile: boolean; profiles: BrowserProfile[] }
export interface ProfileViewer {
  viewer_id: string;
  viewer_token: string;
  generation: number;
  owner: boolean;
  idle_timeout_seconds: number;
  idle_remaining_ms?: number;
  expired?: boolean;
}
export const validProfileName = (value: string) => /^[A-Za-z0-9._-]{1,100}$/.test(value) && value !== '.' && value !== '..' && !/\.(git|wiki)$/i.test(value);
export const validProfileId = (value: string) => value === 'default' || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export function profilePage(name: string) { return `/profile/${encodeURIComponent(name)}`; }

export type PublicBrowserProfile = Omit<BrowserProfile, 'id'>;
export interface PublicProfileConfiguration {multi_profile: boolean; profiles: PublicBrowserProfile[]}
export type ProfileIdentity = Pick<PublicBrowserProfile, 'name'>;
export const canonicalProfileName = (name: string) => name.toLowerCase();
export type NavigateProfile = (profile: ProfileIdentity) => Promise<void>;
export function profileDestination(profile: ProfileIdentity, multiProfile = true) {
  return multiProfile ? profilePage(canonicalProfileName(profile.name)) : '/';
}
const chooserKey = 'webauthn-browser.profile-chooser';
// Old identity-bearing intent/state is retired. Names address public routes;
// the server alone validates the immutable identity behind each credential.
export function clearProfileNavigation() {
  try {sessionStorage.removeItem('webauthn-browser.profile-navigation');} catch { /* Optional legacy metadata. */ }
  const url = new URL(window.location.href);
  if ((['/', '/downloads', '/downloads/', '/profile'].includes(url.pathname) || url.pathname.startsWith('/profile/')) && url.searchParams.has('profile')) {
    url.searchParams.delete('profile');
    window.history.replaceState(window.history.state, '', url);
  }
  const state = window.history.state;
  if (state && typeof state === 'object' && '__webauthnBrowserProfile' in state) {
    const {__webauthnBrowserProfile: _legacy, ...remaining} = state;
    window.history.replaceState(remaining, '', window.location.href);
  }
}
export function prepareProfileNavigation(profile: ProfileIdentity, multiProfile = true) {
  if (!validProfileName(profile.name)) throw new Error('浏览器配置无效。');
  clearProfileNavigation();
  try {sessionStorage.removeItem(chooserKey);} catch { /* A named route needs no client-side credential or identity handoff. */ }
  return profileDestination(profile, multiProfile);
}
export function prepareProfileChooser() {
  clearProfileNavigation();
  try { sessionStorage.setItem(chooserKey, String(Date.now())); }
  catch { throw new Error('无法安全打开登录页面，请重试。'); }
}
export function readProfileChooser() {
  if (window.location.pathname !== '/') return false;
  let createdAt: number;
  try { createdAt = Number(sessionStorage.getItem(chooserKey)); sessionStorage.removeItem(chooserKey); } catch { createdAt = 0; }
  if (createdAt > 0) window.history.replaceState({...window.history.state, __webauthnBrowserChooser: createdAt}, '', window.location.href);
  else createdAt = window.history.state?.__webauthnBrowserChooser;
  return Number.isFinite(createdAt) && Date.now() - createdAt >= 0 && Date.now() - createdAt <= 60000;
}
export function retainProfileSelection(profile: ProfileIdentity, multiProfile = true) {
  clearProfileNavigation();
  window.history.replaceState(window.history.state, '', profileDestination(profile, multiProfile));
}

const SAVED_PROFILES_KEY = 'webauthn-browser.saved-profiles';
export type ProfileStatus = 'unknown' | 'auth_invalid' | 'unavailable' | 'active';
export type SavedProfile = ProfileIdentity & {lastUsedAt: number; status?: 'auth_invalid'};
export function savedProfiles(): SavedProfile[] {
  try {
    const raw = localStorage.getItem(SAVED_PROFILES_KEY) || '[]';
    let value: unknown;
    try {value = JSON.parse(raw);} catch {value = [];}
    if (!Array.isArray(value)) value = [];
    const records = value as unknown[];
    const seen = new Set<string>();
    const entries: SavedProfile[] = [];
    for (const record of records) {
      const item = record as Record<string, unknown>;
      if (!item || typeof item.name !== 'string' || !validProfileName(item.name) || typeof item.lastUsedAt !== 'number' || !Number.isFinite(item.lastUsedAt) || item.lastUsedAt <= 0) continue;
      const name = canonicalProfileName(item.name);
      if (seen.has(name)) continue;
      seen.add(name);
      entries.push({name, lastUsedAt: item.lastUsedAt,
        ...((item.status === 'auth_invalid' || item.auth === false || item.error === true) ? {status: 'auth_invalid' as const} : {})});
      // Preserve known UI preferences while removing retired UUID-keyed hints.
      if (typeof item.id === 'string' && item.id !== 'default' && validProfileId(item.id)) {
        for (const prefix of ['webauthn-browser.mode', 'webauthn-browser.helper-address']) {
          const previous = `${prefix}.${item.id}`, next = name === 'default' ? prefix : `${prefix}.name.${name}`;
          try {const stored = localStorage.getItem(previous); if (stored !== null && localStorage.getItem(next) === null) localStorage.setItem(next, stored); localStorage.removeItem(previous);} catch { /* Read-only storage remains usable. */ }
        }
      }
    }
    // Remove orphaned legacy preference keys too; a forgotten menu row may
    // have left one behind. Other storage namespaces are never touched.
    for (const key of Object.keys(localStorage)) {
      const match = /^webauthn-browser\.(?:mode|helper-address)\.(.+)$/.exec(key);
      if (match && match[1] !== 'default' && validProfileId(match[1])) {
        try {localStorage.removeItem(key);} catch { /* Read-only storage remains usable. */ }
      }
    }
    try { if (JSON.stringify(entries) !== raw) localStorage.setItem(SAVED_PROFILES_KEY, JSON.stringify(entries)); } catch { /* Read-only storage remains usable. */ }
    return entries;
  } catch { return []; }
}
export function rememberProfile(profile: ProfileIdentity) {
  if (!validProfileName(profile.name)) return;
  try {
    // Only menu metadata is readable by JavaScript. Revocable credentials stay
    // in per-profile HttpOnly cookies and expire under server-side policy.
    const name = canonicalProfileName(profile.name);
    const entries = savedProfiles().filter(item => item.name !== name);
    localStorage.setItem(SAVED_PROFILES_KEY, JSON.stringify([{name, lastUsedAt: Date.now()}, ...entries]));
  } catch { /* Storage restrictions must not prevent a valid session. */ }
}
// Authentication hints are UI metadata; availability is always recomputed
// from the current catalog and neither hint grants browser access.
export function setSavedProfileStatus(name: string, status: 'unknown' | 'auth_invalid') {
  try {
    const entries = savedProfiles().map(profile => {
      if (canonicalProfileName(profile.name) !== canonicalProfileName(name)) return profile;
      const {status: _previous, ...identity} = profile;
      return status === 'auth_invalid' ? {...identity, status} : identity;
    });
    localStorage.setItem(SAVED_PROFILES_KEY, JSON.stringify(entries));
  } catch { /* A blocked local hint update must not affect authorization. */ }
}
export function forgetProfile(name: string) {
  try { localStorage.setItem(SAVED_PROFILES_KEY, JSON.stringify(savedProfiles().filter(item => item.name !== canonicalProfileName(name)))); return true; }
  catch { return false; }
}

interface ProfileBinding { name: string; viewer: ProfileViewer | null }
let binding: ProfileBinding | null = null;
export function bindBrowserProfile(name: string) {
  if (!validProfileName(name)) throw new Error('浏览器配置无效。');
  // A name switch loads a new document. The server binds credentials to its
  // internal profile identity; old callbacks keep their original name scope.
  if (binding && canonicalProfileName(binding.name) !== canonicalProfileName(name)) throw new Error('请重新打开浏览器配置。');
  binding ??= {name: canonicalProfileName(name), viewer: null};
}
export function browserProfileName() { return binding?.name ?? null; }
export function setProfileViewer(viewer: ProfileViewer | null, expectedToken?: string) {
  if (binding && (expectedToken === undefined || binding.viewer?.viewer_token === expectedToken)) binding.viewer = viewer;
}
export function viewerHeaders(viewer: ProfileViewer | null | undefined): Record<string, string> {
  return viewer ? {'X-Viewer-Token': viewer.viewer_token, 'X-Owner-Generation': String(viewer.generation)} : {};
}
export function profileViewerHeaders() { return viewerHeaders(binding?.viewer); }
export function isProfileBrowserPath(path: string, body?: unknown) {
  if (['/api/login', '/api/logout'].includes(path)) return !(body && typeof body === 'object' && 'scope' in body && body.scope === 'settings');
  return ['/api/status', '/api/runtime', '/ws'].includes(path)
    || ['/api/browser/', '/api/helper/', '/api/requests', '/api/clipboard/', '/api/viewer/'].some(prefix => path.startsWith(prefix));
}
export function browserApiPath(path: string, body?: unknown) {
  return binding && isProfileBrowserPath(path, body) ? `/p/${encodeURIComponent(binding.name)}${path}` : path;
}
export function profileResourcePath(path: string) { return binding ? `/p/${encodeURIComponent(binding.name)}${path}` : path; }
